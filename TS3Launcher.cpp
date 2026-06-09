// ============================================================================
//  TS3Launcher.cpp — TS3VASManager unified launcher
//
//  No configuration file. All three files live in the same folder:
//      Game\Bin\TS3Launcher.exe       <- this exe
//      Game\Bin\TS3VASManager.dll     <- 32-bit hook DLL
//      Game\Bin\TS3W.exe / TS3.exe    <- the game
//
//  Install instructions: copy all three files into Game\Bin and run
//  TS3Launcher.exe instead of the game directly.
//
//  Auto-detection (no user config needed):
//    Game\Bin\TS3W.exe exists
//      → 1.67 disc / 1.70 Steam — DIRECT mode
//        DetourCreateProcessWithDllExA injects DLL before instruction 1 (pre-OEP)
//
//    Game\Bin\TS3W.exe absent, TS3.exe present
//      → 1.69 EA/Origin — MONITOR mode
//        If Game\Bin\Sims3Launcher.exe present, spawns it; user clicks Play.
//        Otherwise prints "start game via EA App now".
//        Polls for TS3.exe, injects via remote LoadLibraryA as early as possible.
//
//  Launch sequence (both modes):
//    1. Derive all paths from the directory of TS3Launcher.exe.
//    2a. DIRECT:  DetourCreateProcessWithDllExA(TS3W.exe, dll) — pre-OEP.
//    2b. MONITOR: (optionally spawn Sims3Launcher.exe), wait for TS3.exe,
//                 inject via CreateRemoteThread + LoadLibraryA.
//
//  Logs: C:\ts3_tool\ (written by the injected DLL).
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <detours.h>
#include <stdio.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")


// Monitor-mode tuning (1.69 path)
static const DWORD    PROCESS_POLL_MS       = 250;    // process list poll interval
static const DWORD    GAME_TIMEOUT_SEC      = 60;     // max wait for game process
static const DWORD    PRE_INJECT_SLEEP_MS   = 500;    // brief pause before inject

// Known game exe names
static const char* EXE_DIRECT  = "TS3W.exe";    // 1.67 disc / 1.70 Steam
static const char* EXE_MONITOR = "TS3.exe";     // 1.69 EA/Origin
static const char* EXE_EALAUN  = "Sims3Launcher.exe"; // 1.69 intermediate launcher
// Injection DLL. The telemetry build deploys as TS3VASManager.dll and the lean
// play build as TS3VASManager_play.dll — distinct filenames. Try them in order;
// the first one present in Game\Bin wins (telemetry preferred when both exist).
static const char* DLL_CANDIDATES[] = {
    "TS3VASManager.dll",        // telemetry / diagnostic build
    "TS3VASManager_play.dll",   // lean play build
};

// ── Helpers ──────────────────────────────────────────────────────────────────

static bool FileExists(const char* path) {
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

// Returns the directory of this exe (with trailing backslash stripped).
static bool GetSelfDir(char* out, DWORD size) {
    if (!out || size == 0) return false;
    DWORD n = GetModuleFileNameA(nullptr, out, size);
    if (n == 0 || n >= size) return false;
    return PathRemoveFileSpecA(out) ? true : false;
}

// ── MONITOR mode helpers (1.69 path) ────────────────────────────────────────

// Returns PID of the first process matching exeName (case-insensitive), or 0.
static DWORD FindProcess(const char* exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);
    DWORD found = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exeName) == 0) {
                found = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// Polls every PROCESS_POLL_MS until exeName appears or timeoutSec elapses.
static DWORD WaitForProcess(const char* exeName, DWORD timeoutSec) {
    printf("[WAIT] Watching for %s (timeout %lu s)...\n", exeName, timeoutSec);
    DWORD elapsed = 0;
    const DWORD limit = timeoutSec * 1000;
    while (elapsed < limit) {
        DWORD pid = FindProcess(exeName);
        if (pid) {
            printf("[WAIT] Found %s — PID %lu (after %lu ms)\n",
                   exeName, pid, elapsed);
            return pid;
        }
        Sleep(PROCESS_POLL_MS);
        elapsed += PROCESS_POLL_MS;
        if (elapsed % 5000 == 0)
            printf("[WAIT] Still waiting... %lu / %lu s\n",
                   elapsed / 1000, timeoutSec);
    }
    printf("[WAIT] Timed out after %lu s.\n", timeoutSec);
    return 0;
}

// Injects dllPath into process pid via CreateRemoteThread + LoadLibraryA.
// This is the best injection available when we did not spawn the process.
// Hooks go live after game starts, not pre-OEP — earliest achievable for 1.69.
static bool InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        printf("[INJECT] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        printf("         Run TS3Launcher.exe as Administrator if needed.\n");
        return false;
    }

    size_t pathLen   = strlen(dllPath) + 1;
    LPVOID remoteBuf = VirtualAllocEx(hProc, nullptr, pathLen,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        printf("[INJECT] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteBuf, dllPath, pathLen, nullptr)) {
        printf("[INJECT] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // Resolve LoadLibraryA for the remote-thread bootstrap.
    // For same-bitness user processes on Windows this is typically stable enough
    // for remote thread creation during early startup.
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    auto pLoadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hK32, "LoadLibraryA");
    if (!pLoadLib) {
        printf("[INJECT] GetProcAddress(LoadLibraryA) failed.\n");
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    printf("[INJECT] Creating remote thread → LoadLibraryA(\"%s\")\n", dllPath);
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
                                        pLoadLib, remoteBuf, 0, nullptr);
    if (!hThread) {
        printf("[INJECT] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // Wait for DllMain to complete (hooks go live on return)
    WaitForSingleObject(hThread, 10000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (exitCode == 0) {
        printf("[INJECT] LoadLibraryA returned NULL — DLL failed to load.\n");
        printf("         Verify %s is in the game Bin folder.\n", dllPath);
        return false;
    }

    printf("[INJECT] DLL loaded. HMODULE=0x%08lX\n", exitCode);
    return true;
}

// Spawns an intermediate launcher (e.g. Sims3Launcher.exe) and returns.
// The spawned process eventually starts the game; WaitForProcess handles the rest.
static void SpawnIntermediateLauncher(const char* fullPath) {
    char cmd[MAX_PATH + 4];
    snprintf(cmd, sizeof(cmd), "\"%s\"", fullPath);

    STARTUPINFOA        si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);

    printf("[LAUNCH] Starting intermediate launcher: %s\n", fullPath);
    if (!CreateProcessA(fullPath, cmd, nullptr, nullptr,
                        FALSE, CREATE_DEFAULT_ERROR_MODE,
                        nullptr, nullptr, &si, &pi)) {
        printf("[LAUNCH] CreateProcess failed: %lu — proceeding to process watch.\n",
               GetLastError());
        return;
    }
    printf("[LAUNCH] Launcher started (PID %lu). Click Play when the window appears.\n\n",
           pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

// ── Entry point ──────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("  TS3VASManager Launcher\n");
    printf("============================================================\n\n");

    // ── Step 1: Derive all paths from our own location ────────────────────────
    char selfDir  [MAX_PATH] = {};
    char dllPath  [MAX_PATH] = {};
    char gameExe  [MAX_PATH] = {};

    if (!GetSelfDir(selfDir, MAX_PATH)) {
        printf("[ERROR] Could not resolve launcher directory (GLE=%lu).\n", GetLastError());
        system("pause");
        return 1;
    }

    // Resolve which injection DLL is actually present (telemetry build first,
    // then the play build). Falls back to the first name for the error path below.
    const char* dllName = DLL_CANDIDATES[0];
    for (const char* cand : DLL_CANDIDATES) {
        char tryPath[MAX_PATH] = {};
        snprintf(tryPath, MAX_PATH, "%s\\%s", selfDir, cand);
        if (FileExists(tryPath)) { dllName = cand; break; }
    }
    snprintf(dllPath, MAX_PATH, "%s\\%s", selfDir, dllName);

    // ── Step 2: Auto-detect game exe and injection mode ───────────────────────
    char directPath [MAX_PATH] = {};
    char monitorPath[MAX_PATH] = {};
    snprintf(directPath,  MAX_PATH, "%s\\%s", selfDir, EXE_DIRECT);
    snprintf(monitorPath, MAX_PATH, "%s\\%s", selfDir, EXE_MONITOR);

    enum class Mode { DIRECT, MONITOR } mode;
    const char* gameExeName = nullptr;

    if (FileExists(directPath)) {
        mode        = Mode::DIRECT;
        gameExeName = EXE_DIRECT;
        snprintf(gameExe, MAX_PATH, "%s", directPath);
        printf("[AUTO]   Game    : %s  (1.67 disc / 1.70 Steam — DIRECT mode)\n",
               directPath);
    } else if (FileExists(monitorPath)) {
        mode        = Mode::MONITOR;
        gameExeName = EXE_MONITOR;
        snprintf(gameExe, MAX_PATH, "%s", monitorPath);
        printf("[AUTO]   Game    : %s  (1.69 EA/Origin — MONITOR mode)\n",
               monitorPath);
    } else {
        printf("[ERROR] Neither %s nor %s found in:\n", EXE_DIRECT, EXE_MONITOR);
        printf("        %s\n\n", selfDir);
        printf("  All three files must be in the same Game\\Bin folder:\n");
        printf("    TS3Launcher.exe  TS3VASManager.dll (or _play.dll)\n");
        printf("    TS3W.exe (disc/Steam)  OR  TS3.exe (EA/Origin)\n");
        system("pause");
        return 1;
    }

    printf("[AUTO]   DLL     : %s\n\n", dllPath);

    // ── Step 3: Verify DLL exists ─────────────────────────────────────────────
    if (!FileExists(dllPath)) {
        printf("[ERROR] Injection DLL not found in:\n        %s\n\n", selfDir);
        printf("  Expected one of: %s  or  %s\n",
               DLL_CANDIDATES[0], DLL_CANDIDATES[1]);
        printf("  Build TS3VASManager first (run TS3VASManager_build.bat),\n");
        printf("  then copy the DLL into:\n  %s\n", selfDir);
        system("pause");
        return 1;
    }

    // ── Step 4: (server removed) ──────────────────────────────────────────────
    // The DLL runs local-only now (private arena, no capture/eviction/restore), so
    // there is no server to launch.  The launcher's only job is injection.

    // ── Step 5a: DIRECT mode (1.67 / 1.70) ───────────────────────────────────
    if (mode == Mode::DIRECT) {
        // Build mutable command line for Detours (lpCommandLine must be writable)
        char cmdLine[MAX_PATH + 512] = {};
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", gameExe);
        // Pass any extra args forwarded to this launcher
        for (int i = 1; i < argc; ++i) {
            strncat_s(cmdLine, " ", _TRUNCATE);
            strncat_s(cmdLine, argv[i], _TRUNCATE);
        }

        printf("[DIRECT] Command : %s\n", cmdLine);
        printf("[DIRECT] Injecting DLL at process creation (pre-OEP)...\n\n");

        STARTUPINFOA        si = {};
        PROCESS_INFORMATION pi = {};
        si.cb = sizeof(si);

        // DetourCreateProcessWithDllExA:
        //   Spawns TS3W.exe CREATE_SUSPENDED, writes our DLL into its import table,
        //   resumes — DllMain fires before a single game instruction executes.
        BOOL ok = DetourCreateProcessWithDllExA(
            gameExe,      // lpApplicationName
            cmdLine,      // lpCommandLine (mutable)
            nullptr,      // lpProcessAttributes
            nullptr,      // lpThreadAttributes
            FALSE,        // bInheritHandles
            CREATE_DEFAULT_ERROR_MODE,
            nullptr,      // lpEnvironment (inherit)
            selfDir,      // lpCurrentDirectory
            &si, &pi,
            dllPath,      // DLL to inject via import table
            nullptr       // pfCreateProcessA — system default
        );

        if (!ok) {
            DWORD err = GetLastError();
            printf("[ERROR] DetourCreateProcessWithDllExA failed: %lu (0x%08lX)\n\n",
                   err, err);
            if      (err == ERROR_ELEVATION_REQUIRED)
                printf("  Run TS3Launcher.exe as Administrator.\n");
            else if (err == ERROR_FILE_NOT_FOUND)
                printf("  Game exe or DLL path not found. Verify files are in Game\\Bin.\n");
            else if (err == ERROR_BAD_EXE_FORMAT)
                printf("  Architecture mismatch. Launcher and game must both be x86.\n");
            system("pause");
            return 1;
        }

        printf("[OK] Process created — PID %lu  TID %lu\n", pi.dwProcessId, pi.dwThreadId);
        printf("[OK] DLL injected pre-OEP. Hooks live from first instruction.\n");
        // Bump the game to HIGH priority: give the simulation more CPU so it runs
        // faster and (hypothesis) churns less VAS while we hunt heaps.
        if (SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS))
            printf("[OK] Game process priority set to HIGH.\n");
        else
            printf("[WARN] SetPriorityClass(HIGH) failed: %lu\n", GetLastError());
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    // ── Step 5b: MONITOR mode (1.69 EA/Origin) ───────────────────────────────
    else {
        // Check if the game is already running (user may have started it manually)
        DWORD pid = FindProcess(gameExeName);

        if (pid) {
            printf("[MONITOR] %s already running (PID %lu) — injecting directly.\n\n",
                   gameExeName, pid);
        } else {
            // Try to start the EA intermediate launcher if present in Game\Bin.
            char eaLauncher[MAX_PATH];
            snprintf(eaLauncher, MAX_PATH, "%s\\%s", selfDir, EXE_EALAUN);

            if (FileExists(eaLauncher)) {
                SpawnIntermediateLauncher(eaLauncher);
                // Give the EA launcher a moment to settle before we start polling
                Sleep(2000);
            } else {
                printf("[MONITOR] %s not found in Game\\Bin.\n", EXE_EALAUN);
                printf("[MONITOR] Start the game via EA App now — watching for %s...\n\n",
                       gameExeName);
            }

            pid = WaitForProcess(gameExeName, GAME_TIMEOUT_SEC);
            if (!pid) {
                printf("[ERROR] %s did not appear within %lu seconds.\n",
                       gameExeName, GAME_TIMEOUT_SEC);
                system("pause");
                return 1;
            }
        }

        // Brief pause so the game's CRT and loader finish early init.
        // This is the earliest-safe injection point for remote LoadLibraryA.
        // Alpha note: adjust PRE_INJECT_SLEEP_MS based on log results.
        printf("[MONITOR] Waiting %lu ms for early game init before injection...\n",
               PRE_INJECT_SLEEP_MS);
        Sleep(PRE_INJECT_SLEEP_MS);

        if (!InjectDLL(pid, dllPath)) {
            system("pause");
            return 1;
        }

        printf("\n[OK] %s injected into %s (PID %lu)\n",
               dllName, gameExeName, pid);
        printf("[OK] Hooks installing via DllMain.\n");
    }

    // Job done — the game runs independently of us, so exit immediately rather than
    // linger on screen.  (DIRECT: DLL is already in the game's import table; MONITOR:
    // already LoadLibrary'd in.)
    return 0;
}
