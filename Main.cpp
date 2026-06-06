#include "Logger.h"
#include "MemoryManager.h"
#include "HookManager.h"
#include "ExceptionHandler.h"
#include "HeartbeatMonitor.h"
#include "Analytics.h"
#include "HitchDetector.h"
#include "StackWalker.h"
#include "VASPressureMonitor.h"
#include "WorkingHooks.h"
#include "ObserverHooks.h"
#include "EmergencyLogger.h"
#include "ETWProvider.h"
#include <windows.h>
#include <Psapi.h>
#include <new>

#pragma comment(lib, "psapi.lib")

const char* g_buildSignature =
    "[BUILD_SIGNATURE_V3] TS3Patch Build: " __DATE__ " " __TIME__;

static MemoryManager*   g_memoryManager   = nullptr;
static HookManager*           g_hookManager           = nullptr;
static ExceptionHandler*      g_exceptionHandler      = nullptr;
static HeartbeatMonitor*      g_heartbeatMonitor      = nullptr;
static bool                   g_isStarted             = false;
static volatile LONG          g_isStopping            = 0;

void StartPatch();
void StopPatch();

static bool EnvFlagEnabled(const char* name, bool defaultValue = false) {
    char buf[16] = {};
    DWORD n = GetEnvironmentVariableA(name, buf, (DWORD)sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return defaultValue;
    const char c = buf[0];
    return (c == '1' || c == 'y' || c == 'Y' || c == 't' || c == 'T');
}

// ── Singleton storage (placement-new in static buffers avoids heap at init) ─
static char s_analyticsStorage     [sizeof(Analytics)];
static char s_hitchDetectorStorage [sizeof(HitchDetector)];

Analytics*           Analytics::s_instance           = nullptr;
HitchDetector*       HitchDetector::s_instance       = nullptr;

void Analytics::Initialize()          { if (!s_instance) s_instance = new(s_analyticsStorage) Analytics(); }
void Analytics::Shutdown()            { if (s_instance) { s_instance->~Analytics(); s_instance = nullptr; } }
Analytics* Analytics::GetInstance()   { return s_instance; }

void HitchDetector::Initialize()         { if (!s_instance) s_instance = new(s_hitchDetectorStorage) HitchDetector(); }
void HitchDetector::Shutdown()           { if (s_instance) { s_instance->~HitchDetector(); s_instance = nullptr; } }
HitchDetector* HitchDetector::GetInstance() { return s_instance; }

// ────────────────────────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            CloseHandle(CreateThread(NULL, 0,
                (LPTHREAD_START_ROUTINE)StartPatch, NULL, 0, NULL));
            break;
        case DLL_PROCESS_DETACH:
            EmergencyLogF("DllMain", "DLL_PROCESS_DETACH lpReserved=%p isStarted=%d isStopping=%ld",
                lpReserved, g_isStarted ? 1 : 0, InterlockedCompareExchange(&g_isStopping, 0, 0));
            if (lpReserved != nullptr) {
                // Process is terminating: avoid full object teardown under loader shutdown.
                WorkingHooks::BeginShutdown();
                return TRUE;
            }
            StopPatch();
            break;
    }
    return TRUE;
}

// ────────────────────────────────────────────────────────────────────────────
void StartPatch() {
    EmergencyLogger::Initialize();

    // Log which process we're in — critical for multi-exe compatibility
    char procName[MAX_PATH] = {};
    GetModuleFileNameA(NULL, procName, MAX_PATH);
    EmergencyLogF("StartPatch", "Enter. Process: %s", procName);

    // Skip launcher and non-game processes.
    // Blacklist approach handles all versions:
    //   1.67 disc  → TS3W.exe (preferred) or TS3.exe
    //   1.69 EA    → TS3.exe (forced through Sims3Launcher.exe)
    //   1.70 Steam → TS3W.exe
    if (strstr(procName, "Launcher") ||
        strstr(procName, "launcher") ||
        strstr(procName, "patcher")  ||
        strstr(procName, "CASMode")) {
        EmergencyLog("StartPatch", "Non-game process — skipping.");
        return;
    }

    if (g_isStarted) { EmergencyLog("StartPatch", "Already started."); return; }

    try {
        // PHASE 0 — ETW provider (before logger so even logger-init failures are traceable)
        TS3VASEtw::Register();

        // PHASE 1 — Logger
        Logger::Initialize("TS3VAS");
        Logger* logger = Logger::GetInstance();
        if (!logger) { EmergencyLog("StartPatch", "FATAL: Logger NULL."); return; }
        g_isStarted = true;

        logger->Info("==================================================================");
        logger->Info(g_buildSignature);
        logger->Info("==================================================================");
        logger->Info("[PHASE_1] Logger initialized.");

        if (SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS))
            logger->Info("[PHASE_1] Process priority set to HIGH.");
        else
            logger->Warn("[PHASE_1] SetPriorityClass failed. GLE=%lu", GetLastError());

        // PHASE 2 — Core subsystems
        logger->Info("[PHASE_2] Initializing core subsystems...");
        Analytics::Initialize();
        HitchDetector::Initialize();
        StackWalker::Initialize();
        VASPressureMonitor::Initialize();
        logger->Info("[PHASE_2] Core subsystems ready.");

        // PHASE 3 — proxy arena (local-only: a single private arena with
        // eager-committed slots; allocations are contained, never evicted).
        logger->Info("[PHASE_3] Initializing proxy memory manager...");
        g_memoryManager = new MemoryManager();
        if (!g_memoryManager->Initialize()) {
            logger->Error("[PHASE_3] CRITICAL: proxy arena init failed!");
            StopPatch(); return;
        }
        logger->Info("[PHASE_3] Proxy memory manager ready.");

        // PHASE 4 — top-level crash-logging exception filter
        logger->Info("[PHASE_4] Installing exception handler...");
        g_exceptionHandler = new ExceptionHandler();
        g_exceptionHandler->Install();
        logger->Info("[PHASE_4] Exception handler installed.");

        // PHASE 5 — Hooks (Rtl + ReadFile, active immediately — no D3D9 wait)
        logger->Info("[PHASE_5] Installing hooks...");
        g_hookManager = new HookManager(g_memoryManager);
        if (!g_hookManager->InstallAndEnableHooks()) {
            logger->Error("[PHASE_5] CRITICAL: Hook installation failed!");
            StopPatch(); return;
        }

        // Activate proxy immediately — hooks are live so every allocation is
        // now visible.  Previously activation waited for beat 10/15 (~20-30s),
        // meaning the first 42+ large allocations during game load went
        // unproxied and fragmented the heap before we could intervene.
        WorkingHooks::ActivateProxy();
        logger->Info("[HOOKS] All hooks installed and live — RtlAllocateHeap catching all heap allocations from process start.");

        // Start heartbeat immediately (no PatchActivator needed)
        g_heartbeatMonitor = new HeartbeatMonitor(g_memoryManager);
        g_heartbeatMonitor->Start();
        StackWalker::GetInstance()->Start();

        logger->Info("[PHASE_5] All hooks live. RtlAllocateHeap active from process start.");
        if (EnvFlagEnabled("TS3VAS_ENABLE_D3D9_HOOK", true)) {
            ObserverHooks::Install();
            logger->Info("[PHASE_5] D3D9 hook enabled (default ON; set TS3VAS_ENABLE_D3D9_HOOK=0 to disable) — Present telemetry + CPU/GPU resource table.");
        } else {
            logger->Info("[PHASE_5] D3D9 hook disabled (TS3VAS_ENABLE_D3D9_HOOK=0).");
        }
        logger->Flush(); // flush immediately — process may exit before the block below
        logger->Info("==================================================================");
        logger->Info("  TS3VASManager: Rtl* + Nt* + VirtualAlloc* + VirtualProtect/Query/Lock + Heap* + MapView/CreateFileMapping/OpenFileMapping/Flush hooked");
        logger->Info("  No D3D9 activation trigger required.");
        logger->Info("==================================================================");
        logger->Flush();

    } catch (...) {
        EmergencyLog("StartPatch", "CATASTROPHIC FAILURE IN INIT THREAD.");
    }
    EmergencyLog("StartPatch", "Exit.");
}

// ────────────────────────────────────────────────────────────────────────────
void StopPatch() {
    if (InterlockedCompareExchange(&g_isStopping, 1, 0) != 0) return;
    EmergencyLog("StopPatch", "Enter.");
    EmergencyLogF("StopPatch", "State started=%d proxy=%p hooks=%p heartbeat=%p",
        g_isStarted ? 1 : 0, g_memoryManager, g_hookManager, g_heartbeatMonitor);
    EmergencyLog("StopPatch", "Begin RTL shutdown/pass-through.");
    WorkingHooks::BeginShutdown();

    Logger* logger = Logger::GetInstance();
    if (logger && g_isStarted) {
        logger->Info("==================================================================");
        logger->Info("           TS3VAS: Shutdown Sequence Started");
        logger->Info("==================================================================");
    }

    if (g_hookManager)        { EmergencyLog("StopPatch", "Deleting hook manager."); delete g_hookManager;        g_hookManager        = nullptr; EmergencyLog("StopPatch", "Deleted hook manager."); }
    ObserverHooks::Uninstall();
    if (g_heartbeatMonitor)   { EmergencyLog("StopPatch", "Deleting heartbeat monitor."); delete g_heartbeatMonitor;   g_heartbeatMonitor   = nullptr; EmergencyLog("StopPatch", "Deleted heartbeat monitor."); }
    if (g_exceptionHandler)   { EmergencyLog("StopPatch", "Deleting exception handler."); delete g_exceptionHandler;   g_exceptionHandler   = nullptr; EmergencyLog("StopPatch", "Deleted exception handler."); }
    if (g_memoryManager){ EmergencyLog("StopPatch", "Deleting proxy memory manager."); delete g_memoryManager;g_memoryManager= nullptr; EmergencyLog("StopPatch", "Deleted proxy memory manager."); }

    if (g_isStarted) {
        EmergencyLog("StopPatch", "Shutting down StackWalker.");
        StackWalker::Shutdown();
        EmergencyLog("StopPatch", "Shutting down HitchDetector.");
        HitchDetector::Shutdown();

        if (Analytics::GetInstance()) Analytics::GetInstance()->Report();
        EmergencyLog("StopPatch", "Shutting down Analytics.");
        Analytics::Shutdown();
        EmergencyLog("StopPatch", "Shutting down VASPressureMonitor.");
        VASPressureMonitor::Shutdown();

        if (logger) {
            logger->Info("==================================================================");
            logger->Info("           TS3VAS: Shutdown Complete");
            logger->Info("==================================================================");
            Logger::Shutdown();
        }
    }

    g_isStarted = false;
    TS3VASEtw::Unregister();
    EmergencyLog("StopPatch", "Shutdown complete.");
    EmergencyLogger::Shutdown();
}
