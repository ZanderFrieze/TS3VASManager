#include "Logger.h"
#include <stdio.h>
#include <string.h>
#include <new>
#include <sddl.h>
#include "EmergencyLogger.h"

Logger* Logger::s_instance = nullptr;
static char s_loggerStorage[sizeof(Logger)];
static bool s_loggerConstructed = false;

// Cached once at Logger::Init() — used by every NamedLog file so they all
// share the same MMDD_HHMM stamp regardless of when they're first written.
static char s_sessionStamp[16] = {};

#ifndef TS3VAS_TELEMETRY
// Play build only: the main log file is created LAZILY, on the first ERROR/crash
// write, so a normal session leaves NO files behind. Path is built in Init().
static char s_mainLogPath[MAX_PATH] = {};
static HANDLE EnsureLazyLogFile(HANDLE cur) {
    if (cur != INVALID_HANDLE_VALUE || !s_mainLogPath[0]) return cur;
    return CreateFileA(s_mainLogPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
}
#endif

static bool ShouldSuppressConsoleNamed(const char* logName) {
    if (!logName) return false;
    // High-volume observe-only channels: keep them in their files, off the live
    // console so the VAS readout stays watchable.
    return _stricmp(logName, "MEMHOOK")          == 0 ||
           _stricmp(logName, "CPU_TABLE")        == 0 ||
           _stricmp(logName, "GPU_TABLE")        == 0 ||
           _stricmp(logName, "OBSERVE")          == 0 ||
           _stricmp(logName, "RESERVE_CTX")      == 0 ||
           _stricmp(logName, "ANALYTICS_REPORT") == 0 ||
           _stricmp(logName, "GFX_SHADOW")       == 0;
}

static bool ShouldSuppressConsoleLine(const char* line) {
    if (!line) return false;
    return strstr(line, "[HITCH]") != nullptr;
}

// Route multiple named channels into fewer physical files so report output
// stays manageable per session.
static const char* ResolveNamedLogTarget(const char* logName) {
    if (!logName || !*logName) return logName;

    // Consolidate core VAS diagnostics into one timeline file.
    if (_stricmp(logName, "VAS_REPORT") == 0 ||
        _stricmp(logName, "VAS_LOCAL_SOURCES") == 0 ||
        _stricmp(logName, "SCRIPT_VAS") == 0 ||
        _stricmp(logName, "VAS_SNAPSHOT") == 0 ||
        _stricmp(logName, "VAS_SLOPE") == 0) {
        return "VAS_COMBINED";
    }

    // Consolidate low-volume operational summaries.
    if (_stricmp(logName, "PHASE_DIFF") == 0 ||
        _stricmp(logName, "SERVER_REPORT") == 0 ||
        _stricmp(logName, "PROXY_ARENA_REPORT") == 0 ||
        _stricmp(logName, "RTL_ALLOC_REPORT") == 0) {
        return "OPS_REPORT";
    }

    // Consolidate the observe-only CPU/GPU tables into one dedicated file so
    // they don't clog the live main-log / VAS readouts.
    if (_stricmp(logName, "CPU_TABLE") == 0 ||
        _stricmp(logName, "GPU_TABLE") == 0) {
        return "OBSERVE";
    }

    return logName;
}

Logger* Logger::GetInstance() {
    return s_instance;
}

void Logger::Initialize(const char* logName) {
    if (s_instance == nullptr) {
        s_instance = new (s_loggerStorage) Logger();
        s_loggerConstructed = true;
        if (s_instance) {
            s_instance->Init(logName);
        }
    }
}

void Logger::Shutdown() {
    if (s_instance != nullptr) {
        if (s_loggerConstructed) {
            s_instance->~Logger();
            s_loggerConstructed = false;
        }
        s_instance = nullptr;
    }
}

Logger::Logger() : m_hFile(INVALID_HANDLE_VALUE), m_initialized(false) {
    InitializeCriticalSection(&m_logCS);
}

Logger::~Logger() {
    if (m_initialized) {
        Info("Logger shutting down.");
        if (m_hFile != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(m_hFile);
            CloseHandle(m_hFile);
            m_hFile = INVALID_HANDLE_VALUE;
        }
    }
    DeleteCriticalSection(&m_logCS);
}

void Logger::AttachConsole() {
#ifdef TS3VAS_TELEMETRY
    // Debug/telemetry build only: pop a console mirroring the log stream.
    // The play build (TS3VAS_TELEMETRY=OFF) stays windowless — file logging
    // to C:\ts3_tool continues regardless of whether a console exists.
    if (AllocConsole()) {
        SetConsoleTitleA("TS3VASManager Debug Console");
    }
#endif
}

static void CreateLogDirectoryWithOpenPermissions() {
    const char* dirPath = "C:\\ts3_tool";
    if (CreateDirectoryA(dirPath, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
    }
}

void Logger::Init(const char* logName) {
    EmergencyLog("Logger", "Init called");
    
    if (m_initialized) {
        EmergencyLog("Logger", "Already initialized, returning");
        return;
    }

    AttachConsole();
    EmergencyLog("Logger", "AttachConsole returned");

    CreateLogDirectoryWithOpenPermissions();
    EmergencyLog("Logger", "CreateLogDirectory returned");

    SYSTEMTIME st;
    GetLocalTime(&st);

    // Store the session stamp once — all named logs will reuse it.
    wsprintfA(s_sessionStamp, "%02d%02d_%02d%02d", st.wMonth, st.wDay, st.wHour, st.wMinute);

#ifdef TS3VAS_TELEMETRY
    char logPath[MAX_PATH];
    wsprintfA(logPath, "C:\\ts3_tool\\%s_%s.txt", logName, s_sessionStamp);
    EmergencyLogF("Logger", "Log path constructed: %s", logPath);

    EmergencyLog("Logger", "Calling CreateFileA");
    m_hFile = CreateFileA(logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    EmergencyLogF("Logger", "CreateFileA returned. Handle: 0x%p", m_hFile);

    m_initialized = true;

    if (m_hFile == INVALID_HANDLE_VALUE) {
        EmergencyLogF("Logger", "FATAL: Failed to open log file. GLE=%lu", GetLastError());
    } else {
        Info("Logger initialized. Log file: %s", logPath);
    }
#else
    // Play build: stay silent. Defer file creation to the first ERROR/crash write
    // (Log()), so a normal session writes nothing. Routine Info/Warn/Named are
    // no-ops; only the crash dump lands here, in xcpt_<stamp>.txt.
    (void)logName;
    wsprintfA(s_mainLogPath, "C:\\ts3_tool\\xcpt_%s.txt", s_sessionStamp);
    m_hFile = INVALID_HANDLE_VALUE;
    m_initialized = true;
#endif
}

void Logger::Log(const char* level, const char* fmt, va_list args) {
    if (!m_initialized) {
        return;
    }

#ifndef TS3VAS_TELEMETRY
    // Play build: silent except for ERROR/crash output. Routine Info/Warn drop
    // here; the first ERROR lazily creates the xcpt file.
    if (strcmp(level, "ERROR") != 0) return;
    if (m_hFile == INVALID_HANDLE_VALUE) m_hFile = EnsureLazyLogFile(m_hFile);
#endif

    EnterCriticalSection(&m_logCS);

    char buffer[2048];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    buffer[sizeof(buffer) - 1] = '\0';

    char final_buf[2100];
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    wsprintfA(final_buf, "[%02d:%02d:%02d.%03d] [%s] %s\r\n",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level, buffer);
    
    OutputDebugStringA(final_buf);
    
    if (!ShouldSuppressConsoleLine(final_buf)) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole != NULL && hConsole != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten;
            WriteConsoleA(hConsole, final_buf, lstrlenA(final_buf), &bytesWritten, NULL);
        }
    }

    if (m_hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(m_hFile, final_buf, lstrlenA(final_buf), &bytesWritten, NULL);
    }

    LeaveCriticalSection(&m_logCS);
}

void Logger::LogNamed(const char* logName, const char* level, const char* fmt, va_list args) {
    if (!m_initialized || !logName || !*logName) {
        return;
    }

#ifndef TS3VAS_TELEMETRY
    // Play build: no per-channel telemetry files (ANALYTICS_REPORT, VAS_*, etc.).
    (void)level; (void)fmt; (void)args;
    return;
#else
    const char* fileTarget = ResolveNamedLogTarget(logName);
    if (!fileTarget || !*fileTarget) fileTarget = logName;

    EnterCriticalSection(&m_logCS);

    char buffer[2048];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    buffer[sizeof(buffer) - 1] = '\0';

    SYSTEMTIME st;
    GetLocalTime(&st);

    char final_buf[2200];
    wsprintfA(final_buf, "[%02d:%02d:%02d.%03d] [%s] [%s] %s\r\n",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
              level, logName, buffer);

    OutputDebugStringA(final_buf);

    if (!ShouldSuppressConsoleNamed(logName) && !ShouldSuppressConsoleLine(final_buf)) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole != NULL && hConsole != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten;
            WriteConsoleA(hConsole, final_buf, lstrlenA(final_buf), &bytesWritten, NULL);
        }
    }

    if (m_hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(m_hFile, final_buf, lstrlenA(final_buf), &bytesWritten, NULL);
    }

    char namedPath[MAX_PATH];
    // Use the session stamp so all entries for this named log land in one file,
    // and the file is never overwritten by a later launch.
    wsprintfA(namedPath, "C:\\ts3_tool\\%s_%s.txt", fileTarget, s_sessionStamp);
    HANDLE hNamed = CreateFileA(namedPath, FILE_APPEND_DATA, FILE_SHARE_READ,
                                NULL, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (hNamed != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hNamed, final_buf, lstrlenA(final_buf), &bytesWritten, NULL);
        CloseHandle(hNamed);
    }

    LeaveCriticalSection(&m_logCS);
#endif // TS3VAS_TELEMETRY
}

void Logger::Info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log("INFO", fmt, args);
    va_end(args);
}

void Logger::Warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log("WARN", fmt, args);
    va_end(args);
}

void Logger::Error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log("ERROR", fmt, args);
    va_end(args);
}

void Logger::NamedInfo(const char* logName, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogNamed(logName, "INFO", fmt, args);
    va_end(args);
}

void Logger::NamedWarn(const char* logName, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogNamed(logName, "WARN", fmt, args);
    va_end(args);
}

void Logger::NamedError(const char* logName, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogNamed(logName, "ERROR", fmt, args);
    va_end(args);
}

void Logger::Flush() {
    if (m_initialized && m_hFile != INVALID_HANDLE_VALUE) {
        EnterCriticalSection(&m_logCS);
        FlushFileBuffers(m_hFile);
        LeaveCriticalSection(&m_logCS);
    }
}
