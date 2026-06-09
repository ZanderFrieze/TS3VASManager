#include "EmergencyLogger.h"
#include <new>

static char s_emergencyLoggerStorage[sizeof(EmergencyLogger)];
EmergencyLogger* EmergencyLogger::s_instance = nullptr;

void EmergencyLogger::Initialize() {
    if (s_instance == nullptr) {
        s_instance = new (s_emergencyLoggerStorage) EmergencyLogger();
    }
}

void EmergencyLogger::Shutdown() {
    if (s_instance) {
        s_instance->~EmergencyLogger();
        s_instance = nullptr;
    }
}

EmergencyLogger* EmergencyLogger::GetInstance() {
    return s_instance;
}

void EmergencyLogger::Write(const char* component, const char* message) {
    if (GetInstance()) {
        GetInstance()->WriteLog(component, message);
    }
}

EmergencyLogger::EmergencyLogger() : m_hFile(INVALID_HANDLE_VALUE) {
    InitializeCriticalSection(&m_cs);
    CreateLogDirectoryWithOpenPermissions();

#ifdef TS3VAS_TELEMETRY
    // Unique per-launch filename: main_log_MMDD_HHMM.txt
    // FILE_FLAG_WRITE_THROUGH so every write survives a crash without a flush call.
    SYSTEMTIME st;
    GetLocalTime(&st);
    char path[MAX_PATH];
    sprintf_s(path, sizeof(path), "C:\\ts3_tool\\main_log_%02d%02d_%02d%02d.txt",
              st.wMonth, st.wDay, st.wHour, st.wMinute);

    m_hFile = CreateFileA(path,
                          FILE_APPEND_DATA,
                          FILE_SHARE_READ,
                          NULL,
                          OPEN_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                          NULL);
#endif
    // Play build (TS3VAS_TELEMETRY=OFF): no main_log file. m_hFile stays INVALID,
    // so WriteLog() no-ops — the play build's only output is the crash xcpt file
    // (Logger ERROR path). Keeps "just play" silent during normal sessions.
}

EmergencyLogger::~EmergencyLogger() {
    if (m_hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hFile);
    }
    DeleteCriticalSection(&m_cs);
}

void EmergencyLogger::CreateLogDirectoryWithOpenPermissions() {
    const char* dirPath = "C:\\ts3_tool";
    if (CreateDirectoryA(dirPath, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = FALSE;

        if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;OICI;GA;;;WD)",
            SDDL_REVISION_1,
            &sa.lpSecurityDescriptor,
            NULL))
        {
            SetFileSecurityA(dirPath, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor);
            LocalFree(sa.lpSecurityDescriptor);
        }
    }
}

void EmergencyLogger::WriteLog(const char* component, const char* message) {
    if (m_hFile == INVALID_HANDLE_VALUE || !component || !message) return;

    char timeStamp[128];
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(timeStamp, sizeof(timeStamp), "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    char finalMsg[2048];
    sprintf_s(finalMsg, sizeof(finalMsg), "%s[%s:%lu] %s\r\n", timeStamp, component, GetCurrentThreadId(), message);

    EnterCriticalSection(&m_cs);
    DWORD bytesWritten;
    WriteFile(m_hFile, finalMsg, (DWORD)strlen(finalMsg), &bytesWritten, NULL);
    LeaveCriticalSection(&m_cs);
}