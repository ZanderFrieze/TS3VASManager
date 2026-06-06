#pragma once
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <sddl.h>

class EmergencyLogger {
public:
    static void Initialize();
    static void Shutdown();
    static EmergencyLogger* GetInstance();

    static void Write(const char* component, const char* message);

    template<typename... Args>
    static void WriteF(const char* component, const char* format, Args... args) {
        if (GetInstance()) {
            GetInstance()->WriteLogF(component, format, args...);
        }
    }

private:
    EmergencyLogger();
    ~EmergencyLogger();
    EmergencyLogger(const EmergencyLogger&) = delete;
    EmergencyLogger& operator=(const EmergencyLogger&) = delete;

    void WriteLog(const char* component, const char* message);
    
    template<typename... Args>
    void WriteLogF(const char* component, const char* format, Args... args) {
        char buffer[1024];
        sprintf_s(buffer, sizeof(buffer), format, args...);
        WriteLog(component, buffer);
    }

    static void CreateLogDirectoryWithOpenPermissions();

    HANDLE m_hFile;
    CRITICAL_SECTION m_cs;
    static EmergencyLogger* s_instance;
};

#define EmergencyLog(comp, msg) EmergencyLogger::Write(comp, msg)
#define EmergencyLogF(comp, fmt, ...) EmergencyLogger::WriteF(comp, fmt, __VA_ARGS__)