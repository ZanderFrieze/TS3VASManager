#pragma once
#include <windows.h>
#include <stdio.h>

class Logger {
public:
    static Logger* GetInstance();

    static void Initialize(const char* logName);
    static void Shutdown();

    void Info(const char* fmt, ...);
    void Warn(const char* fmt, ...);
    void Error(const char* fmt, ...);
    void NamedInfo(const char* logName, const char* fmt, ...);
    void NamedWarn(const char* logName, const char* fmt, ...);
    void NamedError(const char* logName, const char* fmt, ...);
    void Flush();

private:
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void Init(const char* logName);
    void Log(const char* level, const char* fmt, va_list args);
    void LogNamed(const char* logName, const char* level, const char* fmt, va_list args);
    void AttachConsole();

    HANDLE m_hFile;
    CRITICAL_SECTION m_logCS;
    bool m_initialized;

    static Logger* s_instance;
};
