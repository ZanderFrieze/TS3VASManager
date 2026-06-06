#pragma once
#include <windows.h>

// Installs the top-level crash-logging exception filter (SetUnhandledExceptionFilter).
// The per-page Vectored Exception Handler was removed — the proxy arena is eager-
// committed, so proxy pages never fault.
class ExceptionHandler {
public:
    ExceptionHandler();
    ~ExceptionHandler();

    void Install();
    void Uninstall();

private:
    static LONG CALLBACK UnhandledFilter(PEXCEPTION_POINTERS p);
    static void PrintStackTrace(PCONTEXT context);
    static void LogContextRecord(PCONTEXT context);

    LPTOP_LEVEL_EXCEPTION_FILTER m_previousFilter;
};
