#include "ExceptionHandler.h"
#include "Logger.h"
#include "StackWalker.h"
#include "EmergencyLogger.h"
#include "Analytics.h"
#include "WorkingHooks.h"

// Crash-logging top-level filter only.  The per-page Vectored Exception Handler was
// removed: the proxy arena is eager-committed at allocation, so no proxy page ever
// faults — PROXY_FreshCommit_Ok stayed 0 across multi-hour runs, confirming the lazy-
// commit fault path never fired.

ExceptionHandler::ExceptionHandler()
    : m_previousFilter(nullptr) {
}

ExceptionHandler::~ExceptionHandler() {
    Uninstall();
}

void ExceptionHandler::Install() {
    m_previousFilter = SetUnhandledExceptionFilter(UnhandledFilter);
}

void ExceptionHandler::Uninstall() {
    if (m_previousFilter) {
        SetUnhandledExceptionFilter(m_previousFilter);
        m_previousFilter = nullptr;
    }
}

void ExceptionHandler::LogContextRecord(PCONTEXT context) {
    Logger* logger = Logger::GetInstance();
    if (!logger || !context) return;

    logger->Error("--- BEGIN CPU CONTEXT DUMP ---");
    logger->Error("  EAX: 0x%08X   EBX: 0x%08X   ECX: 0x%08X", context->Eax, context->Ebx, context->Ecx);
    logger->Error("  EDX: 0x%08X   ESI: 0x%08X   EDI: 0x%08X", context->Edx, context->Esi, context->Edi);
    logger->Error("  EIP: 0x%08X   ESP: 0x%08X   EBP: 0x%08X", context->Eip, context->Esp, context->Ebp);
    logger->Error("  Flags: 0x%08X", context->EFlags);
    logger->Error("--- END CPU CONTEXT DUMP ---");
}

void ExceptionHandler::PrintStackTrace(PCONTEXT context) {
    if (StackWalker::GetInstance()) {
        StackWalker::GetInstance()->LogStackOnCrash(context, "Unhandled Exception");
    }
}

LONG CALLBACK ExceptionHandler::UnhandledFilter(PEXCEPTION_POINTERS p) {
    // Immediately stop the proxy hooks from intercepting any further allocations.
    // Everything from this point runs through the real allocator — no re-entrancy
    // risk in Logger, StackWalker, or any other subsystem we call during cleanup.
    WorkingHooks::BeginShutdown();

    EmergencyLogF("UnhandledFilter", "!!! UNHANDLED EXCEPTION 0x%08X at 0x%p !!!",
        p->ExceptionRecord->ExceptionCode, p->ExceptionRecord->ExceptionAddress);

    Logger* logger = Logger::GetInstance();
    if (!logger || !p || !p->ExceptionRecord) {
        EmergencyLog("UnhandledFilter", "Logger or exception pointers are NULL. Cannot log details.");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    logger->Error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    logger->Error("!!!               FATAL: UNHANDLED EXCEPTION CAUGHT            !!!");
    logger->Error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    logger->Error("  Exception Code:    0x%08X", p->ExceptionRecord->ExceptionCode);
    logger->Error("  Exception Address: 0x%p", p->ExceptionRecord->ExceptionAddress);
    logger->Error("  Exception Flags:   0x%08X", p->ExceptionRecord->ExceptionFlags);
    logger->Error("  NumberParameters:  %lu", p->ExceptionRecord->NumberParameters);
    for (DWORD i = 0; i < p->ExceptionRecord->NumberParameters; ++i) {
        logger->Error("    Param[%lu]: 0x%p", i, (void*)p->ExceptionRecord->ExceptionInformation[i]);
    }

    if (p->ContextRecord) {
        LogContextRecord(p->ContextRecord);
        PrintStackTrace(p->ContextRecord);
    } else {
        logger->Error("  CRITICAL: ContextRecord is NULL, cannot dump registers or stack trace.");
    }

    logger->Error("--- FINALIZING LOGS BEFORE TERMINATION ---");
    logger->Flush();

    if (Analytics::GetInstance()) Analytics::GetInstance()->Report();

    Logger::Shutdown();

    return EXCEPTION_EXECUTE_HANDLER;
}
