#include "StackWalker.h"
#include "Logger.h"
#include "EmergencyLogger.h"
#include <new>

static char s_stackWalkerStorage[sizeof(StackWalker)];
StackWalker* StackWalker::s_instance = nullptr;

const int MAX_LINE_LENGTH = 1024;
const int MAX_QUEUE_SIZE = 50;  // Prevent unbounded queue growth

void StackWalker::Initialize() {
    if (s_instance == nullptr) {
        s_instance = new (s_stackWalkerStorage) StackWalker();
    }
}

void StackWalker::Shutdown() {
    if (s_instance) {
        s_instance->~StackWalker();
        s_instance = nullptr;
    }
}

StackWalker* StackWalker::GetInstance() { 
    return s_instance; 
}

StackWalker::StackWalker()
    : m_threadHandle(NULL)
    , m_semaphore(NULL)
    , m_stop(false)
    , m_droppedCaptures(0)
{
    InitializeCriticalSection(&m_queueCS);
    EmergencyLog("StackWalker", "Stack trace output routed to TS3VAS logger.");

    m_semaphore = CreateSemaphore(NULL, 0, LONG_MAX, NULL);
    if (!m_semaphore) {
        EmergencyLogF("StackWalker", "FATAL: CreateSemaphore failed! GLE=%lu", GetLastError());
        return;
    }
    EmergencyLog("StackWalker", "Constructor finished. Worker thread NOT started yet.");
}

StackWalker::~StackWalker() {
    EmergencyLog("StackWalker", "Destructor: Enter");
    m_stop.store(true);
    EmergencyLog("StackWalker", "Destructor: Stop flag set.");

    if (m_semaphore) {
        EmergencyLog("StackWalker", "Destructor: Releasing semaphore to wake worker.");
        ReleaseSemaphore(m_semaphore, 1, NULL);
        EmergencyLog("StackWalker", "Destructor: Semaphore released.");
    } else {
        EmergencyLog("StackWalker", "Destructor: Semaphore handle is NULL, skipping release.");
    }
    
    if (m_threadHandle) {
        EmergencyLog("StackWalker", "Destructor: Waiting for worker thread to exit.");
        DWORD waitResult = WaitForSingleObject(m_threadHandle, 2000);
        EmergencyLogF("StackWalker", "Destructor: WaitForSingleObject returned 0x%lX", waitResult);
        if (waitResult == WAIT_TIMEOUT) {
            EmergencyLog("StackWalker", "Destructor: Worker thread did not exit cleanly, terminating.");
            TerminateThread(m_threadHandle, 1);
        }
        CloseHandle(m_threadHandle);
        m_threadHandle = NULL;
        EmergencyLog("StackWalker", "Destructor: Thread handle closed.");
    } else {
        EmergencyLog("StackWalker", "Destructor: Thread handle is NULL, skipping wait/close.");
    }
    
    if (m_semaphore) {
        CloseHandle(m_semaphore);
        m_semaphore = NULL;
        EmergencyLog("StackWalker", "Destructor: Semaphore handle closed.");
    }

    DeleteCriticalSection(&m_queueCS);
    EmergencyLog("StackWalker", "Destructor: Critical section deleted.");
    
    if (m_droppedCaptures.load() > 0) {
        EmergencyLogF("StackWalker", "Destructor: Total dropped captures: %d", m_droppedCaptures.load());
    }
}

void StackWalker::Start() {
    if (m_threadHandle) {
        return; // Already started
    }
    // Do not start if the semaphore wasn't created.
    if (!m_semaphore) {
        EmergencyLog("StackWalker", "Start() called but semaphore is NULL. Aborting thread creation.");
        return;
    }
    
    m_threadHandle = CreateThread(NULL, 0, WorkerThreadFunc, this, 0, NULL);
    if (m_threadHandle) {
        SetThreadPriority(m_threadHandle, THREAD_PRIORITY_LOWEST);
        EmergencyLog("StackWalker", "Worker thread started via Start().");
        if (Logger::GetInstance()) {
            Logger::GetInstance()->Info("[STACKWALKER] Asynchronous raw stack capture service started.");
        }
    } else {
        EmergencyLogF("StackWalker", "FAILED to create worker thread! GLE=%lu", GetLastError());
    }
}

bool StackWalker::CaptureAndLogStackAsync(const char* reason) {
    if (m_stop.load()) {
        return false;
    }
    
    if (!reason) {
        reason = "Unknown";
    }
    
    if (!m_semaphore || !m_threadHandle) {
        return false;
    }

    StackWalkRequest request = {};
    request.ThreadId = GetCurrentThreadId();
    
    strncpy_s(request.Reason, sizeof(request.Reason), reason, _TRUNCATE);
    
    PVOID frames[MAX_STACK_FRAMES];
    USHORT frameCount = CaptureStackBackTrace(1, MAX_STACK_FRAMES, frames, NULL);
    
    request.FrameCount = frameCount;
    
    for (USHORT i = 0; i < frameCount; ++i) {
        request.Frames[i] = (uintptr_t)frames[i];
    }
    
    if (frameCount == 0) {
        return false;
    }
    
    bool queued = false;
    EnterCriticalSection(&m_queueCS);
    
    if (m_queue.size() < MAX_QUEUE_SIZE) {
        m_queue.push(request);
        queued = true;
    } else {
        m_droppedCaptures.fetch_add(1);
    }
    
    LeaveCriticalSection(&m_queueCS);

    if (queued) {
        ReleaseSemaphore(m_semaphore, 1, NULL);
    }
    
    return queued;
}

// Route stack text through the main logger so it lands in TS3VAS_*.
void StackWalker::WriteToStackFile(const char* text) {
    if (!text || text[0] == '\0') return;

    Logger* logger = Logger::GetInstance();
    if (logger) {
        logger->Info("[STACKTRACE] %s", text);
        return;
    }

    EmergencyLogF("StackWalker", "STACKTRACE (logger unavailable): %s", text);
}

void StackWalker::LogStackOnCrash(PCONTEXT context, const char* reason) {
    // Write directly to the stack-trace file first — Logger may be torn down
    // or locked on the crashing thread.  This write always reaches disk because
    // the file was opened with FILE_FLAG_WRITE_THROUGH.
    char line[MAX_LINE_LENGTH];

    SYSTEMTIME st;
    GetLocalTime(&st);
    wsprintfA(line, "\r\n=== CRASH STACK TRACE [%02d/%02d %02d:%02d] Reason: %s  TID: %lu ===\r\n",
              st.wMonth, st.wDay, st.wHour, st.wMinute,
              reason ? reason : "Crash", GetCurrentThreadId());
    WriteToStackFile(line);

    if (context) {
        wsprintfA(line, "  EIP: 0x%08X\r\n", context->Eip);
        WriteToStackFile(line);
    }

    PVOID frames[MAX_STACK_FRAMES];
    USHORT frameCount = CaptureStackBackTrace(0, MAX_STACK_FRAMES, frames, NULL);

    if (frameCount == 0) {
        WriteToStackFile("  (No frames captured — stack may be corrupted)\r\n");
    } else {
        for (USHORT i = 0; i < frameCount; ++i) {
            sprintf_s(line, "  #%02d: 0x%p\r\n", i, frames[i]);
            WriteToStackFile(line);
        }
    }
    WriteToStackFile("=== End Crash Stack Trace ===\r\n");

    // Also mirror to Logger if it's still alive
    Logger* logger = Logger::GetInstance();
    if (logger) {
        logger->Error("--- Raw Stack Trace (Reason: %s, TID: %lu) ---",
                      reason ? reason : "Crash", GetCurrentThreadId());
        if (context) logger->Error("  EIP: 0x%08X", context->Eip);
        if (frameCount == 0) {
            logger->Error("  (No frames captured - stack may be corrupted)");
        } else {
            for (USHORT i = 0; i < frameCount; ++i) {
                sprintf_s(line, "  #%02d: 0x%p", i, frames[i]);
                logger->Error("%s", line);
            }
        }
        logger->Error("--- End Stack Trace ---");
        logger->Flush();
    }
}

void StackWalker::LogRawFrames(StackWalkRequest& request) {
    char line[256];

    // ── Emit full frame list into TS3VAS via Logger ───────────────────
    SYSTEMTIME st;
    GetLocalTime(&st);
    wsprintfA(line, "\r\n--- Stack Trace [%02d/%02d %02d:%02d] Reason: %s  TID: %lu ---\r\n",
              st.wMonth, st.wDay, st.wHour, st.wMinute,
              request.Reason, request.ThreadId);
    WriteToStackFile(line);

    if (request.FrameCount == 0) {
        WriteToStackFile("  (No frames captured - FPO optimization or corrupted stack)\r\n");
    } else {
        for (int frame = 0; frame < request.FrameCount; ++frame) {
            sprintf_s(line, "  #%02d: 0x%08X\r\n", frame, (unsigned int)request.Frames[frame]);
            WriteToStackFile(line);
        }
    }
    WriteToStackFile("--- End Stack Trace ---\r\n");

    // ── Also mirror a summary line to the main Logger ─────────────────────────
    Logger* logger = Logger::GetInstance();
    if (logger) {
        logger->Info("[STACKTRACE] %s TID:%lu frames:%d  #00:0x%08X",
                     request.Reason, request.ThreadId, request.FrameCount,
                     request.FrameCount > 0 ? (unsigned int)request.Frames[0] : 0u);
    }
}

DWORD WINAPI StackWalker::WorkerThreadFunc(LPVOID param) {
    StackWalker* self = static_cast<StackWalker*>(param);
    if (!self) return 1;

    EmergencyLog("StackWalker", "Worker thread: Started");
    self->ProcessQueue();
    EmergencyLog("StackWalker", "Worker thread: Exiting");
    return 0;
}

void StackWalker::ProcessQueue() {
    while (!m_stop.load()) {
        DWORD waitResult = WaitForSingleObject(m_semaphore, 500);

        if (waitResult == WAIT_TIMEOUT)  continue;

        if (waitResult != WAIT_OBJECT_0) {
            EmergencyLogF("StackWalker", "Semaphore wait failed with result %lu", waitResult);
            break;
        }

        if (m_stop.load()) break;

        StackWalkRequest request;
        bool hasRequest = false;

        EnterCriticalSection(&m_queueCS);
        if (!m_queue.empty()) {
            request = m_queue.front();
            m_queue.pop();
            hasRequest = true;
        }
        LeaveCriticalSection(&m_queueCS);

        if (hasRequest) {
            LogRawFrames(request);
        }
    }

    EmergencyLog("StackWalker", "Worker thread: Draining queue before exit");
    EnterCriticalSection(&m_queueCS);
    size_t remainingCount = m_queue.size();
    LeaveCriticalSection(&m_queueCS);

    if (remainingCount > 0) {
        EmergencyLogF("StackWalker", "Worker thread: %zu requests remain in queue", remainingCount);
    }
}

bool StackWalker::IsValidAddress(DWORD_PTR addr) {
    if (addr < 0x10000) return false;
    if (addr >= 0x80000000) return false;
    
    __try {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        
        return (mbi.State == MEM_COMMIT);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
