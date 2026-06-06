#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <queue>
#include <atomic>

#define MAX_STACK_FRAMES 32  // Reduced from 60 for better reliability

class Logger;

class StackWalker {
public:
    static void Initialize();
    static void Shutdown();
    static StackWalker* GetInstance();

    void Start();
    // Returns true if capture was successful
    bool CaptureAndLogStackAsync(const char* reason);
    void LogStackOnCrash(PCONTEXT context, const char* reason);
    static bool IsValidAddress(DWORD_PTR addr);

private:
    struct StackWalkRequest {
        uintptr_t Frames[MAX_STACK_FRAMES];
        int FrameCount;
        char Reason[128];
        DWORD ThreadId;
    };

    StackWalker();
    ~StackWalker();
    StackWalker(const StackWalker&) = delete;
    StackWalker& operator=(const StackWalker&) = delete;
    
    static DWORD WINAPI WorkerThreadFunc(LPVOID param);
    void ProcessQueue();
    void LogRawFrames(StackWalkRequest& request);
    void WriteToStackFile(const char* text);   // Routed to main logger (TS3VAS)
    bool IsShuttingDown() const { return m_stop.load(); }
    
    HANDLE m_threadHandle;
    HANDLE m_semaphore;
    CRITICAL_SECTION m_queueCS;
    std::queue<StackWalkRequest> m_queue;
    std::atomic<bool> m_stop;
    std::atomic<int> m_droppedCaptures;

    static StackWalker* s_instance;
};
