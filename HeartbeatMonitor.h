#pragma once
#include <windows.h>

class MemoryManager;

class HeartbeatMonitor {
public:
    explicit HeartbeatMonitor(MemoryManager* memManager);
    ~HeartbeatMonitor();

    void Start();
    void Stop();
    static SIZE_T GetLatestLargestFreeBytes();
    static SIZE_T GetLatestTotalFreeBytes();
    static ULONGLONG GetLatestSampleTickMs();

    // Emit a labelled full-detail VAS snapshot to the log (can be called from
    // any thread at any time — e.g. the heartbeat thread at a given beat).
    static void LogVasSnapshot(const char* label);

private:
    static DWORD WINAPI HeartbeatThreadFunc(LPVOID param);
    void GetProcessMemoryInfo(SIZE_T& availableVAS, SIZE_T& largestFreeBlock);

    MemoryManager* m_memManager;
    HANDLE m_threadHandle;
    HANDLE m_wakeEvent;   // signalled by Stop() to unblock the sleep immediately
    volatile LONG m_stopFlag;
};
