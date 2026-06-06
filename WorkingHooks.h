#pragma once
#include <windows.h>

class MemoryManager;

// s_tlsIndex defined once in WorkingHooks.cpp; extern here so all TUs share the
// single TLS slot. The old "static DWORD" gave every .cpp its own copy that
// Install() never updated, making IsInHook() silently always-false elsewhere.
extern DWORD s_tlsIndex;

inline bool  IsInHook() { return s_tlsIndex != TLS_OUT_OF_INDEXES && TlsGetValue(s_tlsIndex) != nullptr; }
inline void  SetInHook(bool v) { if (s_tlsIndex != TLS_OUT_OF_INDEXES) TlsSetValue(s_tlsIndex, (LPVOID)(v ? 1 : 0)); }

// Point-in-time copy of the allocation counters — all fields are plain (non-
// volatile) so callers can do arithmetic across two snapshots to get deltas.
struct RtlAllocSnapshot {
    LONGLONG captured;
    LONGLONG capturedBytes;    // sum of bytesGameExe + bytesGraphics + bytesRuntimeDll
                                // for captured allocs (proxy traffic)
    LONGLONG bytesByModule[6];  // game, graphics, runtime, system, mod, unknown
    LONGLONG captureFailed;
    LONGLONG localVasReserveBytes;
    LONGLONG localVasByModule[6]; // same order as bytesByModule
};

namespace WorkingHooks {
    bool Install(MemoryManager* memManager);
    void Uninstall();
    void EnableHooks();
    void BeginShutdown();
    bool IsShuttingDown();
    void ActivateProxy();   // called by heartbeat after stable startup
    bool IsProxyActive();
    void ReportAllocCallsites(const char* logName);
    void ReportLocalVasSources(const char* logName);
    void ReportProxyHeapUsage(const char* logName);   // sardine sub-allocator shards

    // Non-blocking snapshot of the running alloc counters for phase-diff reports.
    void CaptureAllocSnapshot(RtlAllocSnapshot& out);
}
