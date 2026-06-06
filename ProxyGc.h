#pragma once
#include <windows.h>

// ── ProxyGc — Mono pressure signal ──────────────────────────────────────────────
// The embedded Mono GC triggers on its own managed-heap growth and is blind to
// native VAS pressure (the game never calls AddMemoryPressure on its native-backed
// wrappers).  WE can see the pressure — largest-free VAS every heartbeat — so when
// it drops, or on a 30-min floor, we SetEvent a named auto-reset event
// ("Local\\TS3VAS_MonoGcRequest") that a small managed companion mod waits on to run
// GC.Collect()+WaitForPendingFinalizers().  Asking Mono to collect is its own safe
// operation; this is not us freeing.
//
// (The observe-only conservative proxy-slot scanner that used to live here was
//  removed — it flagged zero abandoned slots every cycle, confirming the game frees
//  its proxy allocations cleanly and the leak was never in the proxy.)
namespace ProxyGc {
    void Init();                                            // create the event (once)
    void MaybeRequestMonoCollect(SIZE_T largestFreeBytes);  // call per heartbeat tick

    // Latest Mono managed-heap size (GC.GetTotalMemory), published by the C#
    // companion into a shared-memory block we create.  0 if the companion isn't
    // loaded / hasn't reported yet.  Read by HeartbeatMonitor so the managed-heap
    // size lands in the VAS_REPORT line (graphable alongside total/largest free).
    unsigned long long GetScriptHeapBytes();
}
