#include "ProxyGc.h"
#include "Logger.h"
#include "Analytics.h"

#include <cstdint>
#include <cstdlib>

namespace {

const uint64_t MB = 1024ull * 1024ull;

HANDLE   s_gcReqEvent  = nullptr;
uint64_t s_lastGcReqMs = 0;

// Shared-memory bridge for the managed-heap size.  We (native) create a named
// section; the C# companion opens it and writes [0]=GC.GetTotalMemory bytes,
// [1]=publish tick.  Single writer (companion), single reader (us) — plain
// interlocked reads are enough.
HANDLE             s_shMap  = nullptr;
volatile LONG64*   s_shHeap = nullptr;   // s_shHeap[0]=bytes, s_shHeap[1]=tick

// Proactive collection: keep the managed heap swept on a regular cadence even with VAS
// to spare, instead of only reacting once we're already low.  Collect MORE often once
// largest-free drops under the pressure threshold (set ABOVE the game's own ~500 MB
// self-management point so we sweep before it panics).  All tunable via env.
uint64_t s_pressureBytes       = 1024 * MB;       // largest-free below this = "pressure"
uint64_t s_proactiveIntervalMs = 60ull * 1000;    // collect this often with VAS to spare
uint64_t s_pressureIntervalMs  = 15ull * 1000;    // collect this often once under pressure

uint64_t EnvU64(const char* name, uint64_t dflt) {
    char v[32] = {};
    DWORD n = GetEnvironmentVariableA(name, v, (DWORD)sizeof(v));
    if (n == 0 || n >= sizeof(v)) return dflt;
    uint64_t r = _strtoui64(v, nullptr, 10);
    return r ? r : dflt;
}

} // namespace

namespace ProxyGc {

void Init() {
    s_pressureBytes       = EnvU64("TS3VAS_GC_PRESSURE_MB", 1024) * MB;
    s_proactiveIntervalMs = EnvU64("TS3VAS_GC_INTERVAL_SEC", 60) * 1000;
    s_pressureIntervalMs  = EnvU64("TS3VAS_GC_PRESSURE_SEC", 15) * 1000;

    // Shared block for the managed-heap size (16 bytes: bytes + tick).  Created here
    // (native, at DLL load) so the companion can reliably OpenFileMapping it later.
    s_shMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 16,
                                 L"Local\\TS3VAS_ScriptHeap");
    if (s_shMap) {
        void* v = MapViewOfFile(s_shMap, FILE_MAP_ALL_ACCESS, 0, 0, 16);
        if (v) { s_shHeap = (volatile LONG64*)v; s_shHeap[0] = 0; s_shHeap[1] = 0; }
    }

    // Auto-reset, initially non-signaled.  The managed companion opens the same name.
    s_gcReqEvent = CreateEventW(nullptr, FALSE, FALSE, L"Local\\TS3VAS_MonoGcRequest");
    if (Logger::GetInstance())
        Logger::GetInstance()->NamedInfo("PROXY_GC",
            "init: event=%s | collect every %llus (proactive), every %llus under <%llu MB",
            s_gcReqEvent ? "ok" : "FAIL",
            (unsigned long long)(s_proactiveIntervalMs / 1000),
            (unsigned long long)(s_pressureIntervalMs / 1000),
            (unsigned long long)(s_pressureBytes / MB));
}

void MaybeRequestMonoCollect(SIZE_T largestFreeBytes) {
    if (!s_gcReqEvent) return;
    uint64_t now = GetTickCount64();
    uint64_t sinceLast = (s_lastGcReqMs == 0) ? UINT64_MAX : (now - s_lastGcReqMs);

    // Tighten the cadence once VAS is under pressure; otherwise sweep on the proactive
    // interval.  (The heartbeat calls this every ~2s, so that's the hard floor on rate.)
    bool pressure = (largestFreeBytes > 0) && (largestFreeBytes < s_pressureBytes);
    uint64_t interval = pressure ? s_pressureIntervalMs : s_proactiveIntervalMs;
    if (sinceLast < interval) return;

    s_lastGcReqMs = now;
    SetEvent(s_gcReqEvent);
    if (Analytics::GetInstance())
        Analytics::GetInstance()->IncrementCounter(pressure ? "MonoGc_Req_Pressure" : "MonoGc_Req_Proactive");
    if (Logger::GetInstance())
        Logger::GetInstance()->NamedInfo("PROXY_GC",
            "mono collect REQUESTED reason=%s largest_free=%llu MB since_last=%llu s",
            pressure ? "pressure" : "proactive",
            (unsigned long long)(largestFreeBytes / MB),
            (unsigned long long)(sinceLast == UINT64_MAX ? 0 : sinceLast / 1000));
}

unsigned long long GetScriptHeapBytes() {
    if (!s_shHeap) return 0;
    return (unsigned long long)InterlockedCompareExchange64(&s_shHeap[0], 0, 0);
}

} // namespace ProxyGc
