// MemoryManager.cpp  (TS3VASManager.dll — 32-bit, in-game)
// See MemoryManager.h for design notes.

#include "MemoryManager.h"
#include "Logger.h"
#include "Analytics.h"
#include "VASPressureMonitor.h"
#include "EmergencyLogger.h"
#include "ETWProvider.h"
#include <cstdlib>
#include <Psapi.h>

constexpr SIZE_T PROXY_ARENA_SIZE = 1024ULL * 1024 * 1024; // 1 GB (holds proxy allocs + the in-arena sardine shards)

// Set by CreateProxyAllocation when it declines because the caller is our own
// DLL (CallerIsSelf).  The RtlAllocateHeap hook reads this so it doesn't count an
// intentional self-skip as an "capture failure".  Thread-local: each alloc path
// is synchronous on its own thread.
static thread_local bool t_lastCreateSelfSkip = false;
// Foreign/system threads our injected DLL never set up have no TLS array (TEB+0x2C
// null); touching a C++ thread_local there faults.  Guard t_lastCreateSelfSkip with
// this (such threads can reach CreateProxyAllocation via the realloc-of-arena path
// before the hook's bootstrap check).
static inline bool ThreadHasTls() {
    return *(LPVOID*)((BYTE*)NtCurrentTeb() + 0x2C) != nullptr;
}
bool MemoryManager::LastCreateWasSelfSkip() { return ThreadHasTls() && t_lastCreateSelfSkip; }

static LONG g_lowVasInit = 0;
// Default OFF: never hard-reject proxy allocations due to low-VAS policy.
// We still use low-VAS as a pressure signal (telemetry only), but allocation
// attempts should continue to flow through the proxy path.
static SIZE_T g_lowVasSkipBytes = 0;

static SIZE_T ResolveLowVasSkipBytes() {
    if (InterlockedCompareExchange(&g_lowVasInit, 1, 0) == 0) {
        char buf[32] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_LOWVAS_SKIP_MB", buf, (DWORD)sizeof(buf));
        if (n > 0 && n < sizeof(buf)) {
            long v = strtol(buf, nullptr, 10);
            if (v <= 0) g_lowVasSkipBytes = 0; // disable skip gate
            else g_lowVasSkipBytes = (SIZE_T)v * 1024ULL * 1024ULL;
        }
    }
    return g_lowVasSkipBytes;
}

static LONG g_proxyCreateLogCfgInit = 0;
static LONG g_proxyCreateVerbose = 0;
static DWORD g_proxyCreateTallyIntervalMs = 5000;
static volatile LONG64 s_proxyCreateReqTotal = 0;
static volatile LONG64 s_proxyCreateOkTotal = 0;
static volatile LONG64 s_proxyCreateFailTotal = 0;
static volatile LONG64 s_proxyCreateBytesTotal = 0;
static volatile LONG64 s_proxyCreateReqSnap = 0;
static volatile LONG64 s_proxyCreateOkSnap = 0;
static volatile LONG64 s_proxyCreateFailSnap = 0;
static volatile LONG64 s_proxyCreateBytesSnap = 0;
static volatile LONG s_proxyCreateLastLogTick = 0;
static volatile LONG s_allocFailStreak = 0;

static void InitProxyCreateLogCfg() {
    if (InterlockedCompareExchange(&g_proxyCreateLogCfgInit, 1, 0) != 0) return;
    char buf[32] = {};
    DWORD n = GetEnvironmentVariableA("TS3VAS_VERBOSE_PROXY_CREATE_LOGS", buf, (DWORD)sizeof(buf));
    if (n > 0 && n < sizeof(buf) && (buf[0] == '1' || buf[0] == 'y' || buf[0] == 'Y' || buf[0] == 't' || buf[0] == 'T'))
        g_proxyCreateVerbose = 1;
    ZeroMemory(buf, sizeof(buf));
    n = GetEnvironmentVariableA("TS3VAS_PROXY_TALLY_MS", buf, (DWORD)sizeof(buf));
    if (n > 0 && n < sizeof(buf)) {
        long v = strtol(buf, nullptr, 10);
        if (v >= 250) g_proxyCreateTallyIntervalMs = (DWORD)v;
    }
}

static void MaybeLogProxyCreateTally() {
    Logger* log = Logger::GetInstance();
    if (!log) return;
    DWORD now = GetTickCount();
    LONG last = s_proxyCreateLastLogTick;
    if ((DWORD)(now - (DWORD)last) < g_proxyCreateTallyIntervalMs) return;
    if (InterlockedCompareExchange(&s_proxyCreateLastLogTick, (LONG)now, last) != last) return;

    // Use InterlockedAdd64(p,0) for atomic 64-bit reads — plain volatile LONG64
    // loads are not atomic on 32-bit x86 and can tear against Interlocked writers.
    const LONG64 req   = InterlockedAdd64(const_cast<volatile LONG64*>(&s_proxyCreateReqTotal),   0);
    const LONG64 ok    = InterlockedAdd64(const_cast<volatile LONG64*>(&s_proxyCreateOkTotal),    0);
    const LONG64 fail  = InterlockedAdd64(const_cast<volatile LONG64*>(&s_proxyCreateFailTotal),  0);
    const LONG64 bytes = InterlockedAdd64(const_cast<volatile LONG64*>(&s_proxyCreateBytesTotal), 0);

    const LONG64 dReq = req - s_proxyCreateReqSnap;
    const LONG64 dOk = ok - s_proxyCreateOkSnap;
    const LONG64 dFail = fail - s_proxyCreateFailSnap;
    const LONG64 dBytes = bytes - s_proxyCreateBytesSnap;

    s_proxyCreateReqSnap = req;
    s_proxyCreateOkSnap = ok;
    s_proxyCreateFailSnap = fail;
    s_proxyCreateBytesSnap = bytes;

    log->NamedInfo("PROXY_TALLY",
        "CreateProxyAllocation: +%lld req +%lld ok +%lld fail +%llu MB | total req=%lld ok=%lld fail=%lld bytes=%llu MB",
        dReq, dOk, dFail, (unsigned long long)(dBytes / (1024 * 1024)),
        req, ok, fail, (unsigned long long)(bytes / (1024 * 1024)));
}

static SIZE_T EnvMb(const char* name, SIZE_T dfltMb);   // defined below; used by Initialize

static void ProxyBucket(const char* prefix, SIZE_T size) {
    Analytics* a = Analytics::GetInstance();
    if (!a) return;
    const int bucket =
        (size < 256  * 1024)        ? 0 :
        (size < 512  * 1024)        ? 1 :
        (size < 1024 * 1024)        ? 2 :
        (size < 4    * 1024 * 1024) ? 3 :
        (size < 16   * 1024 * 1024) ? 4 : 5;

    const char* name = nullptr;
    if (strcmp(prefix, "PROXY_Alloc_Request") == 0) {
        static const char* kNames[] = {
            "PROXY_Alloc_Request_128to256KB",
            "PROXY_Alloc_Request_256to512KB",
            "PROXY_Alloc_Request_512KBto1MB",
            "PROXY_Alloc_Request_1to4MB",
            "PROXY_Alloc_Request_4to16MB",
            "PROXY_Alloc_Request_16MBplus"
        };
        name = kNames[bucket];
    } else if (strcmp(prefix, "PROXY_Alloc_Succeeded") == 0) {
        static const char* kNames[] = {
            "PROXY_Alloc_Succeeded_128to256KB",
            "PROXY_Alloc_Succeeded_256to512KB",
            "PROXY_Alloc_Succeeded_512KBto1MB",
            "PROXY_Alloc_Succeeded_1to4MB",
            "PROXY_Alloc_Succeeded_4to16MB",
            "PROXY_Alloc_Succeeded_16MBplus"
        };
        name = kNames[bucket];
    } else if (strcmp(prefix, "PROXY_Alloc_Failed") == 0) {
        static const char* kNames[] = {
            "PROXY_Alloc_Failed_128to256KB",
            "PROXY_Alloc_Failed_256to512KB",
            "PROXY_Alloc_Failed_512KBto1MB",
            "PROXY_Alloc_Failed_1to4MB",
            "PROXY_Alloc_Failed_4to16MB",
            "PROXY_Alloc_Failed_16MBplus"
        };
        name = kNames[bucket];
    }
    if (name) a->IncrementCounter(name);
}

// Eight-band size classifier mirroring AllocSize_*/AllocBytes_* (WorkingHooks.cpp) so
// the proxy-redirect and proxy-free rows line up with the ALLOC_SIZE_DIST block-size
// histogram.  Bumps a count counter (<cntPrefix>_<band>) and a byte accumulator
// (<bytePrefix>_<band>); both are read back by the HeartbeatMonitor reports.
static void RecordProxyBandPair(const char* cntPrefix, const char* bytePrefix, SIZE_T size) {
    Analytics* a = Analytics::GetInstance();
    if (!a) return;
    const char* band =
        (size <    4 * 1024)      ? "0to4KB"     :
        (size <   64 * 1024)      ? "4to64KB"    :
        (size <  256 * 1024)      ? "64to256KB"  :
        (size <  512 * 1024)      ? "256to512KB" :
        (size < 1024 * 1024)      ? "512KBto1MB" :
        (size < 4  * 1024 * 1024) ? "1to4MB"     :
        (size < 16 * 1024 * 1024) ? "4to16MB"    : "16MBplus";
    char name[64];
    sprintf_s(name, "%s_%s", cntPrefix, band);
    a->IncrementCounter(name);
    sprintf_s(name, "%s_%s", bytePrefix, band);
    a->IncrementCounter(name, (uint64_t)size);
}


static SIZE_T ResolveDynamicLowVasSkipBytes(SIZE_T base) {
    // Previously scaled the skip floor by the restore rate; with eviction/restore
    // retired there are no restores, so the floor is simply the base.
    return base;
}

static const char* LaneFailTag(ContainmentLane lane) {
    switch (lane) {
    case ContainmentLane::LANE_EXCLUDED_A:
    case ContainmentLane::LANE_EXCLUDED_B:
    case ContainmentLane::LANE_EXCLUDED_C:
    case ContainmentLane::LANE_EXCLUDED_D:
        return "Excluded";
    default:
        return "Contained";
    }
}

static void RecordAllocFailForLane(ContainmentLane lane, const char* reason, SIZE_T size) {
    const LONG streak = InterlockedIncrement(&s_allocFailStreak);
    const char* laneTag = LaneFailTag(lane);
    if (Analytics::GetInstance()) {
        char ctr[64];
        sprintf_s(ctr, "PROXY_Alloc_Fail_%s", laneTag);
        Analytics::GetInstance()->IncrementCounter(ctr);
        if (reason && *reason) {
            sprintf_s(ctr, "PROXY_Alloc_Fail_%s_%s", laneTag, reason);
            Analytics::GetInstance()->IncrementCounter(ctr);
        }
    }
    EmergencyLogF("ALLOC_FAIL", "lane=%s size=%zu reason=%s streak=%ld", laneTag, size, reason ? reason : "unknown", streak);
}

static void RecordAllocSuccessStreakReset() {
    InterlockedExchange(&s_allocFailStreak, 0);
}

// ── Constructor / Destructor ──────────────────────────────────────────────────

MemoryManager::MemoryManager()
    : m_pageSize(0),
      m_proxyMaxBytes(0),
      m_corralSegCount(0), m_corralStartBytes(0), m_corralGrowFloor(0),
      m_corralMaxReserved(0), m_corralTotalReserved(0),
      m_corralPeakBytes(0), m_corralReady(false)
{
    EmergencyLog("PROXY_Ctor", "Enter.");
    InitializeCriticalSection(&m_mapCS);
    InitializeCriticalSection(&m_corralCS);
    memset(m_corralSegAlloc, 0, sizeof(m_corralSegAlloc));
    memset(m_corralSegBase,  0, sizeof(m_corralSegBase));
    memset(m_corralSegSize,  0, sizeof(m_corralSegSize));
    SYSTEM_INFO si; GetSystemInfo(&si);
    m_pageSize = si.dwPageSize;
    EmergencyLog("PROXY_Ctor", "Exit.");
}

MemoryManager::~MemoryManager() {
    EmergencyLogF("PROXY_Dtor", "Enter. allocations=%zu", m_allocations.size());
    EnterCriticalSection(&m_mapCS);
    for (auto const& [proxy_ptr, record] : m_allocations)
        VirtualFree(record.proxy_base, record.proxy_size, MEM_DECOMMIT);
    m_allocations.clear();
    LeaveCriticalSection(&m_mapCS);
    DeleteCriticalSection(&m_mapCS);

    // Release every script-arena segment (its sub-allocator + its reservation).
    EnterCriticalSection(&m_corralCS);
    for (int i = 0; i < m_corralSegCount; ++i) {
        if (m_corralSegAlloc[i]) { m_corralSegAlloc[i]->Shutdown(); delete m_corralSegAlloc[i]; m_corralSegAlloc[i] = nullptr; }
        if (m_corralSegBase[i])  { VirtualFree(m_corralSegBase[i], 0, MEM_RELEASE); m_corralSegBase[i] = nullptr; }
    }
    m_corralSegCount = 0;
    LeaveCriticalSection(&m_corralCS);
    DeleteCriticalSection(&m_corralCS);

    m_proxyAllocator.Shutdown();
    EmergencyLog("PROXY_Dtor", "Exit.");
}

// ── Initialize ───────────────────────────────────────────────────────────────

bool MemoryManager::Initialize() {
    EmergencyLog("PROXY_Init", "Enter.");
    bool ok = m_proxyAllocator.Initialize(PROXY_ARENA_SIZE);
    EmergencyLogF("PROXY_Init", "Initialize(private arena) ok=%d", ok);

    // Proxy upper bound.  Default 0 = uncapped: the big VirtualAlloc MEM_RESERVE
    // blocks (e.g. TS3W.exe+0xE53D7's 16 MB regions — dozens per world load) are the
    // single largest drain on largest_free, and they meet every redirect condition
    // EXCEPT a size ceiling.  Sending them to the arena (which fails gracefully to
    // local when a request won't fit) is the whole point.  Env-tunable if a future
    // run needs to re-fence a pathological size.
    m_proxyMaxBytes = EnvMb("TS3VAS_PROXY_MAX_MB", 0);
    if (m_proxyMaxBytes)
        EmergencyLogF("PROXY_Init", "Proxy max size = %zu MB (allocs >= this stay local)",
                      m_proxyMaxBytes / (1024 * 1024));
    else
        EmergencyLogF("PROXY_Init", "Proxy max size = uncapped (all sizes eligible; arena spills to local when full)");

    // Claim the script write-watch arena NOW, while hooks are live and the address
    // space is still unfragmented — so the game can't scatter into it.  Optional:
    // failure just means CorralReserve returns null and reserves fall back to OS
    // placement.  TS3VAS_SCRIPT_ARENA=0 disables (skips the reservation entirely).
    {
        char v[8] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_SCRIPT_ARENA", v, (DWORD)sizeof(v));
        if (!(n == 1 && v[0] == '0'))   // default ON
            InitScriptArena();
    }

    return ok;
}


// ── Script write-watch arena ────────────────────────────────────────────────────
// Reserve write-watch zones we OWN and sub-allocate the game's write-watch reserves
// (the Mono script/JIT heap) from them instead of letting them scatter across VAS.
// Starts at TS3VAS_SCRIPT_ARENA_MB and GROWS on demand so we can measure how big the
// script heap really gets — growth segments are >=2x the triggering reserve, floored
// at TS3VAS_SCRIPT_ARENA_GROW_MB, total capped at TS3VAS_SCRIPT_ARENA_MAX_MB so we
// never starve the process of VAS (growth beyond the cap falls back to OS placement).

static SIZE_T EnvMb(const char* name, SIZE_T dfltMb) {
    char v[32] = {};
    DWORD n = GetEnvironmentVariableA(name, v, (DWORD)sizeof(v));
    SIZE_T mb = (n > 0 && n < sizeof(v)) ? (SIZE_T)_strtoui64(v, nullptr, 10) : 0;
    if (mb == 0) mb = dfltMb;
    return mb * 1024u * 1024u;
}

// Append one MEM_RESERVE|MEM_WRITE_WATCH zone + its sub-allocator.  Caller holds
// m_corralCS (or runs before m_corralReady).  Publishes the slot fields before
// bumping the count so lock-free IsCorralAddress readers never see a half-built seg.
bool MemoryManager::AddCorralSegment(SIZE_T size) {
    int idx = m_corralSegCount;
    if (idx >= kMaxCorralSegs) return false;
    if (m_corralMaxReserved && (m_corralTotalReserved + size) > m_corralMaxReserved)
        return false;   // VAS safety cap — let the reserve fall back to the OS
    LPVOID base = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS);
    if (!base) {
        EmergencyLogF("SCRIPT_ARENA", "SEG_RESERVE_FAIL size=%zu MB GLE=%lu",
                      size / (1024 * 1024), GetLastError());
        return false;
    }
    ProxyAllocator* a = new (std::nothrow) ProxyAllocator();
    if (!a || !a->InitFromShared(base, size)) {
        if (a) delete a;
        VirtualFree(base, 0, MEM_RELEASE);
        EmergencyLog("SCRIPT_ARENA", "SEG allocator InitFromShared failed");
        return false;
    }
    m_corralSegBase[idx]  = base;
    m_corralSegSize[idx]  = size;
    m_corralSegAlloc[idx] = a;
    m_corralTotalReserved += size;
    MemoryBarrier();
    m_corralSegCount = idx + 1;   // publish only after the fields above are set
    EmergencyLogF("SCRIPT_ARENA", "grew: seg[%d] base=%p size=%zu MB total_reserved=%zu MB",
                  idx, base, size / (1024 * 1024), m_corralTotalReserved / (1024 * 1024));
    return true;
}

bool MemoryManager::InitScriptArena() {
    m_corralStartBytes  = EnvMb("TS3VAS_SCRIPT_ARENA_MB", 126);
    m_corralGrowFloor   = EnvMb("TS3VAS_SCRIPT_ARENA_GROW_MB", 32);
    m_corralMaxReserved = EnvMb("TS3VAS_SCRIPT_ARENA_MAX_MB", 512);
    EnterCriticalSection(&m_corralCS);
    bool ok = AddCorralSegment(m_corralStartBytes);
    LeaveCriticalSection(&m_corralCS);
    m_corralReady = ok;
    if (ok)
        EmergencyLogF("SCRIPT_ARENA", "ready: start=%zu MB grow>=%zu MB cap=%zu MB",
                      m_corralStartBytes / (1024 * 1024), m_corralGrowFloor / (1024 * 1024),
                      m_corralMaxReserved / (1024 * 1024));
    return ok;
}

LPVOID MemoryManager::CorralReserve(SIZE_T size, DWORD allocType, DWORD protect) {
    if (!m_corralReady || size == 0) return nullptr;

    // One lock for the whole op: write-watch reserves are rare (tens / session), so a
    // global serialize is free and makes segment-list access trivially safe.
    EnterCriticalSection(&m_corralCS);

    LPVOID slot = nullptr; int segIdx = -1;
    for (int i = 0; i < m_corralSegCount; ++i) {
        slot = m_corralSegAlloc[i]->Allocate(size);
        if (slot) { segIdx = i; break; }
    }
    if (!slot) {
        // All segments full — grow.  New segment is >=2x the triggering reserve,
        // floored, capped (AddCorralSegment enforces the VAS cap).
        SIZE_T segSz = size * 2;
        if (segSz < m_corralGrowFloor) segSz = m_corralGrowFloor;
        if (AddCorralSegment(segSz)) {
            segIdx = m_corralSegCount - 1;
            slot   = m_corralSegAlloc[segIdx]->Allocate(size);
        }
    }
    if (!slot) { LeaveCriticalSection(&m_corralCS); return nullptr; }  // full + can't grow → OS

    // Commit it if the game asked for MEM_COMMIT (with its protection — exec for JIT);
    // otherwise leave it reserved like the game's bare MEM_RESERVE.
    if (allocType & MEM_COMMIT) {
        DWORD prot = protect ? protect : PAGE_READWRITE;
        if (!VirtualAlloc(slot, size, MEM_COMMIT, prot)) {
            m_corralSegAlloc[segIdx]->Free(slot, size);
            LeaveCriticalSection(&m_corralCS);
            return nullptr;
        }
    }
    m_corralSizes[slot] = size;

    // Peak = total used across all segments, for sizing.
    SIZE_T usedTotal = 0;
    for (int i = 0; i < m_corralSegCount; ++i)
        usedTotal += (SIZE_T)m_corralSegAlloc[i]->GetStats().usedBytes;
    for (;;) {
        LONG64 prev = InterlockedCompareExchange64(&m_corralPeakBytes, 0, 0);
        if ((LONG64)usedTotal <= prev ||
            InterlockedCompareExchange64(&m_corralPeakBytes, (LONG64)usedTotal, prev) == prev)
            break;
    }
    LeaveCriticalSection(&m_corralCS);
    return slot;
}

bool MemoryManager::CorralFree(LPVOID addr) {
    if (!m_corralReady || !addr) return false;
    SIZE_T size = 0;
    ProxyAllocator* owner = nullptr;
    EnterCriticalSection(&m_corralCS);
    auto it = m_corralSizes.find(addr);
    if (it != m_corralSizes.end()) {
        size = it->second;
        m_corralSizes.erase(it);
        for (int i = 0; i < m_corralSegCount; ++i) {
            if (addr >= m_corralSegBase[i] &&
                addr <  (LPVOID)((BYTE*)m_corralSegBase[i] + m_corralSegSize[i])) {
                owner = m_corralSegAlloc[i];
                break;
            }
        }
    }
    LeaveCriticalSection(&m_corralCS);
    if (size == 0 || !owner) return false;           // not a known slot base
    VirtualFree(addr, size, MEM_DECOMMIT);           // free committed RAM, keep the zone
    owner->Free(addr, size);                         // recycle the slot in its segment
    return true;
}

bool MemoryManager::IsCorralAddress(LPCVOID addr) const {
    if (!m_corralReady || !addr) return false;
    // Lock-free: the segment list is append-only and published count-last, so reading
    // up to the current count and range-checking each segment is safe on the hot path.
    const LONG n = m_corralSegCount;
    for (LONG i = 0; i < n; ++i) {
        if (addr >= m_corralSegBase[i] &&
            addr <  (LPCVOID)((const BYTE*)m_corralSegBase[i] + m_corralSegSize[i]))
            return true;
    }
    return false;
}

void MemoryManager::ReportCorralUsage() {
    if (!m_corralReady) return;
    Logger* log = Logger::GetInstance();
    if (!log) return;
    EnterCriticalSection(&m_corralCS);
    SIZE_T usedB = 0, rsvB = m_corralTotalReserved; LONG segs = m_corralSegCount;
    ULONGLONG slots = 0;
    for (int i = 0; i < m_corralSegCount; ++i) {
        ProxyAllocator::Stats st = m_corralSegAlloc[i]->GetStats();
        usedB += (SIZE_T)st.usedBytes;
        slots += st.activeAllocations;
    }
    LeaveCriticalSection(&m_corralCS);
    const SIZE_T usedMb = usedB / (1024 * 1024);
    const SIZE_T peakMb = (SIZE_T)(InterlockedCompareExchange64(&m_corralPeakBytes, 0, 0) / (1024 * 1024));
    const SIZE_T rsvMb  = rsvB / (1024 * 1024);
    const unsigned fillPct = rsvMb ? (unsigned)((peakMb * 100) / rsvMb) : 0;
    log->NamedInfo("SCRIPT_ARENA",
        "used=%zu MB  peak=%zu MB  reserved=%zu MB (%ld seg)  peak_fill=%u%%  slots=%llu%s",
        usedMb, peakMb, rsvMb, segs, fillPct, slots,
        (segs >= kMaxCorralSegs) ? "  -> at segment cap" :
        (rsvB >= m_corralMaxReserved) ? "  -> at VAS cap (overflow → OS)" : "");
}

SIZE_T MemoryManager::GetCorralUsedBytes() {
    if (!m_corralReady) return 0;
    EnterCriticalSection(&m_corralCS);
    SIZE_T usedB = 0;
    for (int i = 0; i < m_corralSegCount; ++i) {
        ProxyAllocator::Stats st = m_corralSegAlloc[i]->GetStats();
        usedB += (SIZE_T)st.usedBytes;
    }
    LeaveCriticalSection(&m_corralCS);
    return usedB;
}

// ── Address queries ───────────────────────────────────────────────────────────

bool   MemoryManager::IsProxyAddress(LPCVOID p)    { return m_proxyAllocator.IsProxyAddress(p); }
LPVOID MemoryManager::GetProxyArenaBase() const     { return m_proxyAllocator.GetBase(); }
SIZE_T MemoryManager::GetProxyArenaSize() const     { return m_proxyAllocator.GetSize(); }

// ── CallerIsSelf ──────────────────────────────────────────────────────────────
// True when the allocation originates inside TS3VASManager.dll itself (not the
// game).  Our own large STL allocations must NOT be captured: the proxy arena
// is lazy NOACCESS, so MSVCP140's _Allocate_manually_vector_aligned would fault
// on its first back-pointer write — and that fault re-enters our own VEH/hooks.
//
// The bottom of the stack is always our hook infrastructure (CallerIsSelf →
// CreateProxyAllocation → Hooked_*), which is in our module too.  So we skip
// that leading run of self-frames, and only report "self" if our module shows
// up AGAIN above the CRT frames — i.e. our code is the real originator.
static bool CallerIsSelf() {
    static ULONG_PTR s_base = 0;
    static ULONG_PTR s_end  = 0;
    if (s_base == 0) {
        HMODULE self = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(&CallerIsSelf), &self) && self) {
            MODULEINFO mi = {};
            if (GetModuleInformation(GetCurrentProcess(), self, &mi, sizeof(mi))) {
                s_end  = reinterpret_cast<ULONG_PTR>(mi.lpBaseOfDll) + mi.SizeOfImage;
                s_base = reinterpret_cast<ULONG_PTR>(mi.lpBaseOfDll);   // publish base last
            }
        }
    }
    if (s_base == 0) return false;   // module range unknown — fail open (allow proxy)

    void* frames[32] = {};
    const USHORT n = RtlCaptureStackBackTrace(0, 32, frames, nullptr);
    bool pastInfra = false;
    for (USHORT i = 0; i < n; ++i) {
        const ULONG_PTR a = reinterpret_cast<ULONG_PTR>(frames[i]);
        const bool isSelf = (a >= s_base && a < s_end);
        if (!pastInfra) {
            if (isSelf) continue;    // still in the bottom hook-infrastructure run
            pastInfra = true;        // reached the first non-self (CRT) frame
        }
        if (isSelf) return true;     // our module reappears above the CRT → our alloc
    }
    return false;
}

// ── CreateProxyAllocation ───────────────────────────────────────────────────
// Each slot is eager-committed at allocation (see the MEM_COMMIT note below), so
// the pointer handed back to the game is immediately usable — no lazy-fault path.

LPVOID MemoryManager::CreateProxyAllocation(SIZE_T size, DWORD protect,
                                                    ContainmentLane lane)
{
    // Never capture our own DLL's allocations — only the game's memory belongs
    // in the proxy arena (see CallerIsSelf).
    const bool tlsOk = ThreadHasTls();   // gate the thread_local on no-TLS threads
    if (tlsOk) t_lastCreateSelfSkip = false;
    if (CallerIsSelf()) {
        if (tlsOk) t_lastCreateSelfSkip = true;   // tell the caller this was an intentional skip
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("PROXY_Skipped_SelfAlloc");
        return nullptr;
    }

    // Over the proxy size cap (e.g. the rare >=4MB one-shot load allocs): keep it
    // local.  Intentional skip, not a capture failure (same flag the caller reads).
    if (m_proxyMaxBytes && size >= m_proxyMaxBytes) {
        if (tlsOk) t_lastCreateSelfSkip = true;
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("PROXY_Skipped_TooBig");
        return nullptr;
    }

    InitProxyCreateLogCfg();
    if (g_proxyCreateVerbose)
        EmergencyLogF("PROXY_Create", "Enter. size=%zu lane=%u", size, (unsigned)lane);
    ProxyBucket("PROXY_Alloc_Request", size);

    VASPressureMonitor* mon = VASPressureMonitor::GetInstance();
    const SIZE_T lowVasSkipBytesBase = ResolveLowVasSkipBytes();
    const SIZE_T lowVasSkipBytes = ResolveDynamicLowVasSkipBytes(lowVasSkipBytesBase);
    static LONG s_lowVasGateLogged = 0;
    if (InterlockedCompareExchange(&s_lowVasGateLogged, 1, 0) == 0 && Logger::GetInstance()) {
        Logger::GetInstance()->NamedInfo("VAS_REPORT",
            "Proxy reservation floor active: TS3VAS_LOWVAS_SKIP_MB(base)=%zu MB dynamic_now=%zu MB",
            lowVasSkipBytesBase / (1024ULL * 1024ULL),
            lowVasSkipBytes / (1024ULL * 1024ULL));
    }

    if (lowVasSkipBytes > 0 && mon && mon->GetAvailableVAS() < lowVasSkipBytes) {
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("PROXY_LowVAS_PressureSignal");
    }

    // 1. Carve VAS slice from the proxy arena
    LPVOID proxy_ptr = m_proxyAllocator.Allocate(size, m_proxyAllocator.PrefersTopDown(size));
    if (!proxy_ptr) {
        InterlockedIncrement64(&s_proxyCreateReqTotal);
        InterlockedAdd64(&s_proxyCreateBytesTotal, (LONG64)size);
        InterlockedIncrement64(&s_proxyCreateFailTotal);
        RecordAllocFailForLane(lane, "ProxyExhausted", size);
        MaybeLogProxyCreateTally();
        ProxyBucket("PROXY_Alloc_Failed", size);
        if (Analytics::GetInstance()) {
            Analytics::GetInstance()->IncrementCounter("PROXY_Allocations_Failed_Proxy");
            Analytics::GetInstance()->IncrementCounter("PROXY_Allocations_Failed_Bytes", size);
        }
        return nullptr;
    }

    // Guard against side-allocator fallback addresses. Proxy allocations must
    // always come from the reserved proxy arena.
    if (!m_proxyAllocator.IsProxyAddress(proxy_ptr)) {
        m_proxyAllocator.Free(proxy_ptr, size);
        InterlockedIncrement64(&s_proxyCreateReqTotal);
        InterlockedAdd64(&s_proxyCreateBytesTotal, (LONG64)size);
        InterlockedIncrement64(&s_proxyCreateFailTotal);
        RecordAllocFailForLane(lane, "NonProxySlot", size);
        MaybeLogProxyCreateTally();
        if (Analytics::GetInstance()) {
            Analytics::GetInstance()->IncrementCounter("PROXY_Allocations_Failed_NonProxySlot");
        }
        ProxyBucket("PROXY_Alloc_Failed", size);
        return nullptr;
    }

    // The proxy pointer must be page-aligned for MEM_COMMIT at a fixed address.
    // If we ever get a misaligned pointer, treat it as allocator failure.
    if (((SIZE_T)proxy_ptr & (m_pageSize - 1)) != 0) {
        if (g_proxyCreateVerbose)
            EmergencyLogF("PROXY_Create", "Rejecting misaligned proxy=%p page=%zu", proxy_ptr, m_pageSize);
        m_proxyAllocator.Free(proxy_ptr, size);
        InterlockedIncrement64(&s_proxyCreateReqTotal);
        InterlockedAdd64(&s_proxyCreateBytesTotal, (LONG64)size);
        InterlockedIncrement64(&s_proxyCreateFailTotal);
        RecordAllocFailForLane(lane, "MisalignedProxy", size);
        MaybeLogProxyCreateTally();
        if (Analytics::GetInstance()) {
            Analytics::GetInstance()->IncrementCounter("PROXY_Allocations_Failed_MisalignedProxy");
        }
        ProxyBucket("PROXY_Alloc_Failed", size);
        return nullptr;
    }

    // 2. Eager commit.  With no decommit/reclaim path, there is no reason to fault
    // pages in on demand — an uncommitted NOACCESS page would just crash on first
    // touch.  Commit the whole slot up front; the redirect's caller falls back to
    // Real on a null return.
    {
        DWORD commitProt = protect ? protect : PAGE_READWRITE;
        if (!VirtualAlloc(proxy_ptr, size, MEM_COMMIT, commitProt)) {
            DWORD gle = GetLastError();
            EmergencyLogF("PROXY_Create", "EAGER_COMMIT_FAIL proxy=%p size=%zu prot=0x%X GLE=%lu",
                          proxy_ptr, size, commitProt, gle);
            m_proxyAllocator.Free(proxy_ptr, size);
            InterlockedIncrement64(&s_proxyCreateReqTotal);
            InterlockedAdd64(&s_proxyCreateBytesTotal, (LONG64)size);
            InterlockedIncrement64(&s_proxyCreateFailTotal);
            RecordAllocFailForLane(lane, "EagerCommitFail", size);
            MaybeLogProxyCreateTally();
            if (Analytics::GetInstance())
                Analytics::GetInstance()->IncrementCounter("PROXY_Allocations_Failed_EagerCommit");
            ProxyBucket("PROXY_Alloc_Failed", size);
            return nullptr;
        }
    }

    // 3. Store lightweight record.
    ProxyAllocRecord record;
    record.proxy_base  = proxy_ptr;
    record.proxy_size  = size;
    record.protection  = protect;
    record.lane        = lane;
    record.alloc_tick  = GetTickCount();

    EnterCriticalSection(&m_mapCS);
    m_allocations[proxy_ptr] = record;
    LeaveCriticalSection(&m_mapCS);

    if (Analytics::GetInstance()) {
        const bool excludedLane = (lane == ContainmentLane::LANE_EXCLUDED_A ||
                                   lane == ContainmentLane::LANE_EXCLUDED_B ||
                                   lane == ContainmentLane::LANE_EXCLUDED_C ||
                                   lane == ContainmentLane::LANE_EXCLUDED_D);
        const char* tag = excludedLane ? "Excluded" : "Contained";
        char ctr[64];
        sprintf_s(ctr, "PROXY_Alloc_%s_Count", tag);
        Analytics::GetInstance()->IncrementCounter(ctr);
        sprintf_s(ctr, "PROXY_Alloc_%s_Bytes", tag);
        Analytics::GetInstance()->IncrementCounter(ctr, size);
        Analytics::GetInstance()->IncrementCounter("PROXY_Allocations_Local_Count");
        Analytics::GetInstance()->IncrementCounter("PROXY_Allocations_Local", size);
    }
    // Proxy-redirect size histogram (ALLOC_SIZE_DIST channel): the requested size
    // of everything we actually pulled into the arena, banded like the alloc dist.
    RecordProxyBandPair("ProxySize", "ProxyBytes", size);
    ProxyBucket("PROXY_Alloc_Succeeded", size);
    InterlockedIncrement64(&s_proxyCreateReqTotal);
    InterlockedAdd64(&s_proxyCreateBytesTotal, (LONG64)size);
    InterlockedIncrement64(&s_proxyCreateOkTotal);
    RecordAllocSuccessStreakReset();
    MaybeLogProxyCreateTally();
    TS3VASEtw::EmitProxySlotAssigned((UINT32)(ULONG_PTR)proxy_ptr, (UINT32)size,
                                     (UINT8)(unsigned)lane, protect);
    if (g_proxyCreateVerbose)
        EmergencyLogF("PROXY_Create", "Exit. proxy=%p", proxy_ptr);
    return proxy_ptr;
}

// ── FreeProxyAllocation ─────────────────────────────────────────────────────

bool MemoryManager::FreeProxyAllocation(LPVOID proxy_ptr) {
    if (!IsProxyAddress(proxy_ptr)) return false;

    ProxyAllocRecord record;
    bool found = false;

    EnterCriticalSection(&m_mapCS);
    auto it = m_allocations.find(proxy_ptr);
    if (it != m_allocations.end()) {
        record = it->second;
        found  = true;
        m_allocations.erase(it);
    }
    LeaveCriticalSection(&m_mapCS);

    if (found) {
        // Decommit the slot's pages back to the NOACCESS arena reservation so the
        // slice is clean (and recommits fresh) when the allocator hands it out again.
        VirtualFree(record.proxy_base, record.proxy_size, MEM_DECOMMIT);

        m_proxyAllocator.Free(proxy_ptr, record.proxy_size);
        // Proxy-free size histogram (ALLOC_SIZE_DIST channel): the slot size we just
        // released back to the arena, banded like the proxy-redirect dist so alloc
        // vs free pressure per band is directly comparable.
        RecordProxyBandPair("FreeSize", "FreeBytes", record.proxy_size);
        TS3VASEtw::EmitProxySlotReleased((UINT32)(ULONG_PTR)proxy_ptr,
                                         (UINT32)record.proxy_size);
        return true;
    }
    return false;
}

// ── FindRecordByAddress ───────────────────────────────────────────────────────

bool MemoryManager::FindRecordByAddress(LPCVOID address,
                                               ProxyAllocRecord* out_rec)
{
    if (!out_rec) return false;
    EnterCriticalSection(&m_mapCS);
    for (auto& [base, record] : m_allocations) {
        if (address >= base &&
            address < static_cast<LPBYTE>(base) + record.proxy_size) {
            *out_rec = record;
            LeaveCriticalSection(&m_mapCS);
            return true;
        }
    }
    LeaveCriticalSection(&m_mapCS);
    return false;
}

// ── GetStats / ReportStats ────────────────────────────────────────────────────

MemoryManager::Stats MemoryManager::GetStats() {
    Stats s = {};
    ProxyAllocator::Stats pa = m_proxyAllocator.GetStats();
    s.proxyArenaSize          = pa.arenaSize;
    s.proxyUsedBytes          = pa.usedBytes;
    s.proxyFreeBytes          = pa.freeBytes;
    s.proxyLargestFreeSpan    = pa.largestFreeSpan;
    s.activeAllocations       = pa.activeAllocations;
    s.totalAllocationRequests = pa.totalAllocationRequests;
    s.totalAllocationFailures = pa.totalAllocationFailures;
    s.totalGrantedBytes       = pa.totalGrantedBytes;
    s.totalFreedBytes         = pa.totalFreedBytes;
    s.totalReusedBytes        = pa.totalReusedBytes;
    return s;
}

void MemoryManager::ReportStats(const char* logName) {
    Logger* log = Logger::GetInstance();
    if (!log) return;
    Stats s = GetStats();
    log->NamedInfo(logName,
        "Proxy arena: used=%zu MB free=%zu MB largest_free=%zu MB arena=%zu MB active=%llu gran=%luKB",
        s.proxyUsedBytes / (1024*1024), s.proxyFreeBytes / (1024*1024),
        s.proxyLargestFreeSpan / (1024*1024), s.proxyArenaSize / (1024*1024),
        s.activeAllocations, (unsigned long)(m_proxyAllocator.GetGranularity() / 1024));
    // Per-granularity packing loss for the data that lands in the 1GB arena — the arena
    // analogue of the sardine's PROXY_HEAP loss probe.  Cumulative requested vs granted
    // slot per size band; loss% is the address space the 64KB granularity wall taxes, so
    // a high band = that size could be packed tighter.  Empty bands skipped, like sardine.
    {
        ProxyAllocator::Stats pa2 = m_proxyAllocator.GetStats();
        static const char* const kBandLbl[8] = {
            "0-4KB", "4-64KB", "64-256KB", "256-512KB", "512KB-1MB", "1-4MB", "4-16MB", "16MB+" };
        const ULONGLONG MB = 1024ULL * 1024ULL;
        for (int b = 0; b < 8; ++b) {
            const ULONGLONG actB = pa2.bandSlotBytes[b];
            if (actB == 0) continue;
            const ULONGLONG rqB  = pa2.bandReqBytes[b];
            const ULONGLONG lost = (actB > rqB) ? (actB - rqB) : 0;
            log->NamedInfo(logName,
                "  loss %-10s req=%llu MB act=%llu MB loss=%.1f%%",
                kBandLbl[b], rqB / MB, actB / MB, (double)lost * 100.0 / (double)actB);
        }
    }
    // Size-class reuse: how much address space is parked in per-size caches and how
    // much of all granted bytes came from same-size reuse (high = 40MB→40MB working).
    ProxyAllocator::Stats pa = m_proxyAllocator.GetStats();
    log->NamedInfo(logName,
        "Size-class reuse: cached=%llu MB reused=%llu MB of granted=%llu MB (reuse_rate=%u%%)",
        (unsigned long long)(pa.classCachedBytes / (1024*1024)),
        (unsigned long long)(pa.totalReusedBytes / (1024*1024)),
        (unsigned long long)(pa.totalGrantedBytes / (1024*1024)),
        pa.totalGrantedBytes ? (unsigned)((pa.totalReusedBytes * 100) / pa.totalGrantedBytes) : 0);
}
