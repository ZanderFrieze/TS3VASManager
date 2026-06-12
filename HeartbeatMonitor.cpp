#include "HeartbeatMonitor.h"
#include "Logger.h"
#include "Analytics.h"
#include "VASPressureMonitor.h"
#include "WorkingHooks.h"
#include "MemoryManager.h"
#include "ProxyGc.h"
#include "EmergencyLogger.h"
#include <atomic>
#include <cstdlib>
#include <cstring>
// PSAPI_VERSION=1 keeps the plain symbol names (no K32* macro remap), which would
// otherwise rewrite the existing HeartbeatMonitor::GetProcessMemoryInfo member.
#define PSAPI_VERSION 1
#include <psapi.h>   // GetMappedFileNameA — names file-backed/image regions
#pragma comment(lib, "psapi.lib")

// Defined in WorkingHooks.cpp — dumps all still-tracked large local VirtualAlloc
// reserves to the dedicated UNFREED_ASSETS log channel at world-exit time.
extern void DumpUnfreedAssets();
extern void DumpHeapUsage();   // per-heap large-alloc attribution (WorkingHooks.cpp)

// One 8-band size label set, shared by every distribution below so the rows line up
// when read together in the log.
static const char* kSizeBandLbl[8] = {
    "0-4KB", "4-64KB", "64-256KB", "256-512KB", "512KB-1MB", "1-4MB", "4-16MB", "16MB+" };

// Unified distribution printer.  Reads the 8 band counters in ctr[], sums them, and
// logs each band's share to `channel`.  asBytes => the counters hold byte totals
// (header and rows render in MB); otherwise they're raw counts.  In count mode an
// optional byteCtr[] adds a total-MB figure to the header.  Returns silently when the
// counters are all zero (feature inactive this session).
static void PrintSizeDistribution(const char* channel, const char* title,
                                  const char* const ctr[8], bool asBytes,
                                  const char* const byteCtr[8] = nullptr) {
    Analytics* a   = Analytics::GetInstance();
    Logger*    log = Logger::GetInstance();
    if (!a || !log) return;
    const uint64_t MB = 1024ULL * 1024ULL;
    uint64_t val[8]; uint64_t total = 0, extraBytes = 0;
    for (int i = 0; i < 8; ++i) {
        val[i] = a->GetCounterValue(ctr[i]);
        total += val[i];
        if (!asBytes && byteCtr) extraBytes += a->GetCounterValue(byteCtr[i]);
    }
    if (total == 0) return;

    if (asBytes)
        log->NamedInfo(channel, "=== %s (%llu MB total) ===", title,
                       (unsigned long long)(total / MB));
    else if (byteCtr)
        log->NamedInfo(channel, "=== %s (%llu allocs, %llu MB) ===", title,
                       (unsigned long long)total, (unsigned long long)(extraBytes / MB));
    else
        log->NamedInfo(channel, "=== %s (%llu allocs) ===", title,
                       (unsigned long long)total);

    for (int i = 0; i < 8; ++i) {
        double pct = (double)val[i] * 100.0 / (double)total;
        if (asBytes)
            log->NamedInfo(channel, "  %-10s %5.1f%%  (%llu MB)",
                           kSizeBandLbl[i], pct, (unsigned long long)(val[i] / MB));
        else
            log->NamedInfo(channel, "  %-10s %5.1f%%  (%llu)",
                           kSizeBandLbl[i], pct, (unsigned long long)val[i]);
    }
}

// What sizes the game allocates (count view, dominated by tiny churn) and where the
// address space actually goes (byte view) — the byte view sizes the corral / cache.
static void ReportAllocSizeDistribution() {
    static const char* kCnt[8] = {
        "AllocSize_0to4KB", "AllocSize_4to64KB", "AllocSize_64to256KB",
        "AllocSize_256to512KB", "AllocSize_512KBto1MB", "AllocSize_1to4MB",
        "AllocSize_4to16MB", "AllocSize_16MBplus" };
    PrintSizeDistribution("ALLOC_SIZE_DIST", "block-size distribution", kCnt, false);
}
static void ReportAllocBytesDistribution() {
    static const char* kCnt[8] = {
        "AllocBytes_0to4KB", "AllocBytes_4to64KB", "AllocBytes_64to256KB",
        "AllocBytes_256to512KB", "AllocBytes_512KBto1MB", "AllocBytes_1to4MB",
        "AllocBytes_4to16MB", "AllocBytes_16MBplus" };
    PrintSizeDistribution("ALLOC_BYTES_DIST", "block-size distribution by BYTES", kCnt, true);
}

// What sizes we actually redirect into the proxy arena (CreateProxyAllocation grants
// — corral + threshold capture), and what sizes get freed back (FreeProxyAllocation).
// Compared band-for-band the pair shows churn vs. retention per size.
static void ReportProxySizeDistribution() {
    static const char* kCnt[8] = {
        "ProxySize_0to4KB", "ProxySize_4to64KB", "ProxySize_64to256KB",
        "ProxySize_256to512KB", "ProxySize_512KBto1MB", "ProxySize_1to4MB",
        "ProxySize_4to16MB", "ProxySize_16MBplus" };
    static const char* kByte[8] = {
        "ProxyBytes_0to4KB", "ProxyBytes_4to64KB", "ProxyBytes_64to256KB",
        "ProxyBytes_256to512KB", "ProxyBytes_512KBto1MB", "ProxyBytes_1to4MB",
        "ProxyBytes_4to16MB", "ProxyBytes_16MBplus" };
    PrintSizeDistribution("ALLOC_SIZE_DIST", "proxy redirect size distribution", kCnt, false, kByte);
}
static void ReportProxyFreeSizeDistribution() {
    static const char* kCnt[8] = {
        "FreeSize_0to4KB", "FreeSize_4to64KB", "FreeSize_64to256KB",
        "FreeSize_256to512KB", "FreeSize_512KBto1MB", "FreeSize_1to4MB",
        "FreeSize_4to16MB", "FreeSize_16MBplus" };
    static const char* kByte[8] = {
        "FreeBytes_0to4KB", "FreeBytes_4to64KB", "FreeBytes_64to256KB",
        "FreeBytes_256to512KB", "FreeBytes_512KBto1MB", "FreeBytes_1to4MB",
        "FreeBytes_4to16MB", "FreeBytes_16MBplus" };
    PrintSizeDistribution("ALLOC_SIZE_DIST", "proxy free size distribution", kCnt, false, kByte);
}
// Disposition of >=64KB RtlAllocateHeap allocs, in the SAME population as the block-size
// dist (so per band: captured + missed + self == block-size dist).  Captured = pulled
// into the proxy.  Missed = a game alloc we failed to take (the real leak).  Self = our
// own DLL's CRT allocations (CallerIsSelf, correctly kept local).  Only >=64KB bands are
// populated; the 0-4KB/4-64KB rows are the sardine's domain and stay 0 here.
static void ReportHeapLocalDistribution() {
    static const char* kCaptured[8] = {
        "HeapBandCaptured_0to4KB", "HeapBandCaptured_4to64KB", "HeapBandCaptured_64to256KB",
        "HeapBandCaptured_256to512KB", "HeapBandCaptured_512KBto1MB", "HeapBandCaptured_1to4MB",
        "HeapBandCaptured_4to16MB", "HeapBandCaptured_16MBplus" };
    PrintSizeDistribution("ALLOC_SIZE_DIST", "heap >=64KB CAPTURED into proxy", kCaptured, false);
    static const char* kMissed[8] = {
        "HeapBandMissed_0to4KB", "HeapBandMissed_4to64KB", "HeapBandMissed_64to256KB",
        "HeapBandMissed_256to512KB", "HeapBandMissed_512KBto1MB", "HeapBandMissed_1to4MB",
        "HeapBandMissed_4to16MB", "HeapBandMissed_16MBplus" };
    PrintSizeDistribution("ALLOC_SIZE_DIST", "heap >=64KB MISSED (-> local, real leak)", kMissed, false);
    static const char* kSelf[8] = {
        "HeapBandSelf_0to4KB", "HeapBandSelf_4to64KB", "HeapBandSelf_64to256KB",
        "HeapBandSelf_256to512KB", "HeapBandSelf_512KBto1MB", "HeapBandSelf_1to4MB",
        "HeapBandSelf_4to16MB", "HeapBandSelf_16MBplus" };
    PrintSizeDistribution("ALLOC_SIZE_DIST", "heap >=64KB local: our own DLL (self-skip, correct)", kSelf, false);
}

static std::atomic<SIZE_T> s_latestLargestFreeBytes{0};
static std::atomic<SIZE_T> s_latestTotalFreeBytes{0};
static std::atomic<ULONGLONG> s_latestVasSampleTickMs{0};

SIZE_T HeartbeatMonitor::GetLatestLargestFreeBytes() {
    return s_latestLargestFreeBytes.load(std::memory_order_relaxed);
}

SIZE_T HeartbeatMonitor::GetLatestTotalFreeBytes() {
    return s_latestTotalFreeBytes.load(std::memory_order_relaxed);
}

ULONGLONG HeartbeatMonitor::GetLatestSampleTickMs() {
    return s_latestVasSampleTickMs.load(std::memory_order_relaxed);
}

HeartbeatMonitor::HeartbeatMonitor(MemoryManager* memManager)
    : m_memManager(memManager),
      m_threadHandle(nullptr), m_wakeEvent(nullptr), m_stopFlag(0) {
    m_wakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL); // auto-reset
    EmergencyLog("HeartbeatMonitor", "Constructor called");
}

HeartbeatMonitor::~HeartbeatMonitor() {
    EmergencyLog("HeartbeatMonitor", "Destructor called");
    Stop();
}

void HeartbeatMonitor::Start() {
    EmergencyLog("HeartbeatMonitor", "Start() called");
    
    if (m_threadHandle) {
        EmergencyLog("HeartbeatMonitor", "Thread already running");
        return;
    }
    
    m_stopFlag = 0;
    
    EmergencyLog("HeartbeatMonitor", "Creating heartbeat thread");
    m_threadHandle = CreateThread(NULL, 0, HeartbeatThreadFunc, this, 0, NULL);
    
    if (m_threadHandle) {
        Logger::GetInstance()->Info("Heartbeat monitor thread started.");
        EmergencyLogF("HeartbeatMonitor", "Thread created successfully, handle: 0x%p", m_threadHandle);
    } else {
        DWORD error = GetLastError();
        Logger::GetInstance()->Error("Failed to create heartbeat monitor thread. Error: %lu", error);
        EmergencyLogF("HeartbeatMonitor", "Thread creation FAILED, error: %lu", error);
    }
}

void HeartbeatMonitor::Stop() {
    EmergencyLog("HeartbeatMonitor", "Stop() called");
    if (!m_threadHandle) return;

    InterlockedExchange(&m_stopFlag, 1);
    // Wake the thread immediately so it sees m_stopFlag without waiting
    // for the full sleep interval.  Previously Stop() used a 2000ms timeout
    // which is shorter than the 5000ms steady-state sleep — the thread
    // kept running past the destructor.
    if (m_wakeEvent) SetEvent(m_wakeEvent);

    Logger::GetInstance()->Info("Waiting for heartbeat thread to terminate...");
    // 6000ms > 5000ms steady-state sleep — safe even if the signal is missed
    WaitForSingleObject(m_threadHandle, 6000);
    CloseHandle(m_threadHandle);
    m_threadHandle = nullptr;

    if (m_wakeEvent) { CloseHandle(m_wakeEvent); m_wakeEvent = nullptr; }
    Logger::GetInstance()->Info("Heartbeat thread terminated.");
    EmergencyLog("HeartbeatMonitor", "Thread stopped");
}

void HeartbeatMonitor::GetProcessMemoryInfo(SIZE_T& availableVAS, SIZE_T& largestFreeBlock) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    SIZE_T totalFree = 0;
    SIZE_T largestFree = 0;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_FREE) {
            totalFree += mbi.RegionSize;
            if (mbi.RegionSize > largestFree)
                largestFree = mbi.RegionSize;
        }
        LPVOID nextAddr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddr <= addr) break;
        addr = nextAddr;
    }
    availableVAS = totalFree;
    largestFreeBlock = largestFree;
}

// ── Phase snapshot ────────────────────────────────────────────────────────────
// Bundles VAS state + alloc counters captured at a single moment.

struct VasPhaseSnapshot {
    // VAS
    DWORD totalFreeMb;
    DWORD largestFreeMb;
    DWORD freeRegions;
    DWORD freeBucket[6];     // <1, 1-4, 4-16, 16-64, 64-256, 256+ MB
    DWORD commitPrivateMb;
    DWORD commitImageMb;
    DWORD commitMappedMb;
    DWORD reserveMb;
    DWORD reservePrivateMb;  // anonymous reserves (our arena + game heap segments/reserves)
    DWORD reserveMappedMb;   // file-section reserves (.package streaming — NOT arena-capturable)
    // Alloc
    RtlAllocSnapshot alloc;
    // Beat/time
    DWORD beat;
    ULONGLONG tickMs;
};

static void CaptureVasPhaseSnapshot(VasPhaseSnapshot& out, DWORD beat) {
    out.beat   = beat;
    out.tickMs = GetTickCount64();
    out.freeRegions     = 0;
    out.totalFreeMb     = 0;
    out.largestFreeMb   = 0;
    out.commitPrivateMb = 0;
    out.commitImageMb   = 0;
    out.commitMappedMb  = 0;
    out.reserveMb       = 0;
    out.reservePrivateMb = 0;
    out.reserveMappedMb  = 0;
    memset(out.freeBucket, 0, sizeof(out.freeBucket));

    LPVOID addr = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        DWORD mb = (DWORD)(mbi.RegionSize / (1024 * 1024));
        if (mbi.State == MEM_FREE) {
            out.freeRegions++;
            out.totalFreeMb += mb;
            if (mb > out.largestFreeMb) out.largestFreeMb = mb;
            if      (mb <   1) out.freeBucket[0]++;
            else if (mb <   4) out.freeBucket[1]++;
            else if (mb <  16) out.freeBucket[2]++;
            else if (mb <  64) out.freeBucket[3]++;
            else if (mb < 256) out.freeBucket[4]++;
            else               out.freeBucket[5]++;
        } else if (mbi.State == MEM_COMMIT) {
            if      (mbi.Type == MEM_PRIVATE) out.commitPrivateMb += mb;
            else if (mbi.Type == MEM_IMAGE)   out.commitImageMb   += mb;
            else                              out.commitMappedMb  += mb;
        } else if (mbi.State == MEM_RESERVE) {
            out.reserveMb += mb;
            if      (mbi.Type == MEM_MAPPED) out.reserveMappedMb  += mb;   // file sections
            else                             out.reservePrivateMb += mb;   // anonymous (incl. our arena)
        }
        LPVOID next = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    WorkingHooks::CaptureAllocSnapshot(out.alloc);
}

static const char* const kModuleNames[6] = {
    "game", "graphics", "runtime", "system", "mod", "unknown"
};

void HeartbeatMonitor::LogVasSnapshot(const char* label) {
    VasPhaseSnapshot s = {};
    CaptureVasPhaseSnapshot(s, 0);

    Logger* log = Logger::GetInstance();
    if (!log) return;

    DWORD fragScore = (s.totalFreeMb > 0)
        ? (DWORD)((ULONGLONG)s.largestFreeMb * 100 / s.totalFreeMb) : 0;

    log->NamedInfo("VAS_SNAPSHOT",
        "[%s] total_free=%lu MB largest_free=%lu MB frag_score=%lu/100 free_regions=%lu",
        label, s.totalFreeMb, s.largestFreeMb, fragScore, s.freeRegions);
    log->NamedInfo("VAS_SNAPSHOT",
        "[%s] commit: private=%lu MB image=%lu MB mapped=%lu MB | reserve=%lu MB",
        label, s.commitPrivateMb, s.commitImageMb, s.commitMappedMb, s.reserveMb);
    // Footprint by type (commit+reserve) — separates what the arena CAN host (anonymous
    // private) from what it can't (file-section mappings = .package streaming, and images).
    // A steep largest_free decline driven by 'mapped' is uncaptured-by-design, not a leak
    // in our capture path.
    log->NamedInfo("VAS_SNAPSHOT",
        "[%s] footprint: private=%lu MB mapped=%lu MB image=%lu MB (mapped is file-backed, not arena-capturable)",
        label, s.commitPrivateMb + s.reservePrivateMb,
        s.commitMappedMb + s.reserveMappedMb, s.commitImageMb);
    log->NamedInfo("VAS_SNAPSHOT",
        "[%s] free_histogram: <1MB=%lu  1-4MB=%lu  4-16MB=%lu  16-64MB=%lu  64-256MB=%lu  256+MB=%lu",
        label, s.freeBucket[0], s.freeBucket[1], s.freeBucket[2],
               s.freeBucket[3], s.freeBucket[4], s.freeBucket[5]);
}

// ── CPU table (observe-only) ────────────────────────────────────────────────
// There is no single CPU "vtable" to hook the way the D3D9 device exposes one —
// the Mono script runtime is static inside TS3W.exe and the engine allocators are
// not COM objects.  So CPU-side visibility comes from a live VAS-region scan plus
// the allocation counters we already keep.  The point is to surface what we're
// MISSING: committed-private memory that is NOT inside the proxy arena is local
// (un-captured) — the Mono/script heaps and engine pools appear here as concrete
// address+size blocks.  Gated by TS3VAS_CPU_TABLE=1; default off so it never runs
// during normal play.
static bool ObserveTablesEnabled() {
    static volatile LONG s_init = 0;
    static volatile LONG s_on   = 0;
    if (InterlockedCompareExchange(&s_init, 1, 0) == 0) {
        char v[8] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_OBSERVE", v, (DWORD)sizeof(v));
        // Default ON in this telemetry build; set TS3VAS_OBSERVE=0 to silence.
        LONG on = 1;
        if (n > 0 && (v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F'))
            on = 0;
        InterlockedExchange(&s_on, on);
    }
    return InterlockedCompareExchange(&s_on, 0, 0) != 0;
}

static void LogObserveTables(MemoryManager* mm) {
    Logger* log = Logger::GetInstance();
    if (!log) return;

    ULONG_PTR proxyBase = 0, proxyEnd = 0;
    if (mm) {
        proxyBase = (ULONG_PTR)mm->GetProxyArenaBase();
        proxyEnd  = proxyBase + (ULONG_PTR)mm->GetProxyArenaSize();
    }

    const int kTopN = 8;
    struct Reg { ULONG_PTR base; SIZE_T size; };
    Reg top[kTopN]   = {};   // largest LOCAL private regions (un-captured)
    Reg named[kTopN] = {};   // largest file-backed (image/mapped) regions, named below
    SIZE_T proxyCommitted = 0, localCommitted = 0, localRegions = 0;
    SIZE_T mappedCommitted = 0, imageCommitted = 0;
    SIZE_T band[4] = {};  // local private regions: <1MB, 1-16MB, 16-64MB, 64MB+

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = nullptr;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        ULONG_PTR rb = (ULONG_PTR)mbi.BaseAddress;
        SIZE_T    rs = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            if (proxyEnd > proxyBase && rb >= proxyBase && rb < proxyEnd) {
                proxyCommitted += rs;
            } else {
                localCommitted += rs;
                localRegions++;
                SIZE_T mb = rs / (1024 * 1024);
                if      (mb < 1)  band[0]++;
                else if (mb < 16) band[1]++;
                else if (mb < 64) band[2]++;
                else              band[3]++;
                for (int i = 0; i < kTopN; ++i) {
                    if (rs > top[i].size) {
                        for (int j = kTopN - 1; j > i; --j) top[j] = top[j - 1];
                        top[i].base = rb; top[i].size = rs;
                        break;
                    }
                }
            }
        } else if (mbi.State == MEM_COMMIT &&
                   (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)) {
            // File-backed (DLLs, mapped .package files) — nameable via the file path.
            if (mbi.Type == MEM_IMAGE) imageCommitted += rs; else mappedCommitted += rs;
            for (int i = 0; i < kTopN; ++i) {
                if (rs > named[i].size) {
                    for (int j = kTopN - 1; j > i; --j) named[j] = named[j - 1];
                    named[i].base = rb; named[i].size = rs;
                    break;
                }
            }
        }
        LPVOID next = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    Analytics* a = Analytics::GetInstance();
    auto C = [&](const char* k) -> unsigned long long {
        return a ? (unsigned long long)a->GetCounterValue(k) : 0ULL;
    };
    const unsigned long long MB = 1024ULL * 1024ULL;

    log->NamedInfo("CPU_TABLE",
        "proxy_arena=[0x%08IX..0x%08IX] %llu MB | committed_private: in_proxy=%llu MB  local=%llu MB (%llu regions)",
        proxyBase, proxyEnd, (unsigned long long)((proxyEnd - proxyBase) / MB),
        (unsigned long long)(proxyCommitted / MB), (unsigned long long)(localCommitted / MB),
        (unsigned long long)localRegions);
    log->NamedInfo("CPU_TABLE",
        "local size bands: <1MB=%llu  1-16MB=%llu  16-64MB=%llu  64MB+=%llu  (these are NOT captured)",
        (unsigned long long)band[0], (unsigned long long)band[1],
        (unsigned long long)band[2], (unsigned long long)band[3]);
    for (int i = 0; i < kTopN && top[i].size > 0; ++i) {
        log->NamedInfo("CPU_TABLE", "  local_region[%d] base=0x%08IX size=%llu MB  (candidate: Mono/script heap or missed pool)",
            i, top[i].base, (unsigned long long)(top[i].size / MB));
    }
    // Named file-backed regions (DLLs + mapped .package files) — "names for what's resident".
    log->NamedInfo("CPU_TABLE", "file-backed committed: image(DLLs)=%llu MB  mapped(packages/files)=%llu MB",
        (unsigned long long)(imageCommitted / MB), (unsigned long long)(mappedCommitted / MB));
    for (int i = 0; i < kTopN && named[i].size > 0; ++i) {
        char dev[MAX_PATH * 2] = {};
        const char* nm = "<anonymous>";
        if (GetMappedFileNameA(GetCurrentProcess(), (LPVOID)named[i].base, dev, (DWORD)sizeof(dev)) && dev[0]) {
            const char* slash = strrchr(dev, '\\');
            nm = slash ? slash + 1 : dev;
        }
        log->NamedInfo("CPU_TABLE", "  named_region[%d] %-32s base=0x%08IX size=%llu MB",
            i, nm, named[i].base, (unsigned long long)(named[i].size / MB));
    }
    log->NamedInfo("CPU_TABLE",
        "coverage: VA_redirected=%llu MB | VA_NOT_redirected=%llu MB (commit_only=%llu MB) | heap_captured=%llu MB / %llu allocs",
        C("VirtualAlloc_RedirectedBytes") / MB,
        C("VirtualAlloc_NotRedirected_Bytes") / MB,
        C("VirtualAlloc_NotRedirected_CommitOnlyBytes") / MB,
        C("RtlAllocHeap_Captureed") / MB, C("RtlAllocHeap_CaptureCount"));
    log->NamedInfo("CPU_TABLE",
        "scripts: packages=%llu script_resources=%llu xml/tuning_resources=%llu | heap_by_module_count: game=%llu runtime=%llu system=%llu mod=%llu",
        C("Script_Packages"), C("Script_Resources"), C("Script_Xml_Resources"),
        C("RtlAlloc_ByModule_TS3W"), C("RtlAlloc_ByModule_RuntimeDll"),
        C("RtlAlloc_ByModule_SystemDll"), C("RtlAlloc_ByModule_Mod"));

    // ── GPU table — from the D3D9 resource-creation hooks' counters ───────────
    // (zero unless the D3D9 hook installed; shares the OBSERVE file with the CPU
    // table via the logger's channel routing).
    log->NamedInfo("GPU_TABLE",
        "lanes: contained(Managed/SystemMem textures)=%llu MB / %llu res | excluded(Default + dynamic buffers)=%llu MB / %llu res",
        C("D3D9_Contained_Bytes") / MB, C("D3D9_Contained_Count"),
        C("D3D9_Excluded_Bytes") / MB, C("D3D9_Excluded_Count"));
    log->NamedInfo("GPU_TABLE",
        "textures by pool MB: managed=%llu systemmem=%llu default=%llu | buffers MB: vb(managed+default)=%llu ib(managed+default)=%llu",
        C("D3D9_Texture_Managed_Bytes") / MB, C("D3D9_Texture_SystemMem_Bytes") / MB,
        C("D3D9_Texture_Default_Bytes") / MB,
        (C("D3D9_VertexBuf_Managed_Bytes") + C("D3D9_VertexBuf_Default_Bytes")) / MB,
        (C("D3D9_IndexBuf_Managed_Bytes") + C("D3D9_IndexBuf_Default_Bytes")) / MB);
    // Write-watch reserves split by caller class.  Graphics-driver reserves go in
    // the 164 MB corral (the d3d9 pipeline budget).  Script/JIT reserves (TS3W.exe —
    // Sims 3's script bloat) are kept out of that budget and fall to local; their
    // per-callsite TS3W.exe+offset pointers are in VAS_COMBINED (SCRIPT_VAS lines).
    log->NamedInfo("GPU_TABLE",
        "writewatch GFX-driver (corralled): count=%llu total=%llu MB | sizes: <256K=%llu 256K=%llu 256K-1M=%llu 1-16M=%llu >16M=%llu",
        C("GfxDriverWW_Count"), C("GfxDriverWW_Bytes") / MB,
        C("GfxDriverWW_Lt256K"), C("GfxDriverWW_256K"),
        C("GfxDriverWW_256Kto1M"), C("GfxDriverWW_1Mto16M"), C("GfxDriverWW_Gt16M"));
    log->NamedInfo("GPU_TABLE",
        "writewatch SCRIPT (local, TS3W.exe): count=%llu total=%llu MB | sizes: <256K=%llu 256K=%llu 256K-1M=%llu 1-16M=%llu >16M=%llu",
        C("ScriptWW_Count"), C("ScriptWW_Bytes") / MB,
        C("ScriptWW_Lt256K"), C("ScriptWW_256K"),
        C("ScriptWW_256Kto1M"), C("ScriptWW_1Mto16M"), C("ScriptWW_Gt16M"));
}

// ── Leak-hunter snapshot ──────────────────────────────────────────────────────
// Captures live proxy state alongside the standard VAS/alloc counters.
// Used to diff allocation activity across a full world session.
struct LeakHunterSnapshot {
    DWORD      beat;
    ULONGLONG  tickMs;
    DWORD      totalFreeMb;
    DWORD      largestFreeMb;
    ULONGLONG  proxyUsedBytes;      // live bytes in proxy arena
    DWORD      proxyActiveAllocs;   // live allocation count in proxy arena
    uint64_t   mapViewPackageCount; // cumulative MapView_Package counter
    RtlAllocSnapshot alloc;         // cumulative alloc counters for per-module diff
};

static void CaptureLeakHunterSnapshot(LeakHunterSnapshot& out, DWORD beat,
    DWORD totalFreeMb, DWORD largestFreeMb,
    ULONGLONG proxyUsedBytes, DWORD proxyActiveAllocs)
{
    out.beat               = beat;
    out.tickMs             = GetTickCount64();
    out.totalFreeMb        = totalFreeMb;
    out.largestFreeMb      = largestFreeMb;
    out.proxyUsedBytes     = proxyUsedBytes;
    out.proxyActiveAllocs  = proxyActiveAllocs;
    out.mapViewPackageCount = Analytics::GetInstance()
        ? Analytics::GetInstance()->GetCounterValue("MapView_Package") : 0;
    WorkingHooks::CaptureAllocSnapshot(out.alloc);
}

static void LogLeakHunterDiff(const char* label,
    const LeakHunterSnapshot& entry, const LeakHunterSnapshot& now)
{
    Logger* log = Logger::GetInstance();
    if (!log) return;

    const DWORD     sessionBeats = now.beat  - entry.beat;
    const ULONGLONG sessionMs    = now.tickMs - entry.tickMs;
    const int       vasDelta     = (int)now.totalFreeMb    - (int)entry.totalFreeMb;
    const int       lfDelta      = (int)now.largestFreeMb  - (int)entry.largestFreeMb;
    const LONGLONG  proxyBytesDelta  = (LONGLONG)now.proxyUsedBytes    - (LONGLONG)entry.proxyUsedBytes;
    const int       proxyAllocsDelta = (int)now.proxyActiveAllocs - (int)entry.proxyActiveAllocs;
    const uint64_t  pkgMapsDelta     = now.mapViewPackageCount - entry.mapViewPackageCount;

    log->NamedInfo("LEAK_HUNTER", "=== %s: beats=%lu session_ms=%llu ===",
        label, sessionBeats, (unsigned long long)sessionMs);
    log->NamedInfo("LEAK_HUNTER",
        "  VAS:   total_free %+d MB  largest_free %+d MB  (entry=%lu MB  now=%lu MB)",
        vasDelta, lfDelta, entry.totalFreeMb, now.totalFreeMb);
    log->NamedInfo("LEAK_HUNTER",
        "  proxy: allocs %+d  bytes %+lld MB  (live=%lu allocs  %llu MB)",
        proxyAllocsDelta, proxyBytesDelta / (1024*1024),
        now.proxyActiveAllocs, (unsigned long long)(now.proxyUsedBytes / (1024*1024)));
    log->NamedInfo("LEAK_HUNTER",
        "  package_maps_this_session=%llu", (unsigned long long)pkgMapsDelta);

    // Per-module cumulative alloc growth during the session.
    static const char* const kMods[6] = { "game","graphics","runtime","system","mod","unknown" };
    char modLine[256] = {};
    int  pos = 0;
    for (int i = 0; i < 6; i++) {
        LONGLONG dMb = (now.alloc.bytesByModule[i] - entry.alloc.bytesByModule[i]) / (1024*1024);
        if (dMb == 0) continue;
        pos += _snprintf_s(modLine + pos, sizeof(modLine) - pos, _TRUNCATE,
            "  %s=%+lld MB", kMods[i], dMb);
    }
    if (pos > 0)
        log->NamedInfo("LEAK_HUNTER", "  by_module:%s", modLine);

    // Leak verdict.
    if (proxyAllocsDelta > 0 || proxyBytesDelta > (LONGLONG)(10 * 1024 * 1024)) {
        log->Warn("[LEAK_HUNTER] *** PROXY ALLOCS GREW during session: %+d allocs %+lld MB — LEAK LIKELY",
            proxyAllocsDelta, proxyBytesDelta / (1024*1024));
    } else if (proxyAllocsDelta == 0 && entry.proxyActiveAllocs > 20) {
        log->Warn("[LEAK_HUNTER] *** PROXY ALLOCS UNCHANGED: expected freeing after world session (%lu held) — LEAK POSSIBLE",
            now.proxyActiveAllocs);
    } else {
        log->NamedInfo("LEAK_HUNTER", "  verdict: proxy allocs released normally (%+d allocs %+lld MB)",
            proxyAllocsDelta, proxyBytesDelta / (1024*1024));
    }
}

static void LogPhaseDiff(const char* fromLabel, const char* toLabel,
                         const VasPhaseSnapshot& from, const VasPhaseSnapshot& to) {
    Logger* log = Logger::GetInstance();
    if (!log) return;

    DWORD fragFrom = (from.totalFreeMb > 0)
        ? (DWORD)((ULONGLONG)from.largestFreeMb * 100 / from.totalFreeMb) : 0;
    DWORD fragTo   = (to.totalFreeMb > 0)
        ? (DWORD)((ULONGLONG)to.largestFreeMb   * 100 / to.totalFreeMb)   : 0;
    int vasDelta   = (int)to.totalFreeMb - (int)from.totalFreeMb;
    DWORD durationMs = (to.tickMs > from.tickMs) ? (DWORD)(to.tickMs - from.tickMs) : 0;

    log->NamedInfo("PHASE_DIFF",
        "--- %s -> %s  (beats %lu->%lu  duration=%lu ms) ---",
        fromLabel, toLabel, from.beat, to.beat, durationMs);
    log->NamedInfo("PHASE_DIFF",
        "  vas:       free %lu->%lu MB (%+d MB)  largest %lu->%lu MB  frag_score %lu->%lu/100  regions %lu->%lu",
        from.totalFreeMb, to.totalFreeMb, vasDelta,
        from.largestFreeMb, to.largestFreeMb,
        fragFrom, fragTo,
        from.freeRegions, to.freeRegions);
    log->NamedInfo("PHASE_DIFF",
        "  commit:    private %lu->%lu MB  image %lu->%lu MB  mapped %lu->%lu MB  reserve %lu->%lu MB",
        from.commitPrivateMb, to.commitPrivateMb,
        from.commitImageMb,   to.commitImageMb,
        from.commitMappedMb,  to.commitMappedMb,
        from.reserveMb,       to.reserveMb);

    // Alloc delta
    LONGLONG dCaptureed = to.alloc.captured     - from.alloc.captured;
    LONGLONG dOffBytes  = to.alloc.capturedBytes - from.alloc.capturedBytes;
    LONGLONG dFailed    = to.alloc.captureFailed  - from.alloc.captureFailed;
    log->NamedInfo("PHASE_DIFF",
        "  proxy:     +%lld allocs  +%lld MB captured  %lld failed",
        dCaptureed, dOffBytes / (1024 * 1024), dFailed);

    // Per-module alloc deltas
    char modLine[256];
    int pos = 0;
    for (int i = 0; i < 6; i++) {
        LONGLONG dMb = (to.alloc.bytesByModule[i] - from.alloc.bytesByModule[i]) / (1024 * 1024);
        if (dMb == 0) continue;
        pos += _snprintf_s(modLine + pos, sizeof(modLine) - pos, _TRUNCATE,
            "  %s=%+lld MB", kModuleNames[i], dMb);
    }
    if (pos > 0)
        log->NamedInfo("PHASE_DIFF", "  by_module:%s", modLine);

    // Local VAS reserve delta
    LONGLONG dLocalMb = (to.alloc.localVasReserveBytes - from.alloc.localVasReserveBytes) / (1024 * 1024);
    if (dLocalMb != 0) {
        char localLine[256];
        int lpos = 0;
        for (int i = 0; i < 6; i++) {
            LONGLONG dlMb = (to.alloc.localVasByModule[i] - from.alloc.localVasByModule[i]) / (1024 * 1024);
            if (dlMb == 0) continue;
            lpos += _snprintf_s(localLine + lpos, sizeof(localLine) - lpos, _TRUNCATE,
                "  %s=%+lld MB", kModuleNames[i], dlMb);
        }
        log->NamedInfo("PHASE_DIFF",
            "  local_vas: +%lld MB reserve%s",
            dLocalMb, lpos > 0 ? localLine : "");
    }

    // Free histogram delta — shows fragmentation change as a compact diff
    log->NamedInfo("PHASE_DIFF",
        "  frag_hist: <1=%+d  1-4=%+d  4-16=%+d  16-64=%+d  64-256=%+d  256+=%+d",
        (int)to.freeBucket[0] - (int)from.freeBucket[0],
        (int)to.freeBucket[1] - (int)from.freeBucket[1],
        (int)to.freeBucket[2] - (int)from.freeBucket[2],
        (int)to.freeBucket[3] - (int)from.freeBucket[3],
        (int)to.freeBucket[4] - (int)from.freeBucket[4],
        (int)to.freeBucket[5] - (int)from.freeBucket[5]);
}


DWORD WINAPI HeartbeatMonitor::HeartbeatThreadFunc(LPVOID param) {
    EmergencyLog("HeartbeatMonitor", "Thread function started");

    HeartbeatMonitor* self = static_cast<HeartbeatMonitor*>(param);
    // Observe-only baseline: poll + log the two VAS metrics and nothing else — no
    // GC pushes, observe-table scans, slope/phase/leak telemetry, or proxy stats.
    const bool passive = WorkingHooks::IsPassiveMode();
    if (!passive)
        ProxyGc::Init();   // create the Mono-collect-request event + read tunables (once)
    DWORD beat_count = 0;
    DWORD last_vas_mb = 0;
    uint64_t prevWriteWatchExecBytes = 0;
    uint64_t prevReserveCommitGameBytes = 0;
    uint64_t prevReserveOnlyGameBytes = 0;
    uint64_t prevReserveCommitGameCount = 0;
    uint64_t prevReserveOnlyGameCount = 0;
    uint64_t prevVirtualAllocRedirectedCount = 0;
    DWORD prevLargestFreeReportMb = 0;
    bool hasSlopeBaseline = false;
    // Rolling largest_free history for the 30-min avg up/down rate readout.  Downsampled
    // to ~30s so region merge/split jitter doesn't dominate the rates.
    struct LfSample { ULONGLONG t; DWORD lf; DWORD tf; };   // largest_free + total_free
    const int   kLfRing = 80;            // ~40 min of headroom at 30s spacing
    LfSample    lfRing[kLfRing] = {};
    int         lfRingCount = 0, lfRingHead = 0;
    ULONGLONG   lastLfSampleTick = 0;
    // Don't account for the load-in transient — the first few minutes shed ~1.5 GB just
    // loading the world, which is expected and would swamp the steady-state rate.  Skip
    // it before the ring starts collecting.  Env-tunable (minutes).
    const ULONGLONG monitorStartTick = GetTickCount64();
    DWORD slopeWarmupMin = 10;
    {
        char wv[16] = {};
        DWORD wn = GetEnvironmentVariableA("TS3VAS_SLOPE_WARMUP_MIN", wv, (DWORD)sizeof(wv));
        if (wn > 0 && wn < sizeof(wv)) { int mm = atoi(wv); if (mm >= 0 && mm <= 120) slopeWarmupMin = (DWORD)mm; }
    }
    const ULONGLONG slopeWarmupMs = (ULONGLONG)slopeWarmupMin * 60000ULL;
    DWORD analyticsReportEveryBeats = 30;
    {
        char beatBuf[32] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_ANALYTICS_REPORT_BEATS", beatBuf, (DWORD)sizeof(beatBuf));
        if (n > 0 && n < sizeof(beatBuf)) {
            long v = strtol(beatBuf, nullptr, 10);
            if (v >= 1 && v <= 300) analyticsReportEveryBeats = (DWORD)v;
        }
    }

    Logger::GetInstance()->Info("[HB] Heartbeat thread running (TID: %lu)", GetCurrentThreadId());

    // ── Phase state machine ────────────────────────────────────────────────────
    // Phases (in order): post_inject → main_menu_stable → world_load_detected
    //                    → post_world_stable
    // Each transition logs a PHASE_DIFF block showing VAS + proxy deltas so
    // debug and non-debug runs can be compared line-for-line.
    //
    // Detection heuristics (beat interval = 2s for beats < 150, else 5s):
    //   main_menu_stable    — first time |delta_mb| < 50 for 3 consecutive beats,
    //                         after at least beat 3 (gives DLL load time to settle)
    //   world_load_detected — any beat with delta_mb <= -200
    //   post_world_stable   — first 3-beat stable window after world_load_detected
    //   world_exit_detected — package-map rate drops to 0 for 3 beats after
    //                         >= kMinWorldBeats in PostWorldStable; fires leak diff
    // After WorldExitDetected the machine returns to MainMenuStable so it can
    // detect subsequent world loads in the same session.

    enum class Phase { PostInject, MainMenuStable, WorldLoadDetected,
                       PostWorldStable, WorldExitDetected };
    Phase phase = Phase::PostInject;
    DWORD stableStreak = 0;               // consecutive beats with |delta| < 50 MB
    VasPhaseSnapshot phaseSnap = {};      // snapshot at last phase boundary
    VasPhaseSnapshot prevSnap  = {};      // snapshot at previous beat (for delta)

    // LEAK_HUNTER tracking
    // Gate on wall-time, not beat count: the beat interval switches from 2s to
    // 5s at beat 150, so a fixed beat threshold means very different real dwell
    // times.  45 s of in-world time before exit detection is eligible.
    static const ULONGLONG kMinWorldMs = 45000;
    DWORD mapViewQuietStreak = 0;          // consecutive beats with MapView_Package delta == 0
    uint64_t prevMapViewPackageCount = 0;
    LeakHunterSnapshot worldEntrySnap = {};
    bool worldEntrySnapTaken = false;

    CaptureVasPhaseSnapshot(phaseSnap, 0);
    prevSnap = phaseSnap;
    LogVasSnapshot("post_inject");        // always emit baseline snapshot

    while (InterlockedCompareExchange(&self->m_stopFlag, 0, 0) == 0) {
        DWORD sleep_duration = (beat_count < 150) ? 2000 : 5000;
        // Use wake event so Stop() unblocks us immediately rather than
        // waiting up to sleep_duration ms (old 2000ms timeout < 5000ms sleep = bug).
        WaitForSingleObject(self->m_wakeEvent, sleep_duration);
        if (InterlockedCompareExchange(&self->m_stopFlag, 0, 0) != 0) break;
        beat_count++;

        if (!passive && ObserveTablesEnabled()) {
            LogObserveTables(self->m_memManager);
            // HEAP_USAGE + GFX_CORRAL are coarse pictures — throttle them to once
            // every 5 minutes instead of every observe tick.
            static DWORD64 s_lastHeapCorralReportMs = 0;
            DWORD64 nowMs = GetTickCount64();
            if (s_lastHeapCorralReportMs == 0 || (nowMs - s_lastHeapCorralReportMs) >= 300000) {
                s_lastHeapCorralReportMs = nowMs;
                DumpHeapUsage();
                ReportAllocSizeDistribution();
                ReportAllocBytesDistribution();
                ReportProxySizeDistribution();
                ReportProxyFreeSizeDistribution();
                ReportHeapLocalDistribution();
                if (self->m_memManager) self->m_memManager->ReportCorralUsage();
            }
        }

        SIZE_T available_vas;
        SIZE_T largest_free_block;
        self->GetProcessMemoryInfo(available_vas, largest_free_block);
        s_latestLargestFreeBytes.store(largest_free_block, std::memory_order_relaxed);
        s_latestTotalFreeBytes.store(available_vas, std::memory_order_relaxed);
        s_latestVasSampleTickMs.store(GetTickCount64(), std::memory_order_relaxed);
        DWORD current_vas_mb = (DWORD)(available_vas / (1024 * 1024));
        DWORD largest_free_mb = (DWORD)(largest_free_block / (1024 * 1024));

        // Feed the rolling 30-min largest_free history (downsampled to ~30s), but only
        // after the warm-up so the load-in cliff doesn't dominate the rate.
        {
            ULONGLONG nowTick = GetTickCount64();
            if ((nowTick - monitorStartTick) >= slopeWarmupMs &&
                (lastLfSampleTick == 0 || (nowTick - lastLfSampleTick) >= 30000)) {
                lastLfSampleTick = nowTick;
                lfRing[lfRingHead].t  = nowTick;
                lfRing[lfRingHead].lf = largest_free_mb;
                lfRing[lfRingHead].tf = current_vas_mb;     // total free (less jumpy than largest)
                lfRingHead = (lfRingHead + 1) % kLfRing;
                if (lfRingCount < kLfRing) lfRingCount++;
            }
        }

        // Observe-only baseline: emit just the two VAS metrics for the graph, then
        // skip every other path (GC push, proxy stats, slope, milestones, phase
        // machine, leak hunter, analytics) so the run stays fully non-intervening.
        if (passive) {
            int vas_delta = (int)(current_vas_mb - last_vas_mb);
            const char* vas_dir = (vas_delta >= 0) ? "+" : "";
            Logger::GetInstance()->NamedInfo("VAS_REPORT",
                "Local VAS: total_free=%lu MB largest_free=%lu MB delta=%s%d",
                current_vas_mb, largest_free_mb, vas_dir, vas_delta);
            last_vas_mb = current_vas_mb;
            continue;
        }

        // Tell Mono it's under pressure (it can't see native VAS itself) so it
        // collects; cheap no-op on most ticks (rate-limited + 30-min floor).
        ProxyGc::MaybeRequestMonoCollect(largest_free_block);

        VASPressureMonitor* monitor = VASPressureMonitor::GetInstance();
        if (monitor) {
            monitor->Update(largest_free_block);  // keyed on largest_free, not total
        }
        
        // Proxy stats are local-only now (the server was retired).  The
        // reportedProxy* names are kept for the existing VAS_REPORT format below.
        MemoryManager::Stats localProxyStats = {};
        const bool has_local_proxy_stats = (self->m_memManager != nullptr);
        if (has_local_proxy_stats) {
            localProxyStats = self->m_memManager->GetStats();
        }

        ULONGLONG reportedProxyUsage = has_local_proxy_stats ? (ULONGLONG)localProxyStats.proxyUsedBytes : 0;
        ULONGLONG reportedProxyAllocsU64 = has_local_proxy_stats ? localProxyStats.activeAllocations : 0;
        const DWORD reportedProxyAllocs =
            (reportedProxyAllocsU64 > 0xFFFFFFFFULL) ? 0xFFFFFFFFUL : (DWORD)reportedProxyAllocsU64;

        bool slopeEmittedThisBeat = false;
        auto emitVasSlope = [&](const char* reasonTag) {
            Analytics* analytics = Analytics::GetInstance();
            if (!analytics) return;
            const uint64_t wwExecVaBytes = analytics->GetCounterValue("VirtualAlloc_NotRedirected_WriteWatchExecBytes");
            const uint64_t wwExecNtBytes = analytics->GetCounterValue("NtAllocVM_NotRedirected_WriteWatchExecBytes");
            const uint64_t wwExecNtExBytes = analytics->GetCounterValue("NtAllocVMEx_NotRedirected_WriteWatchExecBytes");
            const uint64_t reserveCommitGameBytes = analytics->GetCounterValue("VAS_VA_ReserveCommit_Game_Bytes");
            const uint64_t reserveOnlyGameBytes = analytics->GetCounterValue("VAS_VA_ReserveOnly_Game_Bytes");
            const uint64_t reserveCommitGameCount = analytics->GetCounterValue("VAS_VA_ReserveCommit_Game_Count");
            const uint64_t reserveOnlyGameCount = analytics->GetCounterValue("VAS_VA_ReserveOnly_Game_Count");
            const uint64_t virtualAllocRedirectedCount = analytics->GetCounterValue("VirtualAlloc_Redirected");
            const uint64_t totalWwExecBytes = wwExecVaBytes + wwExecNtBytes + wwExecNtExBytes;

            uint64_t wwExecDeltaBytes = 0;
            if (totalWwExecBytes >= prevWriteWatchExecBytes) wwExecDeltaBytes = totalWwExecBytes - prevWriteWatchExecBytes;
            uint64_t reserveCommitGameDeltaBytes = 0;
            if (reserveCommitGameBytes >= prevReserveCommitGameBytes) reserveCommitGameDeltaBytes = reserveCommitGameBytes - prevReserveCommitGameBytes;
            uint64_t reserveOnlyGameDeltaBytes = 0;
            if (reserveOnlyGameBytes >= prevReserveOnlyGameBytes) reserveOnlyGameDeltaBytes = reserveOnlyGameBytes - prevReserveOnlyGameBytes;
            uint64_t reserveCommitGameDeltaCount = 0;
            if (reserveCommitGameCount >= prevReserveCommitGameCount) reserveCommitGameDeltaCount = reserveCommitGameCount - prevReserveCommitGameCount;
            uint64_t reserveOnlyGameDeltaCount = 0;
            if (reserveOnlyGameCount >= prevReserveOnlyGameCount) reserveOnlyGameDeltaCount = reserveOnlyGameCount - prevReserveOnlyGameCount;
            uint64_t virtualAllocRedirectedDeltaCount = 0;
            if (virtualAllocRedirectedCount >= prevVirtualAllocRedirectedCount) virtualAllocRedirectedDeltaCount = virtualAllocRedirectedCount - prevVirtualAllocRedirectedCount;

            const double wwExecDeltaMb = (double)wwExecDeltaBytes / (1024.0 * 1024.0);
            const double totalWwExecMb = (double)totalWwExecBytes / (1024.0 * 1024.0);
            const double reserveCommitGameDeltaMb = (double)reserveCommitGameDeltaBytes / (1024.0 * 1024.0);
            const double reserveOnlyGameDeltaMb = (double)reserveOnlyGameDeltaBytes / (1024.0 * 1024.0);
            const int largestDeltaMb = hasSlopeBaseline ? ((int)largest_free_mb - (int)prevLargestFreeReportMb) : 0;

            if (hasSlopeBaseline && wwExecDeltaMb > 0.0) {
                const double lfLossPerWwMb = (double)((int)prevLargestFreeReportMb - (int)largest_free_mb) / wwExecDeltaMb;
                Logger::GetInstance()->NamedInfo("VAS_SLOPE",
                    "reason=%s | lf=%lu MB | lf_delta=%+d MB | WW_Exec=%+.1f MB | RC_Game=%+.1f MB | RO_Game=%+.1f MB | total_ww_exec=%.1f MB | lf_loss_per_ww_mb=%.2f",
                    reasonTag, largest_free_mb, largestDeltaMb, wwExecDeltaMb, reserveCommitGameDeltaMb, reserveOnlyGameDeltaMb, totalWwExecMb, lfLossPerWwMb);
            } else {
                Logger::GetInstance()->NamedInfo("VAS_SLOPE",
                    "reason=%s | lf=%lu MB | lf_delta=%+d MB | WW_Exec=%+.1f MB | RC_Game=%+.1f MB | RO_Game=%+.1f MB | total_ww_exec=%.1f MB | lf_loss_per_ww_mb=n/a",
                    reasonTag, largest_free_mb, largestDeltaMb, wwExecDeltaMb, reserveCommitGameDeltaMb, reserveOnlyGameDeltaMb, totalWwExecMb);
            }
            Logger::GetInstance()->NamedInfo("VAS_SLOPE",
                "reason=%s | pop_delta: Redirected=%+llu | RC_Game_Count=%+llu | RO_Game_Count=%+llu",
                reasonTag,
                (unsigned long long)virtualAllocRedirectedDeltaCount,
                (unsigned long long)reserveCommitGameDeltaCount,
                (unsigned long long)reserveOnlyGameDeltaCount);

            // Rolling 30-min largest_free rate: average decline rate over the stretches
            // it was falling vs average recovery rate over the stretches it was rising,
            // plus the net.  down_avg >> up_avg with a negative net = sustained bleed.
            if ((GetTickCount64() - monitorStartTick) < slopeWarmupMs) {
                const double leftMin =
                    (double)(slopeWarmupMs - (GetTickCount64() - monitorStartTick)) / 60000.0;
                Logger::GetInstance()->NamedInfo("VAS_SLOPE",
                    "reason=%s | 30min_rate: warming up, %.0f min until accounting starts (skips the load-in cliff)",
                    reasonTag, leftMin);
            } else {
                // Average the VAS_REPORT delta over the last 10 min.  Summing the deltas
                // telescopes to the net total_free change across the window, so the
                // average is simply net / window-minutes -> MB/min.
                const ULONGLONG nowT   = GetTickCount64();
                const ULONGLONG window = 10ULL * 60ULL * 1000ULL;   // 10 min
                const int start = (lfRingCount < kLfRing) ? 0 : lfRingHead;  // oldest first
                DWORD firstTf = 0; ULONGLONG firstT = 0; bool haveFirst = false; int n = 0;
                for (int k = 0; k < lfRingCount; ++k) {
                    const int idx = (start + k) % kLfRing;
                    if (nowT - lfRing[idx].t > window) continue;    // outside the 10-min window
                    if (!haveFirst) { firstTf = lfRing[idx].tf; firstT = lfRing[idx].t; haveFirst = true; }
                    n++;
                }
                if (haveFirst) {
                    const int    net     = (int)current_vas_mb - (int)firstTf;
                    const double spanMin = (double)(nowT - firstT) / 60000.0;
                    const double avgRate = spanMin > 0.0 ? (double)net / spanMin : 0.0;
                    Logger::GetInstance()->NamedInfo("VAS_SLOPE",
                        "reason=%s | 10min_avg: %+.1f MB/min (net %+d MB over %.0f min, samples=%d)",
                        reasonTag, avgRate, net, spanMin, n);
                }
            }

            prevWriteWatchExecBytes = totalWwExecBytes;
            prevReserveCommitGameBytes = reserveCommitGameBytes;
            prevReserveOnlyGameBytes = reserveOnlyGameBytes;
            prevReserveCommitGameCount = reserveCommitGameCount;
            prevReserveOnlyGameCount = reserveOnlyGameCount;
            prevVirtualAllocRedirectedCount = virtualAllocRedirectedCount;
            prevLargestFreeReportMb = largest_free_mb;
            hasSlopeBaseline = true;
            slopeEmittedThisBeat = true;
        };
        
        // Proxy activates immediately when hooks go live (Main.cpp calls
        // WorkingHooks::ActivateProxy() right after InstallAndEnableHooks).
        // Fallback removed — if proxy isn't active here something went wrong
        // at hook install time, not a timing issue the heartbeat can fix.

        // VAS milestone logging — fires once per threshold crossing.
        // Critical for diagnosing world-load crashes: shows exactly when
        // VAS pressure crosses each danger level.
        static DWORD vas_milestone_flags = 0; // bit 0=2GB, 1=1.5GB, 2=1GB, 3=500MB, 4=250MB
        static DWORD largest_free_milestone_flags = 0; // bit 0=128MB, 1=96MB, 2=64MB
        struct { DWORD threshold_mb; DWORD bit; const char* label; } milestones[] = {
            { 2000, 0, "2GB"   },
            { 1500, 1, "1.5GB" },
            { 1000, 2, "1GB"   },
            {  500, 3, "500MB" },
            {  250, 4, "250MB" },
        };
        for (auto& m : milestones) {
            if (current_vas_mb < m.threshold_mb && !(vas_milestone_flags & (1u << m.bit))) {
                vas_milestone_flags |= (1u << m.bit);
                Logger::GetInstance()->Warn(
                    "[VAS_MILESTONE] Free VAS crossed below %s (%lu MB free at beat %lu)",
                    m.label, current_vas_mb, beat_count);
                if (Analytics::GetInstance())
                    Analytics::GetInstance()->IncrementCounter("VAS_Milestone_Crossed");
            }
        }
        struct { DWORD threshold_mb; DWORD bit; const char* label; const char* counter; } largestFreeMilestones[] = {
            { 128, 0, "128MB", "VAS_LargestFree_Warning_Crossed" },
            {  96, 1, "96MB",  "VAS_LargestFree_Critical_Crossed" },
            {  64, 2, "64MB",  "VAS_LargestFree_NearFail_Crossed" },
        };
        bool largestFreeMilestoneCrossedThisBeat = false;
        for (auto& m : largestFreeMilestones) {
            if (largest_free_mb < m.threshold_mb && !(largest_free_milestone_flags & (1u << m.bit))) {
                largest_free_milestone_flags |= (1u << m.bit);
                largestFreeMilestoneCrossedThisBeat = true;
                Logger::GetInstance()->Warn(
                    "[VAS_MILESTONE] Largest free crossed below %s (%lu MB largest free at beat %lu)",
                    m.label, largest_free_mb, beat_count);
                if (Analytics::GetInstance())
                    Analytics::GetInstance()->IncrementCounter(m.counter);
            }
        }
        if (largestFreeMilestoneCrossedThisBeat && Analytics::GetInstance()) {
            emitVasSlope("milestone");
        }

        bool vas_changed = (current_vas_mb != last_vas_mb);
        bool should_log = (beat_count <= 30) || vas_changed || (beat_count % 10 == 0);

        if (should_log) {
            int vas_delta = (int)(current_vas_mb - last_vas_mb);
            const char* vas_dir = (vas_delta >= 0) ? "+" : "";
            // Mono managed-heap size: prefer the C# companion's shared-memory value
            // (GC.GetTotalMemory).  Fall back to the native script-arena (corral) used
            // bytes when the companion is not connected — those bytes are the same
            // physical allocation, so the number is accurate even without the companion.
            unsigned long long shBytes = ProxyGc::GetScriptHeapBytes();
            if (shBytes == 0 && self->m_memManager)
                shBytes = (unsigned long long)self->m_memManager->GetCorralUsedBytes();
            const unsigned long long scriptHeapMb = shBytes / (1024ULL * 1024ULL);

            if (reportedProxyAllocs > 0) {
                Logger::GetInstance()->NamedInfo("VAS_REPORT", "Local VAS: total_free=%lu MB largest_free=%lu MB delta=%s%d | Proxy: %lu allocs (%llu MB) | script_heap=%llu MB",
                    current_vas_mb,
                    largest_free_mb,
                    vas_dir,
                    vas_delta,
                    reportedProxyAllocs,
                    reportedProxyUsage / (1024*1024),
                    scriptHeapMb);
            } else {
                Logger::GetInstance()->NamedInfo("VAS_REPORT", "Local VAS: total_free=%lu MB largest_free=%lu MB delta=%s%d | script_heap=%llu MB",
                    current_vas_mb, largest_free_mb, vas_dir, vas_delta, scriptHeapMb);
            }
            if (vas_delta <= -64) {
                WorkingHooks::ReportLocalVasSources("VAS_LOCAL_SOURCES");
            }
        }

        if (beat_count > 0 && beat_count % analyticsReportEveryBeats == 0) {
            if (Analytics::GetInstance())
                Analytics::GetInstance()->Report();
            if (Analytics::GetInstance()) {
                const uint64_t missTotal = Analytics::GetInstance()->GetCounterValue("ReadFile_CacheMiss");
                const uint64_t missRepeat = Analytics::GetInstance()->GetCounterValue("ReadFile_CacheMiss_RepeatWithin60s");
                const double repeatPct = (missTotal > 0) ? (100.0 * (double)missRepeat / (double)missTotal) : 0.0;
                Logger::GetInstance()->NamedInfo("ANALYTICS_REPORT",
                    "Miss churn ratio: repeat60s=%llu/%llu (%.1f%%)",
                    (unsigned long long)missRepeat, (unsigned long long)missTotal, repeatPct);
                const uint64_t failGe128 = Analytics::GetInstance()->GetCounterValue("SyncCache_WriteFailed_At_LargestFree_GE128");
                const uint64_t fail96_127 = Analytics::GetInstance()->GetCounterValue("SyncCache_WriteFailed_At_LargestFree_96_127");
                const uint64_t fail64_95 = Analytics::GetInstance()->GetCounterValue("SyncCache_WriteFailed_At_LargestFree_64_95");
                const uint64_t failLt64 = Analytics::GetInstance()->GetCounterValue("SyncCache_WriteFailed_At_LargestFree_LT64");
                const uint64_t failStale = Analytics::GetInstance()->GetCounterValue("SyncCache_WriteFailed_At_LargestFree_StaleSample");
                const uint64_t failReal = Analytics::GetInstance()->GetCounterValue("SyncCache_WriteFailed");
                const uint64_t failUnsupported = Analytics::GetInstance()->GetCounterValue("SyncCache_WriteFailed_Unsupported");
                if (!slopeEmittedThisBeat) {
                    emitVasSlope("interval");
                }
                Logger::GetInstance()->NamedInfo("ANALYTICS_REPORT",
                    "SyncCache failures: real=%llu unsupported=%llu",
                    (unsigned long long)failReal,
                    (unsigned long long)failUnsupported);
                Logger::GetInstance()->NamedInfo("ANALYTICS_REPORT",
                    "SyncCache fail bands (last VAS sample): >=128=%llu 96-127=%llu 64-95=%llu <64=%llu stale=%llu",
                    (unsigned long long)failGe128,
                    (unsigned long long)fail96_127,
                    (unsigned long long)fail64_95,
                    (unsigned long long)failLt64,
                    (unsigned long long)failStale);
            }
            if (self->m_memManager)
                self->m_memManager->ReportStats("PROXY_ARENA_REPORT");
            WorkingHooks::ReportProxyHeapUsage("PROXY_HEAP");   // sardine fill, same cadence as the arena
            WorkingHooks::ReportAllocCallsites("RTL_ALLOC_REPORT");
            WorkingHooks::ReportLocalVasSources("VAS_LOCAL_SOURCES");
        }
        
        last_vas_mb = current_vas_mb;

        // Track MapView_Package rate for world-exit detection.
        {
            uint64_t mapViewPackageNow = Analytics::GetInstance()
                ? Analytics::GetInstance()->GetCounterValue("MapView_Package") : 0;
            uint64_t mapViewPackageDelta = mapViewPackageNow - prevMapViewPackageCount;
            mapViewQuietStreak = (mapViewPackageDelta == 0) ? mapViewQuietStreak + 1 : 0;
            prevMapViewPackageCount = mapViewPackageNow;
        }

        // ── Phase state machine update ─────────────────────────────────────────
        // Run after VAS sample so current_vas_mb and the running delta are fresh.
        {
            int vasDelta = (int)current_vas_mb - (int)(prevSnap.totalFreeMb);
            bool isStable = (vasDelta > -50 && vasDelta < 50);
            stableStreak = isStable ? stableStreak + 1 : 0;

            VasPhaseSnapshot curSnap = {};
            bool snapshotTaken = false;

            auto takeSnap = [&]() {
                if (!snapshotTaken) {
                    CaptureVasPhaseSnapshot(curSnap, beat_count);
                    snapshotTaken = true;
                }
            };

            if (phase == Phase::PostInject &&
                stableStreak >= 3 && beat_count >= 3)
            {
                takeSnap();
                LogPhaseDiff("post_inject", "main_menu_stable", phaseSnap, curSnap);
                phaseSnap = curSnap;
                phase = Phase::MainMenuStable;
                stableStreak = 0;
            }
            else if (phase == Phase::MainMenuStable && vasDelta <= -200)
            {
                takeSnap();
                LogPhaseDiff("main_menu_stable", "world_load_detected", phaseSnap, curSnap);
                phaseSnap = curSnap;
                phase = Phase::WorldLoadDetected;
                stableStreak = 0;
            }
            else if (phase == Phase::WorldLoadDetected &&
                     stableStreak >= 3)
            {
                takeSnap();
                LogPhaseDiff("world_load_detected", "post_world_stable", phaseSnap, curSnap);
                phaseSnap = curSnap;
                phase = Phase::PostWorldStable;
                stableStreak = 0;
            }
            else if (phase == Phase::PostWorldStable)
            {
                // Capture the world-entry snapshot on the first beat so we have
                // a live-proxy baseline from the moment the world was fully loaded.
                if (!worldEntrySnapTaken) {
                    CaptureLeakHunterSnapshot(worldEntrySnap, beat_count,
                        current_vas_mb, largest_free_mb,
                        reportedProxyUsage, reportedProxyAllocs);
                    worldEntrySnapTaken = true;
                    Logger::GetInstance()->NamedInfo("LEAK_HUNTER",
                        "World entry snapshot captured at beat %lu (proxy=%lu allocs %llu MB)",
                        beat_count, reportedProxyAllocs,
                        (unsigned long long)(reportedProxyUsage / (1024*1024)));
                }

                // World-exit detection: package mapping has gone quiet for 3 beats
                // after the minimum in-world dwell time.  Since VAS does not recover
                // on return to main menu we use the mapping-rate signal instead.
                // Dwell is measured in wall-time from the world-entry snapshot so
                // the 2s→5s beat-interval switch doesn't change the real threshold.
                ULONGLONG worldDwellMs = GetTickCount64() - worldEntrySnap.tickMs;
                if (worldDwellMs >= kMinWorldMs && mapViewQuietStreak >= 3)
                {
                    takeSnap();
                    LeakHunterSnapshot exitSnap = {};
                    CaptureLeakHunterSnapshot(exitSnap, beat_count,
                        current_vas_mb, largest_free_mb,
                        reportedProxyUsage, reportedProxyAllocs);

                    Logger::GetInstance()->Warn(
                        "[LEAK_HUNTER] World exit detected at beat %lu"
                        " (in_world=%llu s, pkg_quiet=%lu beats)",
                        beat_count, (unsigned long long)(worldDwellMs / 1000), mapViewQuietStreak);
                    LogLeakHunterDiff("world_session_diff", worldEntrySnap, exitSnap);
                    WorkingHooks::ReportAllocCallsites("LEAK_HUNTER");
                    WorkingHooks::ReportLocalVasSources("LEAK_HUNTER");
                    if (self->m_memManager) self->m_memManager->ReportStats("LEAK_HUNTER");
                    emitVasSlope("leak_hunter");
                    // Dump still-outstanding large local reserves to their own
                    // dedicated channel (UNFREED_ASSETS), parseable on its own.
                    DumpUnfreedAssets();

                    LogPhaseDiff("post_world_stable", "world_exit_detected", phaseSnap, curSnap);
                    phaseSnap = curSnap;
                    phase = Phase::WorldExitDetected;
                    stableStreak = 0;
                    worldEntrySnapTaken = false;
                    mapViewQuietStreak = 0;
                }
                else
                {
                    // Secondary: cumulative in-session VAS drain (script memory pressure).
                    // Fires if free VAS has grown by >= 150 MB from world-stable entry —
                    // indicates gradual memory recovery during teardown or heavy scripting.
                    int cumulativeDelta = (int)current_vas_mb - (int)phaseSnap.totalFreeMb;
                    if (cumulativeDelta >= 150)
                    {
                        Logger::GetInstance()->Warn(
                            "[LEAK_HUNTER] Cumulative VAS +%d MB from PostWorldStable baseline (beat %lu)",
                            cumulativeDelta, beat_count);
                        WorkingHooks::ReportAllocCallsites("LEAK_HUNTER");
                        WorkingHooks::ReportLocalVasSources("LEAK_HUNTER");
                        if (self->m_memManager) self->m_memManager->ReportStats("LEAK_HUNTER");
                        emitVasSlope("leak_hunter_vas");
                        phaseSnap.totalFreeMb = current_vas_mb;
                        phaseSnap.beat        = beat_count;
                        phaseSnap.tickMs      = GetTickCount64();
                    }
                }
            }
            else if (phase == Phase::WorldExitDetected && stableStreak >= 3)
            {
                // Stable after world exit — back at main menu, ready for next cycle.
                takeSnap();
                LogPhaseDiff("world_exit_detected", "main_menu_stable", phaseSnap, curSnap);
                phaseSnap = curSnap;
                phase = Phase::MainMenuStable;
                stableStreak = 0;
            }

            // Update prevSnap for next beat's delta calculation.
            if (snapshotTaken) {
                prevSnap = curSnap;
            } else {
                // Lightweight update — only what the delta check needs.
                prevSnap.totalFreeMb = current_vas_mb;
                prevSnap.beat        = beat_count;
                prevSnap.tickMs      = GetTickCount64();
            }
        }
    }

    return 0;
}
