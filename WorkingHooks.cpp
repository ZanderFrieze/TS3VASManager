#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <winternl.h>
#include "WorkingHooks.h"
#include "MemoryManager.h"
#include "Analytics.h"
#include "Logger.h"
#include "HitchDetector.h"
#include "EmergencyLogger.h"
#include "ETWProvider.h"
#include "ContainmentLane.h"       // contained/excluded allocation classification
#include "MapViewTypeTracker.h"       // view inventory + type-ID redirect filter
#include "ScriptScanDedup.h"          // shared single-report set for S3SA detection
#include <detours.h>
#include <psapi.h>
#include <intrin.h>
#include <string.h>
#include <algorithm>
#include <cstdlib>

// Use PVOID for RTL_HEAP_PARAMETERS — avoids WDK-only header requirement.
typedef PVOID   (NTAPI *RtlCreateHeap_t)      (ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
typedef PVOID   (NTAPI *RtlAllocateHeap_t)    (PVOID, ULONG, SIZE_T);
typedef BOOLEAN (NTAPI *RtlFreeHeap_t)        (PVOID, ULONG, PVOID);
typedef PVOID   (NTAPI *RtlReAllocateHeap_t)  (PVOID, ULONG, PVOID, SIZE_T);
// NtAllocateVirtualMemory replaces kernel32!VirtualAlloc (bare forwarder on Win10+)
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)    (HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemoryEx_t)(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef LPVOID  (WINAPI *VirtualAlloc_t)           (LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *VirtualFree_t)            (LPVOID, SIZE_T, DWORD);
typedef LPVOID  (WINAPI *HeapAlloc_t)              (HANDLE, DWORD, SIZE_T);
typedef BOOL    (WINAPI *HeapFree_t)               (HANDLE, DWORD, LPVOID);
typedef LPVOID  (WINAPI *HeapReAlloc_t)            (HANDLE, DWORD, LPVOID, SIZE_T);
typedef HANDLE  (WINAPI *HeapCreate_t)             (DWORD, SIZE_T, SIZE_T);
typedef BOOL    (WINAPI *HeapDestroy_t)            (HANDLE);
typedef SIZE_T  (WINAPI *HeapSize_t)               (HANDLE, DWORD, LPCVOID);
// Global/Local movable handles: the block must stay a real heap block so the
// internal RtlSetUserValueHeap linkage works. We hook these only to run them with
// proxy redirection suppressed (see Hooked_GlobalAlloc), never to redirect.
typedef HGLOBAL (WINAPI *GlobalAlloc_t)            (UINT, SIZE_T);
typedef HGLOBAL (WINAPI *GlobalReAlloc_t)          (HGLOBAL, SIZE_T, UINT);
typedef HLOCAL  (WINAPI *LocalAlloc_t)             (UINT, SIZE_T);
typedef HLOCAL  (WINAPI *LocalReAlloc_t)           (HLOCAL, SIZE_T, UINT);
typedef BOOL    (WINAPI *HeapValidate_t)           (HANDLE, DWORD, LPCVOID);
typedef SIZE_T  (WINAPI *HeapCompact_t)            (HANDLE, DWORD);
typedef BOOL    (WINAPI *HeapWalk_t)               (HANDLE, LPPROCESS_HEAP_ENTRY);
typedef BOOL    (WINAPI *HeapLock_t)               (HANDLE);
typedef BOOL    (WINAPI *HeapUnlock_t)             (HANDLE);
typedef LPVOID  (WINAPI *MapViewOfFile_t)          (HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef LPVOID  (WINAPI *MapViewOfFileEx_t)        (HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID);
typedef BOOL    (WINAPI *UnmapViewOfFile_t)        (LPCVOID);
typedef LPVOID  (WINAPI *VirtualAllocEx_t)         (HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *VirtualFreeEx_t)          (HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *VirtualProtect_t)         (LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *VirtualProtectEx_t)       (HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef SIZE_T  (WINAPI *VirtualQuery_t)           (LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef SIZE_T  (WINAPI *VirtualQueryEx_t)         (HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef BOOL    (WINAPI *VirtualLock_t)            (LPVOID, SIZE_T);
typedef BOOL    (WINAPI *VirtualUnlock_t)          (LPVOID, SIZE_T);
typedef LPVOID  (WINAPI *VirtualAlloc2_t)          (HANDLE, LPVOID, SIZE_T, DWORD, DWORD, PVOID, ULONG);
typedef LPVOID  (WINAPI *VirtualAllocFromApp_t)    (PVOID, SIZE_T, ULONG, ULONG);
typedef LPVOID  (WINAPI *VirtualAlloc2FromApp_t)   (HANDLE, PVOID, SIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef HANDLE  (WINAPI *CreateFileMappingA_t)     (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef HANDLE  (WINAPI *CreateFileMappingW_t)     (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef HANDLE  (WINAPI *OpenFileMappingA_t)       (DWORD, BOOL, LPCSTR);
typedef HANDLE  (WINAPI *OpenFileMappingW_t)       (DWORD, BOOL, LPCWSTR);
typedef BOOL    (WINAPI *FlushViewOfFile_t)        (LPCVOID, SIZE_T);

static RtlCreateHeap_t           Real_RtlCreateHeap           = nullptr;
static RtlAllocateHeap_t         Real_RtlAllocateHeap         = nullptr;
static RtlFreeHeap_t             Real_RtlFreeHeap             = nullptr;
static RtlReAllocateHeap_t       Real_RtlReAllocateHeap       = nullptr;
static NtAllocateVirtualMemory_t Real_NtAllocateVirtualMemory = nullptr;
static NtFreeVirtualMemory_t     Real_NtFreeVirtualMemory     = nullptr;
static NtAllocateVirtualMemoryEx_t Real_NtAllocateVirtualMemoryEx = nullptr;
static VirtualAlloc_t            Real_VirtualAlloc            = nullptr;
static VirtualFree_t             Real_VirtualFree             = nullptr;
static HeapAlloc_t               Real_HeapAlloc               = nullptr;
static HeapFree_t                Real_HeapFree                = nullptr;
static HeapReAlloc_t             Real_HeapReAlloc             = nullptr;
static HeapCreate_t              Real_HeapCreate              = nullptr;
static GlobalAlloc_t             Real_GlobalAlloc             = nullptr;
static GlobalReAlloc_t           Real_GlobalReAlloc           = nullptr;
static LocalAlloc_t              Real_LocalAlloc              = nullptr;
static LocalReAlloc_t            Real_LocalReAlloc            = nullptr;
static HeapDestroy_t             Real_HeapDestroy             = nullptr;
static HeapSize_t                Real_HeapSize                = nullptr;
static HeapValidate_t            Real_HeapValidate            = nullptr;
static HeapCompact_t             Real_HeapCompact             = nullptr;
static HeapWalk_t                Real_HeapWalk                = nullptr;
static HeapLock_t                Real_HeapLock                = nullptr;
static HeapUnlock_t              Real_HeapUnlock              = nullptr;
static MapViewOfFile_t           Real_MapViewOfFile           = nullptr;
static MapViewOfFileEx_t         Real_MapViewOfFileEx         = nullptr;
static UnmapViewOfFile_t         Real_UnmapViewOfFile         = nullptr;
static VirtualAllocEx_t          Real_VirtualAllocEx          = nullptr;
static VirtualFreeEx_t           Real_VirtualFreeEx           = nullptr;
static VirtualProtect_t          Real_VirtualProtect          = nullptr;
static VirtualProtectEx_t        Real_VirtualProtectEx        = nullptr;
static VirtualQuery_t            Real_VirtualQuery            = nullptr;
static VirtualQueryEx_t          Real_VirtualQueryEx          = nullptr;
static VirtualLock_t             Real_VirtualLock             = nullptr;
static VirtualUnlock_t           Real_VirtualUnlock           = nullptr;
static VirtualAlloc2_t           Real_VirtualAlloc2           = nullptr;
static VirtualAllocFromApp_t     Real_VirtualAllocFromApp     = nullptr;
static VirtualAlloc2FromApp_t    Real_VirtualAlloc2FromApp    = nullptr;
static CreateFileMappingA_t      Real_CreateFileMappingA      = nullptr;
static CreateFileMappingW_t      Real_CreateFileMappingW      = nullptr;
static OpenFileMappingA_t        Real_OpenFileMappingA        = nullptr;
static OpenFileMappingW_t        Real_OpenFileMappingW        = nullptr;
static FlushViewOfFile_t         Real_FlushViewOfFile         = nullptr;

// ── VirtualAlloc redirect tracker ───────────────────────────────────────────
// Pre-allocated flat arrays — no heap, no re-entrancy risk inside the hook.
static const int    kVatMax       = 8192;
static UINT_PTR     s_vatAddr[kVatMax];
static SIZE_T       s_vatSize[kVatMax];
static volatile LONG s_vatCount   = 0;
static CRITICAL_SECTION s_vatCS;
static bool s_vatCSInit = false;

static void VatInit() {
    if (!s_vatCSInit) { InitializeCriticalSection(&s_vatCS); s_vatCSInit = true; }
}

// ── Unfreed-asset tracking (world-exit leak hunter) ───────────────────────────
// Statically allocated flat array — no heap calls inside hook paths.  Tracks
// large local VirtualAlloc reserves so DumpUnfreedAssets() can list whatever is
// still outstanding when the world unloads.  Module name is resolved once at
// registration time so the dump needs no symbol lookup.  Dedicated log channel
// "UNFREED_ASSETS" — kept separate from SCRIPT_HIGHWAY / LEAK_HUNTER so it
// parses clean with no other noise.
struct DiagnosticAllocRecord {
    volatile UINT_PTR address;
    SIZE_T            size;
    void*             retAddr;
    DWORD             allocTick;   // GetTickCount() at allocation (the "when")
    char              moduleName[64];
};

static const int              kDiagMax     = 8192;
static DiagnosticAllocRecord  s_diagRecords[kDiagMax];
static volatile LONG          s_diagCount  = 0;
static CRITICAL_SECTION       s_diagCS;
static bool                   s_diagCSInit = false;

// ── Per-heap allocation attribution ───────────────────────────────────────────
// Which heap HANDLE the game places large (>=capture) allocations in — the map we
// need before corralling heaps into their own breathing zones.  Bytes/count + the
// first caller module seen per heap.  Dumped to the HEAP_USAGE channel.
struct HeapUseRec {
    volatile UINT_PTR handle;
    volatile LONG64   count;
    volatile LONG64   bytes;
    char              module[40];
    bool              corralTarget;   // route this heap's allocs to the proxy arena
    bool              sardineExclude; // graphics-driver heap: keep its allocs OUT of the sardine
};

// Heaps whose first-caller module is in this set get ALL their allocations routed
// into the proxy arena (a per-heap corral), regardless of size — pulls that
// subsystem's memory out of the loose VAS.  Extend the list to corral more heaps.
static bool IsCorralModule(const char* m) {
    // No heaps are corralled by default.  DSOUND USED to be corralled here, but its heap
    // pointers cross into the kernel audio path and it calls RtlSetUserValueHeap /
    // RtlGetUserInfoHeap on them (which need real ntdll blocks) — corralling its whole
    // heap into the arena corrupted the heap and crashed (xcpt DRAKKAR 26-06-09).  DSOUND
    // and the rest of the audio subsystem are now kept fully hands-off via IsAudioModule
    // (excluded from corral, sardine, AND arena capture).  Re-add a heap here only if its
    // memory NEVER crosses into a driver/kernel command path.
    (void)m;
    return false;
}

static bool StringContainsI(const char* haystack, const char* needle);  // defined below

// Heaps owned by a graphics-driver module.  Their sub-64KB allocations must NOT be
// captured into the in-arena sardine shards: the driver hands those pointers to the
// GPU/kernel command path, which is incompatible with the proxy arena's VAS, and an
// in-arena shard so tenanted gets its heap header smashed -> AV inside RtlAllocateHeap
// on a later sardine alloc (xcpt DRAKKAR 26-06-04: AMDXN32 -> Hooked_RtlAllocateHeap ->
// ProxyHeapAlloc).  This is the single source of truth for "is this a graphics-driver
// module" — ClassifyCallerModule (lane routing) also calls it, so the two never drift.
// Substrings deliberately match the 32- and 64-bit variants of each driver DLL.
static bool IsGraphicsModule(const char* m) {
    if (!m || !m[0]) return false;
    return
        // D3D / OpenGL / Vulkan API runtimes
        StringContainsI(m, "d3d9.dll")    || StringContainsI(m, "dxgi.dll")     ||
        StringContainsI(m, "opengl32.dll")|| StringContainsI(m, "vulkan-1.dll") ||
        // NVIDIA user-mode drivers: nvd3dum(x) D3D9 UMD, nvwgf2um(x) D3D10+ UMD,
        // nvoglv32/64 OpenGL ICD, nvldumd(x) newer UMD, nvumdshim UMD shim.
        StringContainsI(m, "nvd3dum")     || StringContainsI(m, "nvwgf2um")     ||
        StringContainsI(m, "nvoglv")      || StringContainsI(m, "nvldumd")      ||
        StringContainsI(m, "nvumdshim")   ||
        // AMD user-mode drivers
        StringContainsI(m, "atidxx")      || StringContainsI(m, "atidx9")       ||
        StringContainsI(m, "AMDXN32")     || StringContainsI(m, "amdxc32")      ||
        StringContainsI(m, "amdihk")      ||
        // Intel integrated GPU user-mode drivers
        StringContainsI(m, "igd10")       || StringContainsI(m, "igdumd");
}

// Audio subsystem modules — driver-adjacent the SAME way graphics drivers are: DSOUND /
// AUDIOSES / wdmaud hand their heap blocks down to the kernel audio path and call
// RtlSetUserValueHeap / RtlGetUserInfoHeap on them, which require a REAL ntdll heap
// block.  Capturing those allocs into the proxy arena or a sardine shard makes those
// APIs fail ("Invalid address specified to RtlSetUserValueHeap( ... )") and corrupts the
// heap -> AV (xcpt DRAKKAR 26-06-09: DSOUND -> winmmbase -> RPCRT4 -> our hook -> ntdll
// heap, write 0xfffffff8).  So audio is kept fully hands-off: no corral, no sardine, no
// arena capture.  Substrings match the .dll and .drv variants.
static bool IsAudioModule(const char* m) {
    if (!m || !m[0]) return false;
    return
        StringContainsI(m, "dsound")     || StringContainsI(m, "audioses")  ||
        StringContainsI(m, "mmdevapi")   || StringContainsI(m, "wdmaud")    ||
        StringContainsI(m, "winmm")      || StringContainsI(m, "msacm")     ||
        StringContainsI(m, "midimap")    || StringContainsI(m, "avrt")      ||
        StringContainsI(m, "msdmo")      || StringContainsI(m, "resampledmo")||
        StringContainsI(m, "audioeng");
}
static const int        kHeapUseMax = 128;
static HeapUseRec       s_heapUse[kHeapUseMax];
static volatile LONG    s_heapUseCount = 0;
static CRITICAL_SECTION s_heapUseCS;

static void DiagInit() {
    if (!s_diagCSInit) {
        InitializeCriticalSection(&s_diagCS);
        InitializeCriticalSection(&s_heapUseCS);
        s_diagCSInit = true;
    }
}

// ── Caller-based graphics exclusion (sardine backstop) ───────────────────────
// HeapIsSardineExcluded tags a heap by its FIRST-seen caller, which is racy for a
// heap SHARED by a graphics driver and other code. The lean play build (no observe
// layer to shift startup timing) loses that race, so AMDXN32 allocs slip into the
// sardine and smash the LFH freelist (the RtlpAllocateHeap / RtlTryEnterCriticalSection
// AVs at a bogus address). Backstop: reject the sardine when the IMMEDIATE caller's
// return address lies in a graphics-driver module. Each caller module is resolved
// ON A MISS via GetModuleHandleEx and cached with its [base,end)+gfx flag — so a
// driver that loads LATE (AMDXN32 comes up during D3D9 init, after d3d9/dxgi) is
// still caught on its very first call, not skipped because the cache froze early.
struct CallerModRange { UINT_PTR base, end; bool gfx; bool audio; };
static const int      kCallerModMax = 256;
static CallerModRange s_callerMods[kCallerModMax];
static volatile LONG  s_callerModCount = 0;

static bool CallerIsGraphicsModule(void* ra) {
    if (!ra || !s_diagCSInit) return false;
    const UINT_PTR a = (UINT_PTR)ra;
    LONG n = s_callerModCount;                       // lock-free fast path (append-only)
    for (LONG i = 0; i < n; ++i)
        if (a >= s_callerMods[i].base && a < s_callerMods[i].end) return s_callerMods[i].gfx;

    // Miss: resolve THIS caller's module once and cache it. Modules are finite, so the
    // GetModuleHandleEx + lock happens only on first sighting of each caller module.
    HMODULE mod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)a, &mod) || !mod)
        return false;                                // dynamic/JIT code — no owning module
    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return false;
    char name[64] = {};
    GetModuleBaseNameA(GetCurrentProcess(), mod, name, sizeof(name));
    const bool gfx = IsGraphicsModule(name);
    const bool aud = IsAudioModule(name);

    EnterCriticalSection(&s_heapUseCS);
    bool known = false;
    LONG m = s_callerModCount;
    for (LONG j = 0; j < m; ++j)
        if (s_callerMods[j].base == (UINT_PTR)mi.lpBaseOfDll) { known = true; break; }
    if (!known && m < kCallerModMax) {
        s_callerMods[m].base = (UINT_PTR)mi.lpBaseOfDll;
        s_callerMods[m].end  = (UINT_PTR)mi.lpBaseOfDll + mi.SizeOfImage;
        s_callerMods[m].gfx  = gfx;
        s_callerMods[m].audio = aud;
        MemoryBarrier();                             // publish fields before the count
        s_callerModCount = m + 1;
    }
    LeaveCriticalSection(&s_heapUseCS);
    return gfx;
}

// Audio counterpart of CallerIsGraphicsModule.  Reuses the SAME per-module cache —
// CallerIsGraphicsModule's resolver records both the gfx and audio flags in one pass —
// so a miss here just triggers that resolve and re-scans.
static bool CallerIsAudioModule(void* ra) {
    if (!ra || !s_diagCSInit) return false;
    const UINT_PTR a = (UINT_PTR)ra;
    LONG n = s_callerModCount;                       // lock-free fast path (append-only)
    for (LONG i = 0; i < n; ++i)
        if (a >= s_callerMods[i].base && a < s_callerMods[i].end) return s_callerMods[i].audio;
    CallerIsGraphicsModule(ra);                      // resolve+cache both flags for this module
    n = s_callerModCount;
    for (LONG i = 0; i < n; ++i)
        if (a >= s_callerMods[i].base && a < s_callerMods[i].end) return s_callerMods[i].audio;
    return false;
}

// Thread-local cache of the last heap touched — the common case is a run of allocs
// into the same heap, so this skips the scan and keeps the >=0 hot path near-free.
static thread_local UINT_PTR t_lastHeapHandle = 0;
static thread_local int      t_lastHeapSlot   = -1;

// Observe EVERY allocation by heap (>=0).  Called on the hot path, so: TL-cached
// slot + two interlocked adds on a hit; lock + caller-classify only the first time
// a heap is seen.  64-bit counters are interlocked (non-atomic 64-bit writes tear
// on a 32-bit process).
// Returns true if this heap is a corral target (route its allocs to the arena).
static bool RecordHeapUse(PVOID heap, SIZE_T size, void* retAddr) {
    if (!heap || !s_diagCSInit) return false;
    const UINT_PTR h = (UINT_PTR)heap;

    if (h == t_lastHeapHandle && t_lastHeapSlot >= 0) {
        InterlockedIncrement64(&s_heapUse[t_lastHeapSlot].count);
        InterlockedAdd64(&s_heapUse[t_lastHeapSlot].bytes, (LONG64)size);
        return s_heapUse[t_lastHeapSlot].corralTarget;
    }

    LONG n = s_heapUseCount;                 // volatile read of append-only table
    for (LONG i = 0; i < n; ++i) {
        if (s_heapUse[i].handle == h) {
            t_lastHeapHandle = h; t_lastHeapSlot = (int)i;
            InterlockedIncrement64(&s_heapUse[i].count);
            InterlockedAdd64(&s_heapUse[i].bytes, (LONG64)size);
            return s_heapUse[i].corralTarget;
        }
    }

    // First sighting — insert under lock (rare); classify the caller once.
    int idx = -1;
    EnterCriticalSection(&s_heapUseCS);
    n = s_heapUseCount;
    for (LONG i = 0; i < n; ++i) if (s_heapUse[i].handle == h) { idx = (int)i; break; }
    if (idx < 0 && n < kHeapUseMax) {
        idx = (int)n;
        s_heapUse[idx].handle = h;
        s_heapUse[idx].count  = 0;
        s_heapUse[idx].bytes  = 0;
        char m[40] = {};
        HMODULE mod = nullptr;
        if (retAddr &&
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)retAddr, &mod) && mod) {
            GetModuleBaseNameA(GetCurrentProcess(), mod, m, sizeof(m));
        }
        strncpy_s(s_heapUse[idx].module, m[0] ? m : "<?>", _TRUNCATE);
        s_heapUse[idx].corralTarget   = IsCorralModule(s_heapUse[idx].module);
        s_heapUse[idx].sardineExclude = IsGraphicsModule(s_heapUse[idx].module) ||
                                        IsAudioModule(s_heapUse[idx].module);
        MemoryBarrier();
        s_heapUseCount = n + 1;              // publish only after fields are set
    }
    LeaveCriticalSection(&s_heapUseCS);

    if (idx >= 0) {
        t_lastHeapHandle = h; t_lastHeapSlot = idx;
        InterlockedIncrement64(&s_heapUse[idx].count);
        InterlockedAdd64(&s_heapUse[idx].bytes, (LONG64)size);
        return s_heapUse[idx].corralTarget;
    }
    return false;
}

// True if this heap is owned by a graphics-driver module (classified on first sighting
// in RecordHeapUse, which the sardine gate always calls just before this).  Reuses the
// per-thread last-heap cache so the check is near-free on the hot path; falls back to a
// scan of the append-only table.  Default false (capture) for never-before-seen heaps.
static bool HeapIsSardineExcluded(PVOID heap) {
    if (!heap || !s_diagCSInit) return false;
    const UINT_PTR h = (UINT_PTR)heap;
    if (h == t_lastHeapHandle && t_lastHeapSlot >= 0)
        return s_heapUse[t_lastHeapSlot].sardineExclude;
    LONG n = s_heapUseCount;
    for (LONG i = 0; i < n; ++i)
        if (s_heapUse[i].handle == h) return s_heapUse[i].sardineExclude;
    return false;
}

void DumpHeapUsage() {
    Logger* log = Logger::GetInstance();
    if (!log || !s_diagCSInit) return;
    EnterCriticalSection(&s_heapUseCS);
    LONG n = s_heapUseCount;
    log->NamedInfo("HEAP_USAGE", "=== %ld heap(s) receiving large allocations ===", n);
    for (LONG i = 0; i < n; ++i) {
        log->NamedInfo("HEAP_USAGE",
            "  heap=0x%08IX  allocs=%lld  bytes=%lld MB  first_caller=%s",
            s_heapUse[i].handle, (long long)s_heapUse[i].count,
            (long long)(s_heapUse[i].bytes / (1024 * 1024)), s_heapUse[i].module);
    }
    LeaveCriticalSection(&s_heapUseCS);
}

static void RemoveDiagnosticAlloc(void* address, void* freeRetAddr = nullptr) {
    if (!address || !s_diagCSInit) return;
    const UINT_PTR key = (UINT_PTR)address;
    DiagnosticAllocRecord rec = {};
    bool found = false;
    EnterCriticalSection(&s_diagCS);
    LONG n = s_diagCount;
    for (LONG i = 0; i < n; i++) {
        if (s_diagRecords[i].address == key) {
            rec = s_diagRecords[i];
            found = true;
            LONG last = n - 1;
            if (i != last) s_diagRecords[i] = s_diagRecords[last];
            s_diagRecords[last].address = 0;
            InterlockedExchange(&s_diagCount, last);
            break;
        }
    }
    LeaveCriticalSection(&s_diagCS);

    if (!found) return;

    // Provenance: who freed it (module+offset), resolved without symbol services,
    // plus who allocated it and how long it lived.  EmergencyLogF is hook-safe.
    char freeMod[64] = "<unknown>";
    UINT_PTR freeOff = 0;
    HMODULE m = nullptr;
    if (freeRetAddr &&
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)freeRetAddr, &m) && m) {
        GetModuleBaseNameA(GetCurrentProcess(), m, freeMod, sizeof(freeMod));
        MODULEINFO mi = {};
        if (GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof(mi)))
            freeOff = (UINT_PTR)freeRetAddr - (UINT_PTR)mi.lpBaseOfDll;
    }
    EmergencyLogF("PROVENANCE",
        "FREED addr=0x%08IX size=%u KB | alloc_by=%s ret=%p | freed_by=%s+0x%IX ret=%p | lifetime_ms=%lu",
        key, (unsigned)(rec.size / 1024),
        rec.moduleName, rec.retAddr, freeMod, freeOff, freeRetAddr,
        (unsigned long)(GetTickCount() - rec.allocTick));
}

static void VatTrack(UINT_PTR addr, SIZE_T size) {
    EnterCriticalSection(&s_vatCS);
    if (s_vatCount < kVatMax) {
        LONG slot = s_vatCount;
        s_vatAddr[slot] = addr;
        s_vatSize[slot] = size;
        s_vatCount = slot + 1;
    }
    LeaveCriticalSection(&s_vatCS);
}

// Returns true and populates outSize if addr was tracked; removes it.
static bool VatUntrack(UINT_PTR addr, SIZE_T* outSize) {
    EnterCriticalSection(&s_vatCS);
    LONG n = s_vatCount < kVatMax ? s_vatCount : kVatMax;
    for (LONG i = 0; i < n; i++) {
        if (s_vatAddr[i] == addr) {
            if (outSize) *outSize = s_vatSize[i];
            LONG last = n - 1;
            if (i != last) { s_vatAddr[i] = s_vatAddr[last]; s_vatSize[i] = s_vatSize[last]; }
            s_vatAddr[last] = 0; s_vatSize[last] = 0;
            InterlockedDecrement(&s_vatCount);
            LeaveCriticalSection(&s_vatCS);
            return true;
        }
    }
    LeaveCriticalSection(&s_vatCS);
    return false;
}

static MemoryManager* s_memManager = nullptr;
static const SIZE_T HEAP_CAPTURE_THRESHOLD = 64 * 1024;
static volatile LONG64 s_heapFreeOkCount = 0;
static volatile LONG64 s_lastDbpfMapTickMs = 0;
static const ULONGLONG kGraphicsProxyWindowMs = 3000;
static volatile LONG s_policyModeInit = 0;
static volatile LONG s_policyMode = 0; // 0=default, 1=strict render-local-only
static volatile LONG s_forceProxyInit = 0;
static volatile LONG s_forceProxy = 0; // 0=off, 1=on
static volatile LONG s_forceHeapProxyInit = 0;
static volatile LONG s_forceHeapProxy = 0; // 0=off, 1=on
// Heap proxy floor (force mode): allocations >= this go to the proxy.  Pushed to the
// 4 KB page floor (matching VirtualAlloc) to capture as much of the small/mid churn
// as possible now that we know the callers; env TS3VAS_PROXY_HEAP_MIN_KB tunes it
// (set in Install()).  Upper bound is the proxy's own GetProxyMaxBytes() (default 4 MB).
// Below 4 KB is sub-page — not worth a 64 KB arena slot per alloc.
static SIZE_T kForceHeapProxyMinSize = 4 * 1024;
static const SIZE_T kForceVirtualAllocMinSize = 4 * 1024; // page-sized VirtualAlloc floor
// TLS slot shared across all TUs — declared extern in WorkingHooks.h.
// Must be defined exactly once here. TlsAlloc() sets it in Install().
DWORD s_tlsIndex = TLS_OUT_OF_INDEXES;

static volatile LONG s_proxyActive = 0;
static volatile LONG s_shuttingDown = 0;
static volatile LONG s_activeHookCalls = 0;
static volatile LONG s_apiEtwCfgInit = 0;
static volatile LONG s_apiEtwVerboseNoisy = 0;
static volatile LONG s_apiEtwNoisySampleMask = 0x7FF; // default ~1/2048
static volatile LONG s_apiEtwVqTick = 0;
static volatile LONG s_apiEtwVqExTick = 0;
static volatile LONG s_apiEtwHeapSizeTick = 0;
static const USHORT kCallerStackDepth = 32;

enum class AllocCallerKind {
    GameExe,
    Graphics,
    RuntimeDll,
    SystemDll,
    ModDll,
    Unknown
};

struct RtlAllocReportStats {
    volatile LONG64 totalLargeAllocs;
    volatile LONG64 gameExeAllocs;
    volatile LONG64 graphicsAllocs;
    volatile LONG64 runtimeDllAllocs;
    volatile LONG64 systemDllAllocs;
    volatile LONG64 modDllAllocs;
    volatile LONG64 unknownAllocs;
    volatile LONG64 proxyCandidates;
    volatile LONG64 skippedRuntimeDll;
    volatile LONG64 skippedGraphics;
    volatile LONG64 skippedSystemDll;
    volatile LONG64 skippedModDll;
    volatile LONG64 skippedUnknown;
    volatile LONG64 captured;
    volatile LONG64 captureFailed;
    volatile LONG64 observedBeforeActive;
    volatile LONG64 bytesGameExe;
    volatile LONG64 bytesGraphics;
    volatile LONG64 bytesRuntimeDll;
    volatile LONG64 bytesSystemDll;
    volatile LONG64 bytesModDll;
    volatile LONG64 bytesUnknown;
};

static RtlAllocReportStats s_allocReport = {};
static LONG s_proxyGrantLogCfgInit = 0;
static LONG s_proxyGrantVerbose = 0;
static DWORD s_proxyGrantTallyMs = 5000;
static volatile LONG64 s_proxyGrantCount = 0;
static volatile LONG64 s_proxyGrantBytes = 0;
static volatile LONG64 s_proxyGrantCountSnap = 0;
static volatile LONG64 s_proxyGrantBytesSnap = 0;
static volatile LONG s_proxyGrantLastTick = 0;
struct LocalVasSourceStats {
    volatile LONG64 reserveCalls;
    volatile LONG64 reserveBytes;
    volatile LONG64 reserveFailedCalls;
    volatile LONG64 reserveFailedBytes;
    volatile LONG64 byGraphicsBytes;
    volatile LONG64 byRuntimeBytes;
    volatile LONG64 byGameBytes;
    volatile LONG64 bySystemBytes;
    volatile LONG64 byModBytes;
    volatile LONG64 byUnknownBytes;
};
static LocalVasSourceStats s_localVasStats = {};

struct LocalVasCallerStat {
    volatile LONG_PTR addr;
    volatile LONG64 calls;
    volatile LONG64 bytes;
};
static const int kLocalVasCallerSlots = 64;
static LocalVasCallerStat s_localVasCallers[kLocalVasCallerSlots] = {};
static volatile LONG s_rangeLogInit = 0;
static volatile LONG s_rangeLogEnabled = 0;
static UINT_PTR s_rangeLogStart = 0;
static UINT_PTR s_rangeLogEnd = 0;

static void InitRangeLogConfig() {
    if (InterlockedCompareExchange(&s_rangeLogInit, 1, 0) != 0)
        return;

    char en[32] = {};
    GetEnvironmentVariableA("TS3VAS_RANGE_LOG_ENABLE", en, sizeof(en));
    if (!(en[0] == '1' || en[0] == 'y' || en[0] == 'Y' || en[0] == 't' || en[0] == 'T'))
        return;

    char s0[64] = {};
    char s1[64] = {};
    GetEnvironmentVariableA("TS3VAS_RANGE_LOG_START", s0, sizeof(s0));
    GetEnvironmentVariableA("TS3VAS_RANGE_LOG_END", s1, sizeof(s1));
    if (!s0[0] || !s1[0])
        return;

    char* e0 = nullptr;
    char* e1 = nullptr;
    unsigned long long a = strtoull(s0, &e0, 0);
    unsigned long long b = strtoull(s1, &e1, 0);
    if (!e0 || !e1 || e0 == s0 || e1 == s1 || a >= b)
        return;

    s_rangeLogStart = (UINT_PTR)a;
    s_rangeLogEnd = (UINT_PTR)b;
    InterlockedExchange(&s_rangeLogEnabled, 1);
}

static bool ShouldLogRangeHit(AllocCallerKind kind, UINT_PTR base, SIZE_T size) {
    if (InterlockedCompareExchange(&s_rangeLogEnabled, 0, 0) == 0)
        return false;
    if (!(kind == AllocCallerKind::GameExe || kind == AllocCallerKind::SystemDll))
        return false;
    if (size == 0)
        return false;

    UINT_PTR start = s_rangeLogStart;
    UINT_PTR end = s_rangeLogEnd;
    UINT_PTR allocEnd = base + size;
    return (base < end) && (allocEnd > start);
}

static void InitProxyGrantLogCfg() {
    if (InterlockedCompareExchange(&s_proxyGrantLogCfgInit, 1, 0) != 0)
        return;
    char buf[32] = {};
    DWORD n = GetEnvironmentVariableA("TS3VAS_VERBOSE_PROXY_GRANTED_LOGS", buf, (DWORD)sizeof(buf));
    if (n > 0 && n < sizeof(buf) && (buf[0] == '1' || buf[0] == 'y' || buf[0] == 'Y' || buf[0] == 't' || buf[0] == 'T'))
        s_proxyGrantVerbose = 1;
    ZeroMemory(buf, sizeof(buf));
    n = GetEnvironmentVariableA("TS3VAS_PROXY_GRANTED_TALLY_MS", buf, (DWORD)sizeof(buf));
    if (n > 0 && n < sizeof(buf)) {
        long v = strtol(buf, nullptr, 10);
        if (v >= 250) s_proxyGrantTallyMs = (DWORD)v;
    }
}

static void MaybeLogProxyGrantTally() {
    Logger* log = Logger::GetInstance();
    if (!log) return;
    DWORD now = GetTickCount();
    LONG last = s_proxyGrantLastTick;
    if ((DWORD)(now - (DWORD)last) < s_proxyGrantTallyMs) return;
    if (InterlockedCompareExchange(&s_proxyGrantLastTick, (LONG)now, last) != last) return;

    const LONG64 totalCnt = s_proxyGrantCount;
    const LONG64 totalBytes = s_proxyGrantBytes;
    const LONG64 dCnt = totalCnt - s_proxyGrantCountSnap;
    const LONG64 dBytes = totalBytes - s_proxyGrantBytesSnap;
    s_proxyGrantCountSnap = totalCnt;
    s_proxyGrantBytesSnap = totalBytes;

    log->Info("[PROXY] Granted tally: +%lld allocs +%llu MB | total=%lld allocs %llu MB",
        dCnt, (unsigned long long)(dBytes / (1024 * 1024)),
        totalCnt, (unsigned long long)(totalBytes / (1024 * 1024)));
}

void WorkingHooks::ActivateProxy() { InterlockedExchange(&s_proxyActive, 1); }
bool WorkingHooks::IsProxyActive()  { return InterlockedCompareExchange(&s_proxyActive, 0, 0) == 1; }
bool WorkingHooks::IsShuttingDown() { return InterlockedCompareExchange(&s_shuttingDown, 0, 0) != 0; }

void WorkingHooks::BeginShutdown() {
    LONG was = InterlockedExchange(&s_shuttingDown, 1);
    EmergencyLogF("WorkingHooks_BeginShutdown", "was=%ld activeHookCalls=%ld proxyActive=%ld",
        was, InterlockedCompareExchange(&s_activeHookCalls, 0, 0),
        InterlockedCompareExchange(&s_proxyActive, 0, 0));
}

static void InitApiEtwConfig() {
    if (InterlockedCompareExchange(&s_apiEtwCfgInit, 1, 0) != 0)
        return;

    char noisy[32] = {};
    DWORD nNoisy = GetEnvironmentVariableA("TS3VAS_ETW_VERBOSE_NOISY_API", noisy, (DWORD)sizeof(noisy));
    LONG verboseNoisy = 0;
    if (nNoisy > 0) {
        if (!(noisy[0] == '0' || noisy[0] == 'f' || noisy[0] == 'F' ||
              noisy[0] == 'n' || noisy[0] == 'N')) {
            verboseNoisy = 1;
        }
    }
    InterlockedExchange(&s_apiEtwVerboseNoisy, verboseNoisy);

    char samplePow2[32] = {};
    DWORD nPow2 = GetEnvironmentVariableA("TS3VAS_ETW_NOISY_SAMPLE_POW2", samplePow2, (DWORD)sizeof(samplePow2));
    LONG pow2 = 11; // 1/2048 default
    if (nPow2 > 0) {
        LONG v = strtol(samplePow2, nullptr, 10);
        if (v >= 1 && v <= 20)
            pow2 = v;
    }
    InterlockedExchange(&s_apiEtwNoisySampleMask, (1L << pow2) - 1L);
}

static bool ShouldEmitNoisySample(volatile LONG* counter) {
    const LONG mask = InterlockedCompareExchange(&s_apiEtwNoisySampleMask, 0, 0);
    const LONG tick = InterlockedIncrement(counter);
    return (tick & mask) == 0;
}

static bool ShouldEmitApiHookEvent(const char* api, bool failed) {
    if (failed)
        return true;
    InitApiEtwConfig();
    if (InterlockedCompareExchange(&s_apiEtwVerboseNoisy, 0, 0) != 0)
        return true;
    if (!api)
        return true;

    if (_stricmp(api, "VirtualQuery") == 0)
        return ShouldEmitNoisySample(&s_apiEtwVqTick);
    if (_stricmp(api, "VirtualQueryEx") == 0)
        return ShouldEmitNoisySample(&s_apiEtwVqExTick);
    if (_stricmp(api, "HeapSize") == 0)
        return ShouldEmitNoisySample(&s_apiEtwHeapSizeTick);
    return true;
}

static inline void EmitApiHookWin32(const char* api,
                                    UINT64 a0, UINT64 a1, UINT64 a2, UINT64 a3,
                                    UINT64 result, BOOL ok,
                                    UINT8 source = 0) {
    const DWORD postCallGle = GetLastError();
    const bool failed = !ok;
    if (ShouldEmitApiHookEvent(api, failed)) {
        const DWORD etwStatus = failed ? postCallGle : 0;
        TS3VASEtw::EmitApiHookCall(api, a0, a1, a2, a3, result, (UINT32)etwStatus, source);
    }
    SetLastError(postCallGle);
}

static inline void EmitApiHookWin32Size(const char* api,
                                        UINT64 a0, UINT64 a1, UINT64 a2, UINT64 a3,
                                        UINT64 result, bool failed,
                                        UINT8 source = 0) {
    const DWORD postCallGle = GetLastError();
    if (ShouldEmitApiHookEvent(api, failed)) {
        const DWORD etwStatus = failed ? postCallGle : 0;
        TS3VASEtw::EmitApiHookCall(api, a0, a1, a2, a3, result, (UINT32)etwStatus, source);
    }
    SetLastError(postCallGle);
}

static inline void EmitApiHookNt(const char* api,
                                 UINT64 a0, UINT64 a1, UINT64 a2, UINT64 a3,
                                 UINT64 result, NTSTATUS status,
                                 UINT8 source = 2) {
    TS3VASEtw::EmitApiHookCall(api, a0, a1, a2, a3, result, (UINT32)status, source);
}

static bool StringContainsI(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;
    size_t needleLen = lstrlenA(needle);
    if (needleLen == 0) return true;

    for (const char* p = haystack; *p; ++p) {
        size_t i = 0;
        while (i < needleLen && p[i]) {
            char a = p[i];
            char b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
            ++i;
        }
        if (i == needleLen) return true;
    }
    return false;
}

static AllocCallerKind ClassifyCallerModule(void* returnAddress, char* moduleName, size_t moduleNameBytes)
{
    if (moduleName && moduleNameBytes > 0)
        moduleName[0] = '\0';

    if (!returnAddress)
        return AllocCallerKind::Unknown;

    void* stack[kCallerStackDepth] = {};
    USHORT frames = RtlCaptureStackBackTrace(1, kCallerStackDepth, stack, nullptr);

    for (USHORT i = 0; i < frames; ++i) {
        if (!stack[i]) break;

        HMODULE module = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            static_cast<LPCSTR>(stack[i]), &module) || !module)
            continue;

        char path[MAX_PATH] = {};
        if (!GetModuleFileNameA(module, path, MAX_PATH))
            continue;

        const char* base = strrchr(path, '\\');
        base = base ? base + 1 : path;

        if (moduleName && moduleNameBytes > 0)
            strcpy_s(moduleName, moduleNameBytes, base);

        // ── Game Executable ─────────────────────────────────────
        if (StringContainsI(base, "TS3W.exe") ||
            StringContainsI(base, "TS3.exe")  ||
            StringContainsI(base, "Game_Win32.exe"))
            return AllocCallerKind::GameExe;

        // ── Runtime Libraries ───────────────────────────────────
        if (StringContainsI(base, "msvcr") || StringContainsI(base, "msvcp") ||
            StringContainsI(base, "vcruntime") || StringContainsI(base, "ucrtbase"))
            return AllocCallerKind::RuntimeDll;

        // ── Skip our own hook module ────────────────────────────
        if (StringContainsI(base, "TS3VASManager"))
            continue;

        // ── Other Mods / ASI plugins ────────────────────────────
        if (StringContainsI(base, ".asi"))
            return AllocCallerKind::ModDll;

        // ── Graphics Drivers (skip proxying) ────────────────────
        // Single source of truth shared with the sardine-exclusion gate.
        if (IsGraphicsModule(base))
            return AllocCallerKind::Graphics;
    }

    return AllocCallerKind::SystemDll;
}

// Placed after ClassifyCallerModule so it is in scope.  Resolves and stores the
// caller module name at allocation time.
static void RegisterDiagnosticAlloc(void* address, SIZE_T size, void* retAddr) {
    if (!address || size == 0 || !s_diagCSInit) return;
    char modName[64] = {};
    ClassifyCallerModule(retAddr, modName, sizeof(modName));
    if (!modName[0]) strcpy_s(modName, "<unknown>");

    EnterCriticalSection(&s_diagCS);
    if (s_diagCount < kDiagMax) {
        LONG slot = s_diagCount;
        s_diagRecords[slot].address   = (UINT_PTR)address;
        s_diagRecords[slot].size      = size;
        s_diagRecords[slot].retAddr   = retAddr;
        s_diagRecords[slot].allocTick = GetTickCount();
        strcpy_s(s_diagRecords[slot].moduleName, modName);
        InterlockedExchange(&s_diagCount, slot + 1);
    }
    LeaveCriticalSection(&s_diagCS);
}

enum class VaCallKind {
    ReserveOnly,
    CommitOnly,
    ReserveCommit
};

static const char* VaCallerBucketTag(AllocCallerKind kind, bool isSelf) {
    if (isSelf) return "Self";
    switch (kind) {
    case AllocCallerKind::GameExe:    return "Game";
    case AllocCallerKind::Graphics:   return "Graphics";
    case AllocCallerKind::RuntimeDll: return "Runtime";
    case AllocCallerKind::SystemDll:  return "System";
    case AllocCallerKind::ModDll:     return "Mod";
    default:                          return "Unknown";
    }
}

static bool IsExecProtect(DWORD protect) {
    return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool IsSelfOnCurrentStack() {
    void* stack[kCallerStackDepth] = {};
    const USHORT frames = RtlCaptureStackBackTrace(1, kCallerStackDepth, stack, nullptr);
    int leadingSelfFrames = 0;
    bool sawNonSelf = false;
    for (USHORT i = 0; i < frames; ++i) {
        if (!stack[i]) break;
        HMODULE module = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                static_cast<LPCSTR>(stack[i]), &module) || !module) {
            continue;
        }
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameA(module, path, MAX_PATH))
            continue;
        const char* base = strrchr(path, '\\');
        base = base ? base + 1 : path;
        const bool isSelf = StringContainsI(base, "TS3VASManager");
        if (!sawNonSelf) {
            if (isSelf) {
                ++leadingSelfFrames;
                continue;
            }
            sawNonSelf = true;
        }
        // If TS3VASManager reappears below the initial hook frames, treat as self-origin.
        if (isSelf && sawNonSelf)
            return true;
    }
    // Normal external calls have the hook stack only (Record + Hooked).
    // Three or more leading TS3VASManager frames means likely self-origin.
    return leadingSelfFrames >= 3;
}

static void RecordVaMixCounters(SIZE_T size, DWORD allocType, DWORD protect) {
    Analytics* a = Analytics::GetInstance();
    if (!a || size == 0) return;

    a->IncrementCounter("VAS_VA_Call_Total");

    const bool hasReserve = (allocType & MEM_RESERVE) != 0;
    const bool hasCommit = (allocType & MEM_COMMIT) != 0;

    VaCallKind callKind = VaCallKind::ReserveCommit;
    const char* countName = "VAS_VA_ReserveCommit_Count";
    const char* bytesName = "VAS_VA_Bytes_ReserveCommit";
    if (hasReserve && !hasCommit) {
        callKind = VaCallKind::ReserveOnly;
        countName = "VAS_VA_ReserveOnly_Count";
        bytesName = "VAS_VA_Bytes_ReserveOnly";
    } else if (hasCommit && !hasReserve) {
        callKind = VaCallKind::CommitOnly;
        countName = "VAS_VA_CommitOnly_Count";
        bytesName = "VAS_VA_Bytes_CommitOnly";
    }
    a->IncrementCounter(countName);
    a->IncrementCounter(bytesName, (uint64_t)size);

    char moduleName[MAX_PATH] = {};
    const bool isSelf = IsSelfOnCurrentStack();
    AllocCallerKind callerKind = ClassifyCallerModule(_ReturnAddress(), moduleName, sizeof(moduleName));
    const char* bucket = VaCallerBucketTag(callerKind, isSelf);

    char bucketCount[96] = {};
    char bucketBytes[96] = {};
    const char* prefix = (callKind == VaCallKind::ReserveOnly)
        ? "VAS_VA_ReserveOnly"
        : (callKind == VaCallKind::CommitOnly ? "VAS_VA_CommitOnly" : "VAS_VA_ReserveCommit");
    sprintf_s(bucketCount, "%s_%s_Count", prefix, bucket);
    sprintf_s(bucketBytes, "%s_%s_Bytes", prefix, bucket);
    a->IncrementCounter(bucketCount);
    a->IncrementCounter(bucketBytes, (uint64_t)size);

    if (IsExecProtect(protect)) {
        a->IncrementCounter("VAS_VA_ExecProtect_Count");
        a->IncrementCounter("VAS_VA_ExecProtect_Bytes", (uint64_t)size);
        char execBucketCount[96] = {};
        char execBucketBytes[96] = {};
        sprintf_s(execBucketCount, "VAS_VA_ExecProtect_%s_Count", bucket);
        sprintf_s(execBucketBytes, "VAS_VA_ExecProtect_%s_Bytes", bucket);
        a->IncrementCounter(execBucketCount);
        a->IncrementCounter(execBucketBytes, (uint64_t)size);
    }
}

static void LogRoGameContext(const char* api, void* requestedBase, SIZE_T size,
                             DWORD allocType, DWORD protect,
                             bool redirectEligible, bool redirected)
{
    if (!api) return;
    if (!(allocType & MEM_RESERVE) || (allocType & MEM_COMMIT)) return;
    if (size < kForceVirtualAllocMinSize) return;

    const bool isSelf = IsSelfOnCurrentStack();
    char moduleName[MAX_PATH] = {};
    AllocCallerKind callerKind = ClassifyCallerModule(_ReturnAddress(), moduleName, sizeof(moduleName));
    if (isSelf || callerKind != AllocCallerKind::GameExe) return;

    Logger* log = Logger::GetInstance();
    if (!log) return;
    log->NamedInfo("VAS_REPORT",
        "RO_GameCtx api=%s base=%p size=%zu KB type=0x%X prot=0x%X eligible=%d redirected=%d proxy_active=%d",
        api,
        requestedBase,
        (size_t)(size / 1024),
        allocType,
        protect,
        redirectEligible ? 1 : 0,
        redirected ? 1 : 0,
        WorkingHooks::IsProxyActive() ? 1 : 0);
}

static bool IsProxyCandidate(AllocCallerKind kind) {
    return kind == AllocCallerKind::GameExe ||
        kind == AllocCallerKind::Graphics ||
        kind == AllocCallerKind::RuntimeDll ||
        kind == AllocCallerKind::SystemDll  ||
        kind == AllocCallerKind::ModDll;
}

#pragma pack(push, 1)
struct DbpfHeaderMV {
    char     magic[4];
    uint32_t majorVersion;
    uint32_t minorVersion;
    uint8_t  pad1[12];
    uint32_t dateCreated;
    uint32_t dateModified;
    uint32_t pad2;
    uint32_t indexEntryCount;
    uint32_t pad3;
    uint32_t indexSizeBytes;
    uint8_t  pad4[12];
    uint32_t indexOffset;
};

struct DbpfIndexEntryMV {
    uint32_t typeId;
    uint32_t groupId;
    uint32_t instanceHigh;
    uint32_t instanceLow;
    uint32_t chunkOffset;
    uint32_t diskSize;
    uint32_t memSize;
    uint16_t compressionType;
    uint16_t committed;
};
#pragma pack(pop)

static uint32_t ScanDbpfIndex(const void* viewBase, SIZE_T viewSize,
                              DbpfTypeStats* outStats, uint32_t outCap)
{
    if (!viewBase || !outStats || outCap == 0 || viewSize < sizeof(DbpfHeaderMV))
        return 0;

    const auto* hdr = static_cast<const DbpfHeaderMV*>(viewBase);
    if (memcmp(hdr->magic, "DBPF", 4) != 0 || hdr->majorVersion != 2)
        return 0;

    uint32_t indexOffset = hdr->indexOffset;
    uint32_t entryCount  = hdr->indexEntryCount;
    if (indexOffset == 0 || entryCount == 0 || indexOffset >= (uint32_t)viewSize)
        return 0;

    SIZE_T maxEntries = (viewSize - indexOffset) / sizeof(DbpfIndexEntryMV);
    if (entryCount > (uint32_t)maxEntries)
        entryCount = (uint32_t)maxEntries;
    if (entryCount == 0)
        return 0;

    const auto* entries = reinterpret_cast<const DbpfIndexEntryMV*>(
        static_cast<const uint8_t*>(viewBase) + indexOffset);

    uint32_t used = 0;
    for (uint32_t i = 0; i < entryCount; ++i) {
        const uint32_t t = entries[i].typeId;
        const uint32_t s = entries[i].memSize;

        uint32_t slot = 0;
        bool found = false;
        for (; slot < used; ++slot) {
            if (outStats[slot].typeId == t) {
                found = true;
                break;
            }
        }

        if (!found) {
            if (used >= outCap)
                continue;
            slot = used++;
            outStats[slot].typeId = t;
            outStats[slot].entryCount = 0;
            outStats[slot].totalMemBytes = 0;
        }

        outStats[slot].entryCount += 1;
        outStats[slot].totalMemBytes += (uint64_t)s;
    }
    return used;
}

// SEH-guarded wrapper around ScanDbpfIndex.  The Win32-level MapViewOfFile
// hooks fire SCRIPT_PROBE on whole-file mappings (dwNumberOfBytesToMap == 0)
// whose backing file may be shorter than the rounded section size; touching
// pages past EOF raises EXCEPTION_IN_PAGE_ERROR.  Isolate the scan in a
// C-style frame (no C++ unwinding) so a faulting view degrades to "0 types"
// rather than crashing the game.  Mirrors the SafeMapViewCopy pattern.
static uint32_t SafeScanDbpfIndex(const void* viewBase, SIZE_T viewSize,
                                  DbpfTypeStats* outStats, uint32_t outCap)
{
    __try {
        return ScanDbpfIndex(viewBase, viewSize, outStats, outCap);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// ── Script-resource detection ──────────────────────────────────────────────────
// CORRECTED type IDs from EA's DeltaPackages/*.cfg FileType table:
//   0x0175e5cd = script (compiled .NET script)      <- the real script type
//   0x0175e5d9 = scriptsym (script debug symbols)
//   0x073faa07 = modder script archive (S3SA; NRaas et al.)
//   0x0333406c = xml  (tuning)  <- previously MISLABELED here as "S3SA"
// We were only ever matching 0x0333406C, i.e. detecting XML tuning, never actual
// scripts.  Now we detect the real script types and log a named breakdown of the
// package's script/tuning resources (reusing typeStats; no second view scan).
// Observe/logging only — does not change lane routing.
static const uint32_t kDbpfTypeScript    = 0x0175e5cdu;
static const uint32_t kDbpfTypeScriptSym = 0x0175e5d9u;
static const uint32_t kDbpfTypeS3SAMod   = 0x073faa07u;
static const uint32_t kDbpfTypeXml       = 0x0333406cu;

static bool TypeStatsHaveScript(const DbpfTypeStats* typeStats, uint32_t count) {
    if (!typeStats) return false;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t t = typeStats[i].typeId;
        if (t == kDbpfTypeScript || t == kDbpfTypeScriptSym || t == kDbpfTypeS3SAMod)
            return true;
    }
    return false;
}

static void ProbeScriptAssembly(const DbpfTypeStats* typeStats, uint32_t count,
                                const void* view, SIZE_T size, void* callerRet)
{
    if (!TypeStatsHaveScript(typeStats, count)) return;   // cheap common-path bail

    // Resolve the package name lazily — only when a script resource is present.
    char devName[MAX_PATH * 2] = {};
    const char* base = "<unnamed>";
    bool named = false;
    if (view && GetMappedFileNameA(GetCurrentProcess(), (LPVOID)view,
                                   devName, sizeof(devName)) && devName[0]) {
        const char* slash = strrchr(devName, '\\');
        base = slash ? slash + 1 : devName;
        named = true;
    }

    // Single-report dedup shared with the ReadFile path: count each package's script
    // resources exactly once, whichever load path (map-view here, or ReadFile) sees it
    // first.  Skip dedup for unnamed views (can't key them) so they still report.
    if (named && ScriptScanDedup::MarkOnce(ScriptScanDedup::KeyFromBaseNameA(base)))
        return;

    // Tally the script/tuning resource types present (names from EA cfg table).
    uint32_t scrCount = 0, symCount = 0, modCount = 0, xmlCount = 0;
    uint64_t scrBytes = 0, xmlBytes = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t t = typeStats[i].typeId;
        if (t == kDbpfTypeScript)         { scrCount += typeStats[i].entryCount; scrBytes += typeStats[i].totalMemBytes; }
        else if (t == kDbpfTypeScriptSym) { symCount += typeStats[i].entryCount; }
        else if (t == kDbpfTypeS3SAMod)   { modCount += typeStats[i].entryCount; scrBytes += typeStats[i].totalMemBytes; }
        else if (t == kDbpfTypeXml)       { xmlCount += typeStats[i].entryCount; xmlBytes += typeStats[i].totalMemBytes; }
    }

    Logger* log = Logger::GetInstance();
    if (log)
        log->NamedInfo("SCRIPT_HIGHWAY",
            "script load: package=%s view=%p map=%zu KB | script=%u (%llu KB) scriptsym=%u s3sa_mod=%u | xml/tuning=%u (%llu KB) | ret=%p",
            base, view, size / 1024,
            scrCount, (unsigned long long)(scrBytes / 1024), symCount, modCount,
            xmlCount, (unsigned long long)(xmlBytes / 1024), callerRet);
    if (Analytics::GetInstance()) {
        Analytics::GetInstance()->IncrementCounter("Script_Packages");
        Analytics::GetInstance()->IncrementCounter("Script_Resources", (uint64_t)(scrCount + symCount + modCount));
        Analytics::GetInstance()->IncrementCounter("Script_Xml_Resources", (uint64_t)xmlCount);
    }
}

static bool IsDbpfMapContextRecent() {
    const LONG64 last = InterlockedCompareExchange64(&s_lastDbpfMapTickMs, 0, 0);
    if (last <= 0)
        return false;
    const ULONGLONG now = GetTickCount64();
    return now >= static_cast<ULONGLONG>(last) &&
           (now - static_cast<ULONGLONG>(last)) <= kGraphicsProxyWindowMs;
}

static bool IsStrictRenderLocalOnlyMode() {
    if (InterlockedCompareExchange(&s_policyModeInit, 1, 0) == 0) {
        char value[32] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_STRICT_RENDER_LOCAL_ONLY", value, (DWORD)sizeof(value));
        // Default OFF (relaxed): keep graphics eligible for proxy as before.
        LONG mode = 0;
        if (n > 0) {
            if (value[0] == '0' || value[0] == 'f' || value[0] == 'F' ||
                value[0] == 'n' || value[0] == 'N')
                mode = 0;
            else
                mode = 1;
        }
        InterlockedExchange(&s_policyMode, mode);
    }
    return InterlockedCompareExchange(&s_policyMode, 0, 0) == 1;
}

static bool IsForceProxyActiveMode() {
    if (InterlockedCompareExchange(&s_forceProxyInit, 1, 0) == 0) {
        char value[32] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_FORCE_PROXY_ACTIVE", value, (DWORD)sizeof(value));
        // Default ON: keep proxy enabled immediately for load/save stress.
        LONG mode = 1;
        if (n > 0) {
            if (value[0] == '0' || value[0] == 'f' || value[0] == 'F' ||
                value[0] == 'n' || value[0] == 'N')
                mode = 0;
            else
                mode = 1;
        }
        InterlockedExchange(&s_forceProxy, mode);
    }
    return InterlockedCompareExchange(&s_forceProxy, 0, 0) == 1;
}

static void EnsureProxyActiveForVirtualPath(SIZE_T size, DWORD allocType, DWORD protect) {
    if (WorkingHooks::IsProxyActive())
        return;
    if (!IsForceProxyActiveMode())
        return;
    if (!(allocType & MEM_RESERVE))
        return;
    if (size < kForceVirtualAllocMinSize)
        return;
    if (allocType & (MEM_PHYSICAL | MEM_LARGE_PAGES))
        return;
    if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        return;

    WorkingHooks::ActivateProxy();
    if (Logger::GetInstance()) {
        Logger::GetInstance()->Info(
            "[PROXY] Activated via VirtualAlloc/NtAllocate path (size=%zu type=0x%X prot=0x%X)",
            size, allocType, protect);
    }
}

static bool IsForceHeapProxyMode() {
    if (InterlockedCompareExchange(&s_forceHeapProxyInit, 1, 0) == 0) {
        char value[32] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_FORCE_PROXY_HEAP_ALL", value, (DWORD)sizeof(value));
        // Default ON for stress testing: force heap allocs through proxy.
        LONG mode = 1;
        if (n > 0) {
            if (value[0] == '0' || value[0] == 'f' || value[0] == 'F' ||
                value[0] == 'n' || value[0] == 'N')
                mode = 0;
            else
                mode = 1;
        }
        InterlockedExchange(&s_forceHeapProxy, mode);
    }
    return InterlockedCompareExchange(&s_forceHeapProxy, 0, 0) == 1;
}

static void Add64(volatile LONG64* target, SIZE_T value) {
    InterlockedAdd64(target, static_cast<LONGLONG>(value));
}

static void RecordCallerBucket(AllocCallerKind kind, SIZE_T size, const char* moduleName) {
    auto* a = Analytics::GetInstance();
    InterlockedIncrement64(&s_allocReport.totalLargeAllocs);

    switch (kind) {
    case AllocCallerKind::GameExe:
        InterlockedIncrement64(&s_allocReport.gameExeAllocs);
        Add64(&s_allocReport.bytesGameExe, size);
        if (a) a->IncrementCounter("RtlAlloc_ByModule_TS3W");
        break;

    case AllocCallerKind::Graphics:
        InterlockedIncrement64(&s_allocReport.graphicsAllocs);
        Add64(&s_allocReport.bytesGraphics, size);
        if (a) a->IncrementCounter("RtlAlloc_ByModule_Graphics");
        if (a && moduleName && StringContainsI(moduleName, "d3d9"))
            a->IncrementCounter("RtlAlloc_ByModule_d3d9");
        break;

    case AllocCallerKind::RuntimeDll:
        InterlockedIncrement64(&s_allocReport.runtimeDllAllocs);
        Add64(&s_allocReport.bytesRuntimeDll, size);
        if (a) a->IncrementCounter("RtlAlloc_ByModule_RuntimeDll");
        break;

    case AllocCallerKind::SystemDll:
        InterlockedIncrement64(&s_allocReport.systemDllAllocs);
        Add64(&s_allocReport.bytesSystemDll, size);
        if (a) a->IncrementCounter("RtlAlloc_ByModule_SystemDll");
        break;

    case AllocCallerKind::ModDll:
        InterlockedIncrement64(&s_allocReport.modDllAllocs);
        Add64(&s_allocReport.bytesModDll, size);
        if (a) a->IncrementCounter("RtlAlloc_ByModule_ModDll");
        break;

    default: // Unknown
        InterlockedIncrement64(&s_allocReport.unknownAllocs);
        Add64(&s_allocReport.bytesUnknown, size);
        InterlockedIncrement64(&s_allocReport.skippedUnknown);
        if (a) a->IncrementCounter("RtlAlloc_ByModule_unknown");
        if (a) a->IncrementCounter("RtlAlloc_ProxySkipped_Unknown");
        break;
    }

    if (IsProxyCandidate(kind)) {
        InterlockedIncrement64(&s_allocReport.proxyCandidates);
        if (a) a->IncrementCounter("RtlAlloc_ProxyCandidate");
    }
}

static LONGLONG Read64(volatile LONG64* value) {
    return InterlockedCompareExchange64(value, 0, 0);
}

static void TrackLocalVasCaller(void* callerAddr, SIZE_T size) {
    if (!callerAddr) return;
    LONG_PTR key = (LONG_PTR)callerAddr;
    int start = (int)((((UINT_PTR)callerAddr) >> 4) % kLocalVasCallerSlots);
    for (int i = 0; i < kLocalVasCallerSlots; ++i) {
        int idx = (start + i) % kLocalVasCallerSlots;
        LONG_PTR cur = (LONG_PTR)InterlockedCompareExchangePointer((PVOID volatile*)&s_localVasCallers[idx].addr, nullptr, nullptr);
        if (cur == key) {
            InterlockedIncrement64(&s_localVasCallers[idx].calls);
            InterlockedAdd64(&s_localVasCallers[idx].bytes, (LONGLONG)size);
            return;
        }
        if (cur == 0) {
            if (InterlockedCompareExchangePointer((PVOID volatile*)&s_localVasCallers[idx].addr, (PVOID)key, nullptr) == nullptr) {
                InterlockedIncrement64(&s_localVasCallers[idx].calls);
                InterlockedAdd64(&s_localVasCallers[idx].bytes, (LONGLONG)size);
                return;
            }
        }
    }
}

// Walk a captured stack and return the real allocation ORIGINATOR — skipping our
// own hook DLL and the CRT allocator wrappers (malloc / operator new live in
// msvcr*/msvcp*/ucrtbase), which otherwise mask the true caller.  Script/sim
// allocations go GameCode -> CRT malloc -> our hook, so without this the callsite
// resolves to msvcr80 or TS3VASManager instead of TS3W.exe+offset.  Prefers a
// TS3W.exe frame; falls back to the first non-self/non-CRT frame.
static void* ResolveOriginatorFrame(void* const* stack, USHORT frames,
                                    char* outModule, size_t outModuleBytes, UINT_PTR* outOffset) {
    if (outModule && outModuleBytes) outModule[0] = '\0';
    if (outOffset) *outOffset = 0;
    void* fallback = nullptr;
    char  fbMod[64] = {};
    UINT_PTR fbOff = 0;
    for (USHORT i = 0; i < frames; ++i) {
        if (!stack[i]) break;
        HMODULE mod = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)stack[i], &mod) || !mod)
            continue;
        char base[64] = {};
        GetModuleBaseNameA(GetCurrentProcess(), mod, base, sizeof(base));
        if (StringContainsI(base, "TS3VASManager")) continue;      // our own hook frame
        if (StringContainsI(base, "msvcr") || StringContainsI(base, "msvcp") ||
            StringContainsI(base, "vcruntime") || StringContainsI(base, "ucrtbase"))
            continue;                                              // CRT alloc wrapper, not originator
        UINT_PTR off = 0;
        MODULEINFO mi = {};
        if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
            off = (UINT_PTR)stack[i] - (UINT_PTR)mi.lpBaseOfDll;
        if (StringContainsI(base, "TS3W.exe") || StringContainsI(base, "TS3.exe") ||
            StringContainsI(base, "Game_Win32.exe")) {             // the game = the originator we want
            if (outModule && outModuleBytes) strcpy_s(outModule, outModuleBytes, base);
            if (outOffset) *outOffset = off;
            return stack[i];
        }
        if (!fallback) { fallback = stack[i]; strcpy_s(fbMod, sizeof(fbMod), base); fbOff = off; }
    }
    if (fallback) {
        if (outModule && outModuleBytes) strcpy_s(outModule, outModuleBytes, fbMod);
        if (outOffset) *outOffset = fbOff;
    }
    return fallback;
}

static void RecordLocalVasReserve(SIZE_T size, bool failed, DWORD allocType = 0,
                                  DWORD protect = 0, bool fixedBase = false) {
    InterlockedIncrement64(&s_localVasStats.reserveCalls);
    InterlockedAdd64(&s_localVasStats.reserveBytes, (LONGLONG)size);
    if (failed) {
        InterlockedIncrement64(&s_localVasStats.reserveFailedCalls);
        InterlockedAdd64(&s_localVasStats.reserveFailedBytes, (LONGLONG)size);
    }

    void* stack[kCallerStackDepth] = {};
    USHORT frames = RtlCaptureStackBackTrace(1, kCallerStackDepth, stack, nullptr);
    // Resolve the true originator (past our hook + CRT wrappers) so script/sim
    // reserves attribute to TS3W.exe+offset, not msvcr80 / TS3VASManager.
    char originMod[64] = {};
    UINT_PTR originOff = 0;
    void* origin = ResolveOriginatorFrame(stack, frames, originMod, sizeof(originMod), &originOff);
    if (!origin) origin = stack[0];
    TrackLocalVasCaller(origin, size);
    char moduleName[MAX_PATH] = {};
    AllocCallerKind kind = ClassifyCallerModule(stack[0], moduleName, sizeof(moduleName));
    switch (kind) {
    case AllocCallerKind::Graphics:  InterlockedAdd64(&s_localVasStats.byGraphicsBytes, (LONGLONG)size); break;
    case AllocCallerKind::RuntimeDll:InterlockedAdd64(&s_localVasStats.byRuntimeBytes, (LONGLONG)size); break;
    case AllocCallerKind::GameExe:   InterlockedAdd64(&s_localVasStats.byGameBytes, (LONGLONG)size); break;
    case AllocCallerKind::SystemDll: InterlockedAdd64(&s_localVasStats.bySystemBytes, (LONGLONG)size); break;
    case AllocCallerKind::ModDll:    InterlockedAdd64(&s_localVasStats.byModBytes, (LONGLONG)size); break;
    default:                         InterlockedAdd64(&s_localVasStats.byUnknownBytes, (LONGLONG)size); break;
    }

    // Per-reserve context for local reserves that still bypass proxy + arena.  High
    // volume, so it goes to the RESERVE_CTX file only (console-suppressed) — the
    // watchable per-callsite rollup is the TopLocalReserve summary, not this.  The
    // flags self-classify WHY it stayed local: ww=write-watch, exec=executable,
    // phys=physical/large-page, fixedbase=caller-chosen address (e.g. a GPU aperture).
    if (size >= (1 * 1024 * 1024) && Logger::GetInstance()) {
        const char* modBase = originMod[0] ? originMod : "<unknown>";
        char flags[48] = "";
        if (allocType & MEM_WRITE_WATCH)                  strcat_s(flags, "ww,");
        if (IsExecProtect(protect))                       strcat_s(flags, "exec,");
        if (allocType & (MEM_PHYSICAL | MEM_LARGE_PAGES)) strcat_s(flags, "phys,");
        if (fixedBase)                                    strcat_s(flags, "fixedbase,");
        if (!flags[0])                                    strcpy_s(flags, "plain");
        Logger::GetInstance()->NamedInfo("RESERVE_CTX",
            "ReserveCtx: kind=%d origin=%s+0x%IX size=%zu KB flags=%s type=0x%X prot=0x%X failed=%d tid=%lu ret=%p",
            (int)kind, modBase, originOff, size / 1024, flags, allocType, protect,
            failed ? 1 : 0, GetCurrentThreadId(), origin);
    }
}

static void LogRangeAllocationHit(const char* api, void* retAddr, UINT_PTR base, SIZE_T size, DWORD protect, DWORD typeFlags) {
    Logger* log = Logger::GetInstance();
    if (!log) return;
    char moduleName[MAX_PATH] = {};
    AllocCallerKind kind = ClassifyCallerModule(retAddr, moduleName, sizeof(moduleName));
    if (!ShouldLogRangeHit(kind, base, size))
        return;
    log->NamedInfo("VAS_RANGE_LOG",
        "%s hit: kind=%d module=%s ret=%p base=0x%08IX size=%zu end=0x%08IX prot=0x%X type=0x%X range=[0x%08IX..0x%08IX)",
        api, (int)kind, moduleName[0] ? moduleName : "<unknown>", retAddr,
        base, size, base + size, protect, typeFlags, s_rangeLogStart, s_rangeLogEnd);
}

void WorkingHooks::ReportAllocCallsites(const char* logName) {
    Logger* log = Logger::GetInstance();
    if (!log) return;
    if (!logName || !*logName) logName = "RTL_ALLOC_REPORT";

    log->NamedInfo(logName, "Large RtlAllocateHeap callsites: total=%lld candidates=%lld captured=%lld capture_failed=%lld observed_before_active=%lld",
                   Read64(&s_allocReport.totalLargeAllocs),
                   Read64(&s_allocReport.proxyCandidates),
                   Read64(&s_allocReport.captured),
                   Read64(&s_allocReport.captureFailed),
                   Read64(&s_allocReport.observedBeforeActive));

    log->NamedInfo(logName, "By module count: game=%lld graphics=%lld runtime=%lld system=%lld mod=%lld unknown=%lld",
                   Read64(&s_allocReport.gameExeAllocs),
                   Read64(&s_allocReport.graphicsAllocs),
                   Read64(&s_allocReport.runtimeDllAllocs),
                   Read64(&s_allocReport.systemDllAllocs),
                   Read64(&s_allocReport.modDllAllocs),
                   Read64(&s_allocReport.unknownAllocs));

    log->NamedInfo(logName, "By module bytes: game=%lld MB graphics=%lld MB runtime=%lld MB system=%lld MB mod=%lld MB unknown=%lld MB",
                   Read64(&s_allocReport.bytesGameExe) / (1024 * 1024),
                   Read64(&s_allocReport.bytesGraphics) / (1024 * 1024),
                   Read64(&s_allocReport.bytesRuntimeDll) / (1024 * 1024),
                   Read64(&s_allocReport.bytesSystemDll) / (1024 * 1024),
                   Read64(&s_allocReport.bytesModDll) / (1024 * 1024),
                   Read64(&s_allocReport.bytesUnknown) / (1024 * 1024));

    log->NamedInfo(logName, "Proxy skipped: graphics=%lld runtime=%lld system=%lld mod=%lld unknown=%lld",
                   Read64(&s_allocReport.skippedGraphics),
                   Read64(&s_allocReport.skippedRuntimeDll),
                   Read64(&s_allocReport.skippedSystemDll),
                   Read64(&s_allocReport.skippedModDll),
                   Read64(&s_allocReport.skippedUnknown));
}

void WorkingHooks::ReportLocalVasSources(const char* logName) {
    Logger* log = Logger::GetInstance();
    if (!log) return;
    if (!logName || !*logName) logName = "VAS_LOCAL_SOURCES";
    log->NamedInfo(logName,
        "Local VirtualAlloc reserve: calls=%lld bytes=%lld MB failed_calls=%lld failed_bytes=%lld MB",
        Read64(&s_localVasStats.reserveCalls),
        Read64(&s_localVasStats.reserveBytes) / (1024 * 1024),
        Read64(&s_localVasStats.reserveFailedCalls),
        Read64(&s_localVasStats.reserveFailedBytes) / (1024 * 1024));
    log->NamedInfo(logName,
        "By caller bytes MB: graphics=%lld runtime=%lld game=%lld system=%lld mod=%lld unknown=%lld",
        Read64(&s_localVasStats.byGraphicsBytes) / (1024 * 1024),
        Read64(&s_localVasStats.byRuntimeBytes) / (1024 * 1024),
        Read64(&s_localVasStats.byGameBytes) / (1024 * 1024),
        Read64(&s_localVasStats.bySystemBytes) / (1024 * 1024),
        Read64(&s_localVasStats.byModBytes) / (1024 * 1024),
        Read64(&s_localVasStats.byUnknownBytes) / (1024 * 1024));

    struct TopEntry { LONG_PTR addr; LONGLONG bytes; LONGLONG calls; };
    TopEntry top[5] = {};
    for (int i = 0; i < kLocalVasCallerSlots; ++i) {
        LONG_PTR a = (LONG_PTR)InterlockedCompareExchangePointer((PVOID volatile*)&s_localVasCallers[i].addr, nullptr, nullptr);
        if (!a) continue;
        LONGLONG b = Read64(&s_localVasCallers[i].bytes);
        LONGLONG c = Read64(&s_localVasCallers[i].calls);
        if (b <= 0) continue;
        for (int k = 0; k < 5; ++k) {
            if (b > top[k].bytes) {
                for (int m = 4; m > k; --m) top[m] = top[m - 1];
                top[k].addr = a; top[k].bytes = b; top[k].calls = c;
                break;
            }
        }
    }
    for (int k = 0; k < 5; ++k) {
        if (!top[k].addr || top[k].bytes <= 0) continue;
        HMODULE mod = nullptr;
        char modName[MAX_PATH] = "<unknown>";
        UINT_PTR offs = 0;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)(ULONG_PTR)top[k].addr, &mod) && mod) {
            GetModuleBaseNameA(GetCurrentProcess(), mod, modName, MAX_PATH);
            MODULEINFO mi = {};
            if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
                offs = (UINT_PTR)top[k].addr - (UINT_PTR)mi.lpBaseOfDll;
        }
        log->NamedInfo(logName,
            "TopLocalReserve[%d]: %s+0x%IX calls=%lld bytes=%lld MB addr=%p",
            k + 1, modName, offs, top[k].calls, top[k].bytes / (1024 * 1024), (void*)(ULONG_PTR)top[k].addr);
    }
}

void WorkingHooks::CaptureAllocSnapshot(RtlAllocSnapshot& out) {
    out.captured        = Read64(&s_allocReport.captured);
    out.captureFailed    = Read64(&s_allocReport.captureFailed);
    out.bytesByModule[0] = Read64(&s_allocReport.bytesGameExe);
    out.bytesByModule[1] = Read64(&s_allocReport.bytesGraphics);
    out.bytesByModule[2] = Read64(&s_allocReport.bytesRuntimeDll);
    out.bytesByModule[3] = Read64(&s_allocReport.bytesSystemDll);
    out.bytesByModule[4] = Read64(&s_allocReport.bytesModDll);
    out.bytesByModule[5] = Read64(&s_allocReport.bytesUnknown);
    out.capturedBytes   = out.bytesByModule[0] + out.bytesByModule[1] + out.bytesByModule[2];
    out.localVasReserveBytes      = Read64(&s_localVasStats.reserveBytes);
    out.localVasByModule[0]       = Read64(&s_localVasStats.byGameBytes);
    out.localVasByModule[1]       = Read64(&s_localVasStats.byGraphicsBytes);
    out.localVasByModule[2]       = Read64(&s_localVasStats.byRuntimeBytes);
    out.localVasByModule[3]       = Read64(&s_localVasStats.bySystemBytes);
    out.localVasByModule[4]       = Read64(&s_localVasStats.byModBytes);
    out.localVasByModule[5]       = Read64(&s_localVasStats.byUnknownBytes);
}

// ── TLS bootstrapping guard ───────────────────────────────────────────────────
static inline bool TlsIsBootstrapping() {
    return *(LPVOID*)((BYTE*)NtCurrentTeb() + 0x2C) == nullptr;
}

// ── Thread-local recursion guard ─────────────────────────────────────────────
// RtlHookScope: RAII guard that sets/clears the TLS in-hook flag.
// Do NOT redeclare or redefine them here.
static thread_local bool s_tlHookActive = false;

struct RtlHookScope {
    RtlHookScope()  { s_tlHookActive = true;  }
    ~RtlHookScope() { s_tlHookActive = false; }
};

// ── Proxy heap sub-allocator ("sardine packing" for sub-64KB heap allocs) ───────
// The arena hands out a 64KB-granular slot per allocation — fine for >=64KB, hugely
// wasteful for the small-alloc flood (a 4KB alloc burning 64KB).  So for data < 64KB
// we sub-allocate from our own sharded private LFH heaps instead: real malloc-grade
// packing, in bounded regions we own, pulling the small churn out of the game's
// heaps.  Sharded (default 3) so the per-heap lock + LFH front-end caches don't
// serialize the game's multi-threaded alloc traffic.
//
// Recursion-safe: we only redirect non-in-hook game allocs (the hook bails on
// IsInHook at entry), and every shard op uses the Real_* trampolines, so nothing
// re-enters our hooks.  Frees/realloc/size route by address range.  Executable heaps
// are never redirected (their allocations are code).  Gated by
// TS3VAS_PROXY_HEAP_SUBALLOC (default ON); shard count via TS3VAS_PROXY_HEAP_SHARDS
// (default 3, 1..8 — set 1 to measure single-heap-lock perf) and per-shard size via
// TS3VAS_PROXY_HEAP_SHARD_MB (default 54 → 162 MB reserved across 3 shards).
static const SIZE_T  kHeapSubAllocMax  = 64 * 1024;   // only data strictly < 64 KB
static const int     kMaxProxyHeapShards = 8;          // array cap; live count is env-tunable
static HANDLE        s_proxyHeaps[kMaxProxyHeapShards]  = {};
static uintptr_t     s_proxyHeapLo[kMaxProxyHeapShards] = {};
static uintptr_t     s_proxyHeapHi[kMaxProxyHeapShards] = {};
static volatile LONG s_proxyHeapCount   = 0;          // published after Lo/Hi are set
static volatile LONG s_proxyHeapInit    = 0;
static LONG          s_proxyHeapEnabled  = 0;
static volatile LONG s_proxyHeapRR      = 0;          // round-robin shard picker

// Per-band internal-loss probe for the sub-64KB sardine tier.  For each captured alloc
// we compare the requested size to the actual usable block (HeapSize) — the difference
// is LFH bucket rounding + block header overhead.  loss% = (act-req)/act per band, the
// sub-64KB analogue of the arena's 64KB slot-rounding meter.  Cumulative (lifetime avg).
// Default on; TS3VAS_SARDINE_LOSS_PROBE=0 disables the per-alloc HeapSize call.
static LONG            s_sardineLossProbe = 1;
static volatile LONG64 s_sardineReqB[8]   = {};
static volatile LONG64 s_sardineActB[8]   = {};
static const char* const kSardineBandLbl[8] = {
    "<512B", "512B-1K", "1-2K", "2-4K", "4-8K", "8-16K", "16-32K", "32-64K" };
static void RecordSardineLoss(SIZE_T req, SIZE_T act) {
    int b = (req <    512) ? 0 : (req <   1024) ? 1 : (req <  2*1024) ? 2 :
            (req <  4*1024) ? 3 : (req < 8*1024) ? 4 : (req < 16*1024) ? 5 :
            (req < 32*1024) ? 6 : 7;
    InterlockedAdd64(&s_sardineReqB[b], (LONG64)req);
    InterlockedAdd64(&s_sardineActB[b], (LONG64)act);
}

// Executable heaps the game creates — their allocations are JIT/code, never redirect.
static const int      kMaxExecHeaps = 16;
static PVOID volatile s_execHeaps[kMaxExecHeaps] = {};
static volatile LONG  s_execHeapCount = 0;

static void ProxyHeapNoteExecHeap(PVOID h) {
    if (!h) return;
    LONG n = s_execHeapCount;
    if (n >= kMaxExecHeaps) return;
    s_execHeaps[n] = h;
    MemoryBarrier();
    s_execHeapCount = n + 1;
}
static bool ProxyHeapIsExecHeap(PVOID h) {
    LONG n = s_execHeapCount;
    for (LONG i = 0; i < n; ++i) if (s_execHeaps[i] == h) return true;
    return false;
}

static inline bool ProxyHeapOn() { return s_proxyHeapEnabled != 0; }

static void ProxyHeapInit() {
    if (InterlockedCompareExchange(&s_proxyHeapInit, 1, 0) != 0) return;
    char v[16] = {};
    DWORD n = GetEnvironmentVariableA("TS3VAS_PROXY_HEAP_SUBALLOC", v, (DWORD)sizeof(v));
    // Default ON now (env propagation through the launcher is unreliable).  Only OFF
    // if explicitly disabled: TS3VAS_PROXY_HEAP_SUBALLOC=0 (use setx for persistence).
    bool off = (n > 0) && (v[0]=='0'||v[0]=='f'||v[0]=='F'||v[0]=='n'||v[0]=='N');
    if (off) {
        EmergencyLog("ProxyHeap", "sub-allocator OFF (disabled via TS3VAS_PROXY_HEAP_SUBALLOC=0)");
        return;
    }
    SIZE_T shardMb = 54;        // x3 = 162 MB, carved from the arena bottom (eager-committed)
    n = GetEnvironmentVariableA("TS3VAS_PROXY_HEAP_SHARD_MB", v, (DWORD)sizeof(v));
    if (n > 0 && n < sizeof(v)) { SIZE_T mb = (SIZE_T)atoi(v); if (mb) shardMb = mb; }
    int shardCount = 3;
    n = GetEnvironmentVariableA("TS3VAS_PROXY_HEAP_SHARDS", v, (DWORD)sizeof(v));
    if (n > 0 && n < sizeof(v)) {
        int c = atoi(v);
        if (c >= 1 && c <= kMaxProxyHeapShards) shardCount = c;
    }
    const SIZE_T maxSize = shardMb * 1024 * 1024;

    // Place the sardine shards INSIDE the proxy arena: carve a reserved slot, eager-commit
    // it, and build an LFH heap over it with RtlCreateHeap.  Committing the whole carve up
    // front means the heap never has to grow within it (sidesteps the commit-on-demand-
    // with-a-base question).  Anything missing (no arena, RtlCreateHeap unresolved, carve
    // or commit fails) falls back to a standalone HeapCreate so the sub-allocator always
    // comes up.  Runs before hooks attach, so these calls are un-hooked.
    typedef PVOID (NTAPI *RtlCreateHeap_fn)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
    RtlCreateHeap_fn pRtlCreateHeap = nullptr;
    if (HMODULE hNt = GetModuleHandleA("ntdll.dll"))
        pRtlCreateHeap = (RtlCreateHeap_fn)GetProcAddress(hNt, "RtlCreateHeap");

    int created = 0, inArena = 0;
    for (int i = 0; i < shardCount; ++i) {
        HANDLE h = nullptr;
        uintptr_t base = 0;
        if (s_memManager && pRtlCreateHeap) {
            LPVOID slot = s_memManager->GetProxyAllocator().Allocate(maxSize);
            if (slot) {
                if (VirtualAlloc(slot, maxSize, MEM_COMMIT, PAGE_READWRITE))
                    h = (HANDLE)pRtlCreateHeap(0, slot, maxSize, maxSize, nullptr, nullptr);
                if (h) { base = (uintptr_t)slot; inArena++; }
                else   { s_memManager->GetProxyAllocator().Free(slot, maxSize); }
            }
        }
        if (!h) {
            h = HeapCreate(0, 0, maxSize);   // fallback: standalone heap (separate VAS)
            if (!h) continue;
            base = (uintptr_t)h;
        }
        ULONG lfh = 2;
        HeapSetInformation(h, HeapCompatibilityInformation, &lfh, sizeof(lfh));
        s_proxyHeapLo[created] = base;
        s_proxyHeapHi[created] = base + maxSize;
        s_proxyHeaps[created]  = h;
        created++;
    }
    MemoryBarrier();
    s_proxyHeapCount   = created;
    s_proxyHeapEnabled = (created > 0) ? 1 : 0;
    {
        char pv[8] = {};
        DWORD pn = GetEnvironmentVariableA("TS3VAS_SARDINE_LOSS_PROBE", pv, (DWORD)sizeof(pv));
        if (pn > 0 && (pv[0]=='0'||pv[0]=='f'||pv[0]=='F'||pv[0]=='n'||pv[0]=='N'))
            s_sardineLossProbe = 0;
    }
    EmergencyLogF("ProxyHeap", "sub-allocator ON: %d shard(s) x %zu MB = %zu MB (%d in-arena, %d standalone), capture < %zu KB (LFH), loss_probe=%ld",
                  created, shardMb, (SIZE_T)created * shardMb, inArena, created - inArena, kHeapSubAllocMax / 1024, s_sardineLossProbe);
}

static int ProxyHeapShardOf(LPCVOID p) {
    if (!p) return -1;
    uintptr_t a = (uintptr_t)p;
    LONG n = s_proxyHeapCount;
    for (LONG i = 0; i < n; ++i)
        if (a >= s_proxyHeapLo[i] && a < s_proxyHeapHi[i]) return (int)i;
    return -1;
}

// A shard's heap handle IS its base page (RtlCreateHeap over the carved slot).
// If that page isn't committed RW, the shard's backing memory is gone — never
// committed past shard 0, or later reclaimed — and any RtlAllocateHeap/RtlFreeHeap
// on it faults reading the heap header (this is the launch-time RtlFreeHeap+0x6c
// crash). Validate cheaply before touching a shard so a dead one is skipped, not
// dereferenced.
static bool ShardHandleLive(HANDLE h) {
    if (!h) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(h, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    return mbi.State == MEM_COMMIT &&
           !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
}

// RAII: mark in-hook for the duration of a shard op so the shard's own internal
// work (growing → hooked NtAllocateVirtualMemory, any logging alloc) does NOT route
// back into the sardine and re-enter the same heap → recursion / stack overflow.
// Save/restore so it's a no-op when the caller (alloc hooks) already set it.
struct ProxyHeapHookScope {
    bool was;
    ProxyHeapHookScope() : was(IsInHook()) { if (!was) SetInHook(true); }
    ~ProxyHeapHookScope() { if (!was) SetInHook(false); }
};

// Allocate from a shard (round-robin start, try each so a full shard spills to a
// sibling).  Returns null only when ALL shards are full → caller falls back.
static LPVOID ProxyHeapAlloc(ULONG flags, SIZE_T size) {
    LONG n = s_proxyHeapCount;
    if (n <= 0) return nullptr;
    ProxyHeapHookScope guard;
    LPVOID p = nullptr;
    LONG start = InterlockedIncrement(&s_proxyHeapRR);
    for (LONG k = 0; k < n; ++k) {
        HANDLE h = s_proxyHeaps[(start + k) % n];
        if (!ShardHandleLive(h)) continue;   // skip a shard whose pages are gone
        p = Real_RtlAllocateHeap(h, flags & HEAP_ZERO_MEMORY, size);
        if (p) break;
    }
    return p;
}
static bool   ProxyHeapFree(ULONG flags, LPVOID p) {
    int s = ProxyHeapShardOf(p);
    if (s < 0) return false;
    // Failsafe: never free into a shard whose backing pages aren't committed —
    // RtlFreeHeap would fault on the heap header. Decline so the caller routes the
    // arena pointer to FreeProxyAllocation (which safely no-ops an unknown arena
    // pointer) instead of crashing. Worst case the block leaks; it never crashes.
    if (!ShardHandleLive(s_proxyHeaps[s])) return false;
    ProxyHeapHookScope guard;
    // CRITICAL: drop HEAP_NO_SERIALIZE.  The shards are shared across every game thread
    // (round-robin capture), so a no-serialize free would skip the shard lock while other
    // threads allocate under it — unlocked concurrent freelist mutation -> ntdll heap
    // corruption.  The caller's no-serialize intent was for ITS heap, not our shared one.
    Real_RtlFreeHeap(s_proxyHeaps[s], flags & ~HEAP_NO_SERIALIZE, p);
    return true;
}
static LPVOID ProxyHeapReAlloc(ULONG flags, LPVOID p, SIZE_T size) {
    int s = ProxyHeapShardOf(p);
    if (s < 0) return nullptr;
    if (!ShardHandleLive(s_proxyHeaps[s])) return nullptr;  // dead shard — fail, don't fault
    ProxyHeapHookScope guard;
    return Real_RtlReAllocateHeap(s_proxyHeaps[s], flags & HEAP_ZERO_MEMORY, p, size);
}
static SIZE_T ProxyHeapSize(ULONG flags, LPCVOID p) {
    int s = ProxyHeapShardOf(p);
    if (s < 0) return (SIZE_T)-1;
    if (!Real_HeapSize) return (SIZE_T)-1;
    ProxyHeapHookScope guard;
    // Same shared-shard reason as ProxyHeapFree: never skip the lock on the size read.
    return Real_HeapSize(s_proxyHeaps[s], flags & ~HEAP_NO_SERIALIZE, p);
}

// Committed (real RAM-backed) bytes in one shard's reservation, via a VAS walk.
static SIZE_T ProxyHeapShardCommitted(uintptr_t lo, uintptr_t hi) {
    SIZE_T committed = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t a = lo;
    while (a < hi && VirtualQuery((LPCVOID)a, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t rEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (rEnd > hi) rEnd = hi;
        if (mbi.State == MEM_COMMIT) committed += (rEnd - a);
        a = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (a <= lo) break;
    }
    return committed;
}

void WorkingHooks::ReportProxyHeapUsage(const char* logName) {
    Logger* log = Logger::GetInstance();
    if (!log) return;
    if (!logName || !*logName) logName = "PROXY_HEAP";
    const SIZE_T MB = 1024 * 1024;
    LONG shards = s_proxyHeapCount;
    if (!ProxyHeapOn() || shards <= 0) {
        log->NamedInfo(logName, "sub-allocator OFF");
        return;
    }
    SIZE_T reserved = 0, committed = 0;
    for (LONG i = 0; i < shards; ++i) {
        reserved  += (SIZE_T)(s_proxyHeapHi[i] - s_proxyHeapLo[i]);
        committed += ProxyHeapShardCommitted(s_proxyHeapLo[i], s_proxyHeapHi[i]);
    }
    Analytics* a = Analytics::GetInstance();
    auto C = [&](const char* k) -> unsigned long long {
        return a ? (unsigned long long)a->GetCounterValue(k) : 0ULL;
    };
    unsigned long long alloc = C("ProxyHeap_Alloc");
    unsigned long long freed = C("ProxyHeap_Free");
    unsigned long long live  = (alloc > freed) ? (alloc - freed) : 0;
    log->NamedInfo(logName,
        "shards=%ld reserved=%zu MB committed=%zu MB | live=%llu (cum alloc=%llu free=%llu) "
        "cum_alloc=%llu MB fallback=%llu",
        shards, reserved / MB, committed / MB, live, alloc, freed,
        C("ProxyHeap_AllocBytes") / MB, C("ProxyHeap_Full_Fallback"));

    // Per-granularity packing loss (sub-64KB): actual usable block vs requested = LFH
    // bucket rounding + block header.  Cumulative lifetime average per band.
    if (s_sardineLossProbe) {
        for (int b = 0; b < 8; ++b) {
            const LONG64 req = InterlockedCompareExchange64(&s_sardineReqB[b], 0, 0);
            const LONG64 act = InterlockedCompareExchange64(&s_sardineActB[b], 0, 0);
            if (act <= 0) continue;
            const double lossPct = (double)(act - req) * 100.0 / (double)act;
            log->NamedInfo(logName,
                "  loss %-8s req=%lld MB act=%lld MB loss=%.1f%%",
                kSardineBandLbl[b], (long long)(req / (LONG64)MB),
                (long long)(act / (LONG64)MB), lossPct);
        }
    }
}

PVOID NTAPI Hooked_RtlCreateHeap(
    ULONG Flags, PVOID Base, SIZE_T Reserve,
    SIZE_T Commit, PVOID Lock, PVOID Params)
{
    if (TlsIsBootstrapping())
        return Real_RtlCreateHeap(Flags, Base, Reserve, Commit, Lock, Params);
    if (s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown())
        return Real_RtlCreateHeap(Flags, Base, Reserve, Commit, Lock, Params);

    RtlHookScope scope;
    SetInHook(true);
    InterlockedIncrement(&s_activeHookCalls);

    PVOID heap = Real_RtlCreateHeap(Flags, Base, Reserve, Commit, Lock, Params);

    // Executable heap → its allocations are code; never sub-allocate them into our
    // (non-exec) proxy heaps.
    if (heap && (Flags & HEAP_CREATE_ENABLE_EXECUTE))
        ProxyHeapNoteExecHeap(heap);

    if (s_memManager && Analytics::GetInstance())
        Analytics::GetInstance()->IncrementCounter("RtlCreateHeap_Seen");

    // Catalog every heap the game creates and who created it — pairs with HEAP_USAGE
    // to map heap -> purpose, the groundwork for per-heap corralling.
    if (heap && Logger::GetInstance()) {
        void* cstk[1] = {};
        RtlCaptureStackBackTrace(1, 1, cstk, nullptr);
        char m[64] = {};
        ClassifyCallerModule(cstk[0], m, sizeof(m));
        Logger::GetInstance()->NamedInfo("HEAP_CREATE",
            "handle=0x%08IX flags=0x%lX by=%s ret=%p",
            (UINT_PTR)heap, (unsigned long)Flags, m[0] ? m : "<?>", cstk[0]);
    }

    SetInHook(false);
    InterlockedDecrement(&s_activeHookCalls);
    return heap;
}

static void RecordAllocSizeBucket(SIZE_T size) {
    auto* a = Analytics::GetInstance();
    if (!a) return;
    const char* cntName;
    const char* byteName;
    if      (size <    4 * 1024)      { cntName = "AllocSize_0to4KB";     byteName = "AllocBytes_0to4KB"; }
    else if (size <   64 * 1024)      { cntName = "AllocSize_4to64KB";    byteName = "AllocBytes_4to64KB"; }
    else if (size <  256 * 1024)      { cntName = "AllocSize_64to256KB";  byteName = "AllocBytes_64to256KB"; }
    else if (size <  512 * 1024)      { cntName = "AllocSize_256to512KB"; byteName = "AllocBytes_256to512KB"; }
    else if (size < 1024 * 1024)      { cntName = "AllocSize_512KBto1MB"; byteName = "AllocBytes_512KBto1MB"; }
    else if (size < 4  * 1024 * 1024) { cntName = "AllocSize_1to4MB";     byteName = "AllocBytes_1to4MB"; }
    else if (size < 16 * 1024 * 1024) { cntName = "AllocSize_4to16MB";    byteName = "AllocBytes_4to16MB"; }
    else                              { cntName = "AllocSize_16MBplus";   byteName = "AllocBytes_16MBplus"; }
    a->IncrementCounter(cntName);
    a->IncrementCounter(byteName, size);   // parallel byte accumulator -> ALLOC_BYTES_DIST
}

// Diagnostic: the disposition of a >=64KB RtlAllocateHeap alloc, recorded in the SAME
// population as RecordAllocSizeBucket (the block-size dist) so the three buckets are
// directly reconcilable against it — unlike the proxy-redirect dist, which mixes in
// HeapAlloc/realloc/corral callers.  Per band:  HeapBandCaptured + HeapBandMissed +
// HeapBandSelf == AllocSize (for the >=64KB bands).
//   Captured = pulled into the proxy.   Missed = a game alloc we should have taken but
//   didn't (CRA failed / proxy inactive) — the real leak.   Self = CallerIsSelf, our
//   own DLL's CRT allocations, which must stay local.   Sub-64KB ignored (sardine's job).
static void RecordHeapBandBucket(SIZE_T size, const char* prefix) {
    if (size < HEAP_CAPTURE_THRESHOLD) return;
    auto* a = Analytics::GetInstance();
    if (!a) return;
    const char* band =
        (size <  256 * 1024)      ? "64to256KB"  :
        (size <  512 * 1024)      ? "256to512KB" :
        (size < 1024 * 1024)      ? "512KBto1MB" :
        (size < 4  * 1024 * 1024) ? "1to4MB"     :
        (size < 16 * 1024 * 1024) ? "4to16MB"    : "16MBplus";
    char name[64];
    sprintf_s(name, "%s_%s", prefix, band);
    a->IncrementCounter(name);
}

PVOID NTAPI Hooked_RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size)
{
    void* const callerRA = _ReturnAddress();   // immediate caller, for graphics exclusion
    InitProxyGrantLogCfg();
    if (TlsIsBootstrapping())
        return Real_RtlAllocateHeap(HeapHandle, Flags, Size);
    if (s_tlHookActive || IsInHook() || !s_memManager || WorkingHooks::IsShuttingDown())
        return Real_RtlAllocateHeap(HeapHandle, Flags, Size);

    RtlHookScope scope;
    SetInHook(true);
    InterlockedIncrement(&s_activeHookCalls);

    if (HitchDetector::GetInstance())
        HitchDetector::GetInstance()->IncrementAlloc();

    // Observe EVERY heap allocation (>=0), not just the capture-sized ones — the
    // true per-heap weight (small allocs included, e.g. script churn) is what tells
    // us which heaps to corral.  Cheap: TL-cached slot + interlocked adds.
    bool corralTargetHeap = RecordHeapUse(HeapHandle, Size, _ReturnAddress());
    RecordAllocSizeBucket(Size);

    PVOID result = nullptr;

    // Per-heap corral: a heap flagged by first-caller module (e.g. DSOUND.dll) routes
    // ALL its allocations into the proxy arena regardless of size, pulling that
    // subsystem's memory out of loose VAS.  Free/realloc resolve via IsProxyAddress.
    if (corralTargetHeap && Size > 0 && s_memManager) {
        if (!WorkingHooks::IsProxyActive()) WorkingHooks::ActivateProxy();
        if (WorkingHooks::IsProxyActive()) {
            result = s_memManager->CreateProxyAllocation(Size, PAGE_READWRITE, ContainmentLane::LANE_CONTAINED_A);
            if (result) {
                RecordHeapBandBucket(Size, "HeapBandCaptured");   // corral path also counts as captured
                if (Analytics::GetInstance()) {
                    Analytics::GetInstance()->IncrementCounter("HeapCorral_Redirected");
                    Analytics::GetInstance()->IncrementCounter("HeapCorral_RedirectedBytes", (uint64_t)Size);
                }
                SetInHook(false);
                InterlockedDecrement(&s_activeHookCalls);
                return result;
            }
            // CreateProxyAllocation failed (or self-skip) — fall through to normal path.
        }
    }

    // Sardine packing: capture sub-64KB heap allocs into our sharded LFH heaps
    // (malloc-granular) instead of a 64KB arena slot each.  Exec heaps are skipped
    // (their allocs are code).  All shards full → fall through to the arena gate.
    if (ProxyHeapOn() && Size > 0 && Size < kHeapSubAllocMax && !ProxyHeapIsExecHeap(HeapHandle)
        && !HeapIsSardineExcluded(HeapHandle) && !CallerIsGraphicsModule(callerRA)
        && !CallerIsAudioModule(callerRA)) {
        PVOID hp = ProxyHeapAlloc(Flags, Size);
        if (hp) {
            if (Analytics::GetInstance()) {
                Analytics::GetInstance()->IncrementCounter("ProxyHeap_Alloc");
                Analytics::GetInstance()->IncrementCounter("ProxyHeap_AllocBytes", (uint64_t)Size);
            }
            if (s_sardineLossProbe) {
                SIZE_T act = ProxyHeapSize(0, hp);     // actual usable block vs requested
                if (act != (SIZE_T)-1) RecordSardineLoss(Size, act);
            }
            SetInHook(false);
            InterlockedDecrement(&s_activeHookCalls);
            return hp;
        }
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("ProxyHeap_Full_Fallback");
    }

    if (Size >= HEAP_CAPTURE_THRESHOLD || (Size >= kForceHeapProxyMinSize && IsForceHeapProxyMode())) {
        void* stack[kCallerStackDepth] = {};
        RtlCaptureStackBackTrace(1, kCallerStackDepth, stack, nullptr);
        char moduleName[MAX_PATH] = {};
        AllocCallerKind callerKind = ClassifyCallerModule(stack[0], moduleName, sizeof(moduleName));
        RecordCallerBucket(callerKind, Size, moduleName);

        bool strictMode = IsStrictRenderLocalOnlyMode();
        bool forceProxy = IsForceProxyActiveMode();
        bool canActivate = true;

        if (!WorkingHooks::IsProxyActive() && canActivate) {
            WorkingHooks::ActivateProxy();
            static bool activationLogged = false;
            if (!activationLogged && Logger::GetInstance()) {
                activationLogged = true;
                Logger::GetInstance()->Info("[PROXY] Activated via first large allocation (kind=%d, module=%s)",
                    (int)callerKind, moduleName);
            }
        }

        static bool policyLogged = false;
        if (!policyLogged && Logger::GetInstance()) {
            policyLogged = true;
            Logger::GetInstance()->Info("[PROXY] Policy mode: THRESHOLD_ONLY (TS3VAS_STRICT_RENDER_LOCAL_ONLY=%d, TS3VAS_FORCE_PROXY_ACTIVE=%d)",
                strictMode ? 1 : 0, forceProxy ? 1 : 0);
        }

        bool craAttempted = false;
        if (WorkingHooks::IsProxyActive()) {
            if (Size > 0 && !IsAudioModule(moduleName)   // audio stays in the real heap (see IsAudioModule)
                && (Size >= 64 * 1024 || (IsForceHeapProxyMode() && Size >= kForceHeapProxyMinSize))) {
                // Classify the allocation lane from caller kind:
                // Graphics driver allocations → Lane A (pinned, never evicted).
                // Everything else → Lane B (evictable via LRU).
                ContainmentLane lane = ContainmentLane_FromCallerKind((int)callerKind);
                result = s_memManager->CreateProxyAllocation(Size, PAGE_READWRITE, lane);
                craAttempted = true;
            }

            if (result) {
                RecordHeapBandBucket(Size, "HeapBandCaptured");   // taken into the proxy arena
                auto* a = Analytics::GetInstance();
                if (a) {
                    a->IncrementCounter("RtlAllocHeap_Captureed", Size);
                    a->IncrementCounter("RtlAllocHeap_CaptureCount");
                }
                if (Logger::GetInstance())
                {
                    InterlockedIncrement64(&s_proxyGrantCount);
                    InterlockedAdd64(&s_proxyGrantBytes, (LONG64)Size);
                    if (s_proxyGrantVerbose) {
                        Logger::GetInstance()->Info("[PROXY] Granted: module=%-30s size=%7zu KB  proxy=%p",
                            moduleName, Size / 1024, result);
                    } else {
                        MaybeLogProxyGrantTally();
                    }
                }
                InterlockedIncrement64(&s_allocReport.captured);
                SetInHook(false);
                InterlockedDecrement(&s_activeHookCalls);
                return result;
            }
            // Our own allocations are intentionally skipped (CallerIsSelf in
            // CreateProxyAllocation) — don't count those as capture failures.
            if (craAttempted && MemoryManager::LastCreateWasSelfSkip()) {
                RecordHeapBandBucket(Size, "HeapBandSelf");      // our own DLL's memory — correct
            } else {
                InterlockedIncrement64(&s_allocReport.captureFailed);
                RecordHeapBandBucket(Size, "HeapBandMissed");    // a game alloc we failed to take
            }
        } else {
            auto* a = Analytics::GetInstance();
            if (a) {
                a->IncrementCounter("RtlAllocHeap_Observed", Size);
                a->IncrementCounter("RtlAllocHeap_ObservedCount");
            }
            if (!WorkingHooks::IsProxyActive())
                InterlockedIncrement64(&s_allocReport.observedBeforeActive);
            RecordHeapBandBucket(Size, "HeapBandMissed");        // escaped: proxy not active
        }
    }

    result = Real_RtlAllocateHeap(HeapHandle, Flags, Size);
    SetInHook(false);
    InterlockedDecrement(&s_activeHookCalls);
    return result;
}

BOOLEAN NTAPI Hooked_RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase)
{
    if (!HeapBase) return TRUE;

    // Proxy-heap sub-allocation: free back to the owning shard (route by address).
    if (ProxyHeapFree(Flags, HeapBase)) {
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("ProxyHeap_Free");
        return TRUE;
    }

    if (s_memManager && s_memManager->IsProxyAddress(HeapBase)) {
        s_memManager->FreeProxyAllocation(HeapBase);
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("RtlFreeHeap_Proxy");
        return TRUE;
    }

    if (TlsIsBootstrapping())
        return Real_RtlFreeHeap(HeapHandle, Flags, HeapBase);
    if (s_tlHookActive || IsInHook() || !s_memManager)
        return Real_RtlFreeHeap(HeapHandle, Flags, HeapBase);

    RtlHookScope scope;
    SetInHook(true);
    InterlockedIncrement(&s_activeHookCalls);

    if (HitchDetector::GetInstance())
        HitchDetector::GetInstance()->IncrementFree();

    BOOLEAN result = Real_RtlFreeHeap(HeapHandle, Flags, HeapBase);
    SetInHook(false);
    InterlockedDecrement(&s_activeHookCalls);
    return result;
}

// ── RtlReAllocateHeap ────────────────────────────────────────────────────────
PVOID NTAPI Hooked_RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags,
                                      PVOID HeapBase, SIZE_T Size)
{
    // Re-entrancy guard FIRST. RtlReAllocateHeap does its block-move bookkeeping by
    // re-entering the patched PUBLIC heap entries; if we route that back into the
    // shard fast-path we recurse into ProxyHeapReAlloc until the stack overflows
    // (the c00000fd crash). When already inside a hook — or bootstrapping/shutting
    // down — use the real heap on the handle ntdll passed and never re-route.
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || !s_memManager ||
        WorkingHooks::IsShuttingDown())
        return Real_RtlReAllocateHeap(HeapHandle, Flags, HeapBase, Size);

    // Proxy-heap sub-allocation: realloc within the owning shard (route by address).
    // Null return = standard realloc-failure (original block left intact).
    if (HeapBase && ProxyHeapShardOf(HeapBase) >= 0)
        return ProxyHeapReAlloc(Flags, HeapBase, Size);

    if (s_memManager && HeapBase && s_memManager->IsProxyAddress(HeapBase)) {
        PVOID new_ptr = nullptr;
        if ((Size >= HEAP_CAPTURE_THRESHOLD || (Size >= kForceHeapProxyMinSize && IsForceHeapProxyMode())) &&
            WorkingHooks::IsProxyActive() && !WorkingHooks::IsShuttingDown())
            new_ptr = s_memManager->CreateProxyAllocation(Size, PAGE_READWRITE);
        if (!new_ptr)
            new_ptr = Real_RtlAllocateHeap(HeapHandle, Flags, Size);

        if (new_ptr) {
            MemoryManager::ProxyAllocRecord old_rec = {};
            if (s_memManager->FindRecordByAddress(HeapBase, &old_rec) &&
                old_rec.proxy_base && old_rec.proxy_size > 0 && Size > 0) {
                // Pages are eagerly committed at the proxy address — copy directly.
                // ram_buffer was removed; all data lives in the proxy arena itself.
                SIZE_T copy_sz = std::min(old_rec.proxy_size, Size);
                memcpy(new_ptr, old_rec.proxy_base, copy_sz);
            }
            s_memManager->FreeProxyAllocation(HeapBase);
            if (Analytics::GetInstance())
                Analytics::GetInstance()->IncrementCounter("RtlReAllocHeap_ProxyHandled");
        } else {
            s_memManager->FreeProxyAllocation(HeapBase);
        }
        return new_ptr;
    }

    if (TlsIsBootstrapping())
        return Real_RtlReAllocateHeap(HeapHandle, Flags, HeapBase, Size);
    if (s_tlHookActive || IsInHook() || !s_memManager)
        return Real_RtlReAllocateHeap(HeapHandle, Flags, HeapBase, Size);
    if (WorkingHooks::IsShuttingDown())
        return Real_RtlReAllocateHeap(HeapHandle, Flags, HeapBase, Size);

    RtlHookScope scope;
    SetInHook(true);
    InterlockedIncrement(&s_activeHookCalls);

    PVOID result = Real_RtlReAllocateHeap(HeapHandle, Flags, HeapBase, Size);
    if (result && Size >= HEAP_CAPTURE_THRESHOLD) {
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("RtlReAllocHeap_LargePassThrough");
    }
    SetInHook(false);
    InterlockedDecrement(&s_activeHookCalls);
    return result;
}

// ── NtAllocateVirtualMemory ──────────────────────────────────────────────────
NTSTATUS NTAPI Hooked_NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect)
{
    InitRangeLogConfig();
    if (TlsIsBootstrapping())
        return Real_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                            RegionSize, AllocationType, Protect);
    if (s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !s_memManager || !BaseAddress || !RegionSize)
        return Real_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                            RegionSize, AllocationType, Protect);

    RtlHookScope scope;
    SetInHook(true);
    InterlockedIncrement(&s_activeHookCalls);

    const bool currentProc = (ProcessHandle == GetCurrentProcess() ||
                               ProcessHandle == (HANDLE)(ULONG_PTR)-1);
    void* requestedBasePtr = (BaseAddress ? *BaseAddress : nullptr);
    const UINT32 requestedBaseIn = (BaseAddress && *BaseAddress)
        ? (UINT32)(ULONG_PTR)(*BaseAddress) : 0;
    if (currentProc && BaseAddress && RegionSize)
        EnsureProxyActiveForVirtualPath(*RegionSize, AllocationType, Protect);
    if (currentProc && RegionSize && *RegionSize > 0)
        RecordVaMixCounters(*RegionSize, AllocationType, Protect);

    const bool redirect =
        currentProc                                                     &&
        (*BaseAddress == nullptr)                                       &&
        (AllocationType & MEM_RESERVE)                                  &&
        // MEM_WRITE_WATCH excluded — proxy slot cannot satisfy GetWriteWatch.
        !(AllocationType & (MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_LARGE_PAGES)) &&
        !(Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                     PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))  &&
        (*RegionSize >= HEAP_CAPTURE_THRESHOLD || *RegionSize >= kForceVirtualAllocMinSize) &&
        s_memManager &&
        (!s_memManager->GetProxyMaxBytes() || *RegionSize < s_memManager->GetProxyMaxBytes()) &&
        WorkingHooks::IsProxyActive();

    if (redirect) {
        const SIZE_T requested = *RegionSize;
        LPVOID slot = s_memManager->GetProxyAllocator().Allocate(requested, s_memManager->GetProxyAllocator().PrefersTopDown(requested));
        if (slot) {
            if (VirtualAlloc(slot, requested, MEM_COMMIT, Protect)) {
                *BaseAddress = slot;
                *RegionSize  = requested;
                VatTrack((UINT_PTR)slot, requested);
                char moduleName[MAX_PATH] = {};
                AllocCallerKind callerKind = ClassifyCallerModule(_ReturnAddress(), moduleName, MAX_PATH);
                ContainmentLane lane = ContainmentLane_FromCallerKind((int)callerKind);
                TS3VASEtw::EmitProxySlotAssigned((UINT32)(ULONG_PTR)slot, (UINT32)requested,
                                                 (UINT8)(unsigned)lane, Protect);

                auto* a = Analytics::GetInstance();
                if (a) {
                    a->IncrementCounter("VirtualAlloc_Redirected");
                    a->IncrementCounter("VirtualAlloc_RedirectedBytes", (uint64_t)requested);
                    if      (requested <  1 * 1024 * 1024) a->IncrementCounter("VirtualAlloc_sub1MB");
                    else if (requested < 16 * 1024 * 1024) a->IncrementCounter("VirtualAlloc_1to16MB");
                    else                                    a->IncrementCounter("VirtualAlloc_16to256MB");
                }
                TS3VASEtw::EmitVirtualAllocHook(
                    requestedBaseIn, (UINT32)requested, AllocationType, Protect,
                    (UINT32)(ULONG_PTR)slot, /*redirected*/1, /*source=Nt*/0);
                LogRoGameContext("NtAllocateVirtualMemory",
                    requestedBasePtr, requested, AllocationType, Protect,
                    /*redirectEligible*/true, /*redirected*/true);
                InterlockedDecrement(&s_activeHookCalls);
                return 0; // STATUS_SUCCESS
            }
            s_memManager->GetProxyAllocator().Free(slot, requested);
        }
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("VirtualAlloc_RedirectFailed");
    }

    NTSTATUS status = Real_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                                    RegionSize, AllocationType, Protect);
    if (!redirect && currentProc && RegionSize && *RegionSize > 0 && Analytics::GetInstance()) {
        const SIZE_T sz = *RegionSize;
        Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected");
        Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_Bytes", (uint64_t)sz);
        if (*BaseAddress != nullptr)
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_NonNullBase");
        if (!(AllocationType & MEM_RESERVE))
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_NoReserve");
        if ((AllocationType & MEM_COMMIT) && !(AllocationType & MEM_RESERVE)) {
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_CommitOnly");
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_CommitOnlyBytes", (uint64_t)sz);
        }
        if (AllocationType & MEM_WRITE_WATCH) {
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_WriteWatch");
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_WriteWatchBytes", (uint64_t)sz);
        }
        if (IsExecProtect(Protect)) {
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_ExecProtect");
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_ExecProtectBytes", (uint64_t)sz);
        }
        if ((AllocationType & MEM_WRITE_WATCH) && IsExecProtect(Protect)) {
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_WriteWatchExec");
            Analytics::GetInstance()->IncrementCounter("NtAllocVM_NotRedirected_WriteWatchExecBytes", (uint64_t)sz);
        }
    }
    if (currentProc && RegionSize && *RegionSize > 0) {
        LogRoGameContext("NtAllocateVirtualMemory",
            requestedBasePtr, *RegionSize, AllocationType, Protect,
            /*redirectEligible*/redirect, /*redirected*/false);
    }
    if (currentProc && (AllocationType & MEM_RESERVE) && RegionSize &&
        *RegionSize >= kForceVirtualAllocMinSize) {
        RecordLocalVasReserve(*RegionSize, !NT_SUCCESS(status), AllocationType, Protect);
    }
    if (NT_SUCCESS(status) && currentProc &&
        (AllocationType & MEM_RESERVE) && RegionSize)
    {
        const SIZE_T sz = *RegionSize;
        if (BaseAddress && *BaseAddress) {
            void* stack[kCallerStackDepth] = {};
            RtlCaptureStackBackTrace(1, kCallerStackDepth, stack, nullptr);
            LogRangeAllocationHit("NtAllocateVirtualMemory", stack[0], (UINT_PTR)*BaseAddress, sz, Protect, AllocationType);
        }
        if (sz >= HEAP_CAPTURE_THRESHOLD && Analytics::GetInstance()) {
            auto* a = Analytics::GetInstance();
            a->IncrementCounter("VirtualAlloc_ReserveCount");
            a->IncrementCounter("VirtualAlloc_ReserveBytes", (uint64_t)sz);
            if      (sz <  1 * 1024 * 1024) a->IncrementCounter("VirtualAlloc_sub1MB");
            else if (sz < 16 * 1024 * 1024) a->IncrementCounter("VirtualAlloc_1to16MB");
            else                            a->IncrementCounter("VirtualAlloc_16to256MB");
        }
    }
    if (NT_SUCCESS(status) && currentProc && BaseAddress && *BaseAddress)
        TS3VASEtw::EmitVirtualAllocHook(
            requestedBaseIn, (UINT32)(RegionSize ? *RegionSize : 0), AllocationType, Protect,
            (UINT32)(ULONG_PTR)*BaseAddress, /*redirected*/0, /*source=Nt*/0);
    InterlockedDecrement(&s_activeHookCalls);
    return status;
}

// ── NtFreeVirtualMemory ──────────────────────────────────────────────────────
NTSTATUS NTAPI Hooked_NtFreeVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType)
{
    if (TlsIsBootstrapping())
        return Real_NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    if (s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !s_memManager || !BaseAddress)
        return Real_NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);

    RtlHookScope scope;
    SetInHook(true);
    InterlockedIncrement(&s_activeHookCalls);

    // Retire the unfreed-asset record before release completes (provenance: who freed).
    if ((FreeType & MEM_RELEASE) && BaseAddress && *BaseAddress) {
        void* fstk[1] = {};
        RtlCaptureStackBackTrace(1, 1, fstk, nullptr);
        RemoveDiagnosticAlloc(*BaseAddress, fstk[0]);
    }

    // Corral slots: intercept MEM_RELEASE here too (direct NtFree callers), since a
    // mid-reservation release would fail.  Recycle the slot, report success.
    if ((FreeType & MEM_RELEASE) && *BaseAddress &&
        s_memManager->IsCorralAddress(*BaseAddress)) {
        s_memManager->CorralFree(*BaseAddress);
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("ScriptArena_Freed");
        *BaseAddress = nullptr;
        if (RegionSize) *RegionSize = 0;
        InterlockedDecrement(&s_activeHookCalls);
        return 0; // STATUS_SUCCESS
    }

    SIZE_T trackedSz = 0;
    if ((FreeType & MEM_RELEASE) && VatUntrack((UINT_PTR)*BaseAddress, &trackedSz)) {
        const UINT32 freedAddr = (UINT32)(ULONG_PTR)*BaseAddress;
        VirtualFree(*BaseAddress, trackedSz, MEM_DECOMMIT);
        s_memManager->GetProxyAllocator().Free(*BaseAddress, trackedSz);

        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("VirtualAlloc_RedirectedFreed");

        TS3VASEtw::EmitProxySlotReleased(freedAddr, (UINT32)trackedSz);
        TS3VASEtw::EmitVirtualFreeHook(freedAddr, (UINT32)trackedSz, FreeType, /*wasProxy*/1);
        *BaseAddress = nullptr;
        if (RegionSize) *RegionSize = 0;
        InterlockedDecrement(&s_activeHookCalls);
        return 0; // STATUS_SUCCESS
    }

    const UINT32 capturedAddr = (BaseAddress && *BaseAddress)
                                ? (UINT32)(ULONG_PTR)*BaseAddress : 0;
    const UINT32 capturedSize = (RegionSize && *RegionSize)
                                ? (UINT32)*RegionSize : 0;
    NTSTATUS s = Real_NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    if (NT_SUCCESS(s) && capturedAddr)
        TS3VASEtw::EmitVirtualFreeHook(capturedAddr, capturedSize, FreeType, /*wasProxy*/0);
    InterlockedDecrement(&s_activeHookCalls);
    return s;
}

// ── Graphics write-watch corral ───────────────────────────────────────────────
// The game's graphics-pool allocator reserves many MEM_WRITE_WATCH regions that
// the OS scatters across high VAS, shredding largest_free (run 0601: largest_free
// −182 MB vs total −146 MB).  We can't capture them (write-watch + GPU-read), but
// we CAN place them: hint each reserve at the next slot of one contiguous zone so
// they pack instead of fragmenting.  OS-choice fallback on any collision.  Gated
// TS3VAS_GFX_CORRAL (default ON).

LPVOID WINAPI Hooked_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    InitRangeLogConfig();
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualAlloc)
        return Real_VirtualAlloc ? Real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = nullptr;
    bool usedRealPath = false;
    bool gfxWriteWatchCandidate = false;
    // Caller class of a write-watch reserve, resolved once when we detect the
    // candidate shape; used for the per-class counters/logging.
    AllocCallerKind wwKind = AllocCallerKind::Unknown;
    // True once the reserve lands in the script arena — it is then NOT local VAS, so
    // it must be excluded from RecordLocalVasReserve (TopLocalReserve / ReserveCtx).
    bool arenaPlaced = false;
    const char* redirectFailReason = nullptr;
    DWORD redirectFailGle = 0;
    Logger* log = Logger::GetInstance();
    if (dwSize > 0)
        RecordVaMixCounters(dwSize, flAllocationType, flProtect);
    EnsureProxyActiveForVirtualPath(dwSize, flAllocationType, flProtect);

    // ── Write-watch reserve classification ───────────────────────────────────
    // Every MEM_WRITE_WATCH | MEM_RESERVE (null base) reserve is a candidate for the
    // corral.  Classify the caller ONCE here so routing + reporting can tell genuine
    // graphics-driver pools (d3d9/dxgi/nvd3dum — the GPU's per-frame vertex/index/
    // mesh buffers, which belong in the 164 MB corral) apart from the Mono/script
    // JIT + GC heap (TS3W.exe), which carries write-watch too but must NOT eat the
    // graphics budget.  Sized counters are split by class so the script-heap growth
    // (Sims 3's notorious script bloat) is visible on its own; the per-callsite
    // pointers land in VAS_LOCAL_SOURCES/TopLocalReserve once they fall to local.
    if ((flAllocationType & MEM_WRITE_WATCH) &&
        (flAllocationType & MEM_RESERVE) &&
        lpAddress == nullptr) {
        gfxWriteWatchCandidate = true;
        char wwMod[64] = {};
        wwKind = ClassifyCallerModule(_ReturnAddress(), wwMod, sizeof(wwMod));
        const bool gfx = (wwKind == AllocCallerKind::Graphics);
        if (Analytics* a = Analytics::GetInstance()) {
            const char* pfx = gfx ? "GfxDriverWW" : "ScriptWW";
            char ctr[48];
            sprintf_s(ctr, "%s_Count", pfx);  a->IncrementCounter(ctr);
            sprintf_s(ctr, "%s_Bytes", pfx);  a->IncrementCounter(ctr, (uint64_t)dwSize);
            const char* band =
                (dwSize <  0x40000)   ? "Lt256K"   :
                (dwSize == 0x40000)   ? "256K"     :
                (dwSize <= 0x100000)  ? "256Kto1M" :
                (dwSize <= 0x1000000) ? "1Mto16M"  : "Gt16M";
            sprintf_s(ctr, "%s_%s", pfx, band);        a->IncrementCounter(ctr);
            sprintf_s(ctr, "%s_%s_Bytes", pfx, band);  a->IncrementCounter(ctr, (uint64_t)dwSize);
        }
    }

    const bool redirect =
        (lpAddress == nullptr) &&
        (flAllocationType & MEM_RESERVE) &&
        // MEM_WRITE_WATCH excluded: the proxy commits a plain arena slot, which
        // cannot satisfy GetWriteWatch on the returned region.  Let write-watch
        // reserves hit Real_VirtualAlloc so OS page-tracking semantics survive.
        !(flAllocationType & (MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_LARGE_PAGES)) &&
        !(flProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
        (dwSize >= HEAP_CAPTURE_THRESHOLD || dwSize >= kForceVirtualAllocMinSize) &&
        s_memManager &&
        (!s_memManager->GetProxyMaxBytes() || dwSize < s_memManager->GetProxyMaxBytes()) &&
        WorkingHooks::IsProxyActive();
    if (redirect) {
        LPVOID slot = s_memManager->GetProxyAllocator().Allocate(dwSize, s_memManager->GetProxyAllocator().PrefersTopDown(dwSize));
        if (slot && VirtualAlloc(slot, dwSize, MEM_COMMIT, flProtect)) {
            p = slot;
            VatTrack((UINT_PTR)slot, dwSize);
            char moduleName[MAX_PATH] = {};
            AllocCallerKind callerKind = ClassifyCallerModule(_ReturnAddress(), moduleName, MAX_PATH);
            ContainmentLane lane = ContainmentLane_FromCallerKind((int)callerKind);
            TS3VASEtw::EmitProxySlotAssigned((UINT32)(ULONG_PTR)slot, (UINT32)dwSize,
                                             (UINT8)(unsigned)lane, flProtect);
            if (Analytics::GetInstance()) {
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_Redirected");
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_RedirectedBytes", (uint64_t)dwSize);
            }
        } else if (slot) {
            redirectFailReason = "commit_fail";
            redirectFailGle = GetLastError();
            s_memManager->GetProxyAllocator().Free(slot, dwSize);
        } else {
            redirectFailReason = "slot_null";
            // No commit attempt occurred, so no reliable thread GLE exists.
            redirectFailGle = ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    if (!p) {
        if (!redirect && dwSize > 0 && Analytics::GetInstance()) {
            Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected");
            Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_Bytes", (uint64_t)dwSize);
            if (lpAddress != nullptr)
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_NonNullBase");
            if (!(flAllocationType & MEM_RESERVE))
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_NoReserve");
            if ((flAllocationType & MEM_COMMIT) && !(flAllocationType & MEM_RESERVE)) {
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_CommitOnly");
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_CommitOnlyBytes", (uint64_t)dwSize);
            }
            if (flAllocationType & MEM_WRITE_WATCH) {
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_WriteWatch");
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_WriteWatchBytes", (uint64_t)dwSize);
            }
            if (IsExecProtect(flProtect)) {
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_ExecProtect");
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_ExecProtectBytes", (uint64_t)dwSize);
            }
            if ((flAllocationType & MEM_WRITE_WATCH) && IsExecProtect(flProtect)) {
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_WriteWatchExec");
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_WriteWatchExecBytes", (uint64_t)dwSize);
            }
            if (flAllocationType & (MEM_PHYSICAL | MEM_LARGE_PAGES))
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_PhysicalOrLargePages");
            if (dwSize < kForceVirtualAllocMinSize)
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_SizeTooSmall");
            if (!s_memManager)
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_NoMemManager");
            if (!WorkingHooks::IsProxyActive())
                Analytics::GetInstance()->IncrementCounter("VirtualAlloc_NotRedirected_ProxyInactive");
        }

        if (redirect && Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("VirtualAlloc_RedirectFallback_Local");

        if (redirect && redirectFailReason && log) {
            void* stack[kCallerStackDepth] = {};
            RtlCaptureStackBackTrace(1, kCallerStackDepth, stack, nullptr);
            HMODULE mod = nullptr;
            char modBase[MAX_PATH] = "<unknown>";
            UINT_PTR offs = 0;
            if (stack[0] &&
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)stack[0], &mod) && mod) {
                GetModuleBaseNameA(GetCurrentProcess(), mod, modBase, MAX_PATH);
                MODULEINFO mi = {};
                if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
                    offs = (UINT_PTR)stack[0] - (UINT_PTR)mi.lpBaseOfDll;
            }
            log->NamedInfo("MEMHOOK",
                "VirtualAlloc redirect failed: reason=%s gle=%lu caller=%s+0x%IX ret=%p size=%zu type=0x%X prot=0x%X",
                redirectFailReason, redirectFailGle, modBase, offs, stack[0], dwSize, flAllocationType, flProtect);
        }

        usedRealPath = true;
        // Route EVERY write-watch reserve into the script arena (we own growable
        // write-watch zones).  d3d9 issues none of these in practice — the customers
        // are Mono's script/JIT exec write-watch reserves, which is exactly the script
        // heap we want pulled out of loose VAS.  The arena grows on demand; only when
        // it hits the VAS cap (or can't grow) does a reserve fall back to the OS.
        if (gfxWriteWatchCandidate && s_memManager)
            p = s_memManager->CorralReserve(dwSize, flAllocationType, flProtect);
        if (p) {
            arenaPlaced = true;   // in our arena, not local VAS
            if (Analytics::GetInstance()) Analytics::GetInstance()->IncrementCounter("ScriptArena_Placed");
        } else {
            if (gfxWriteWatchCandidate && Analytics::GetInstance())
                Analytics::GetInstance()->IncrementCounter("ScriptArena_Fallback");
            p = Real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        }
    }
    LogRoGameContext("VirtualAlloc",
        lpAddress, dwSize, flAllocationType, flProtect,
        /*redirectEligible*/redirect,
        /*redirected*/(redirect && p != nullptr && !usedRealPath));
    if (!p && (flAllocationType & MEM_RESERVE) && dwSize >= kForceVirtualAllocMinSize)
        RecordLocalVasReserve(dwSize, true, flAllocationType, flProtect, lpAddress != nullptr);
    else if (p && usedRealPath && !arenaPlaced && (flAllocationType & MEM_RESERVE) && dwSize >= kForceVirtualAllocMinSize)
        RecordLocalVasReserve(dwSize, false, flAllocationType, flProtect, lpAddress != nullptr);

    if (log && dwSize >= HEAP_CAPTURE_THRESHOLD)
        log->NamedInfo("MEMHOOK", "VirtualAlloc addr=%p size=%zu type=0x%X prot=0x%X -> %p",
                       lpAddress, dwSize, flAllocationType, flProtect, p);
    if (p && usedRealPath && (flAllocationType & MEM_RESERVE)) {
        void* stack[kCallerStackDepth] = {};
        RtlCaptureStackBackTrace(1, kCallerStackDepth, stack, nullptr);
        LogRangeAllocationHit("VirtualAlloc", stack[0], (UINT_PTR)p, dwSize, flProtect, flAllocationType);
        // Write-watch reserve detail: name the caller's module+offset and base so the
        // call site is symbolizable against the TS3W.exe map without Ghidra.  Script/
        // JIT reserves go to the SCRIPT_VAS channel (the script-bloat view); genuine
        // graphics-driver reserves stay on GFX_SHADOW.  ret offset is module-relative
        // because module name alone is always TS3W.exe for the script side.
        if (gfxWriteWatchCandidate && log) {
            char modName[MAX_PATH] = {};
            ClassifyCallerModule(stack[0], modName, sizeof(modName));
            HMODULE mod = nullptr;
            UINT_PTR offs = 0;
            if (stack[0] &&
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)stack[0], &mod) && mod) {
                MODULEINFO mi = {};
                if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
                    offs = (UINT_PTR)stack[0] - (UINT_PTR)mi.lpBaseOfDll;
            }
            const bool gfx = (wwKind == AllocCallerKind::Graphics);
            log->NamedInfo(gfx ? "GFX_SHADOW" : "SCRIPT_VAS",
                "writewatch_reserve: class=%s module=%s+0x%IX base=0x%08X size=%u KB ret=%p",
                gfx ? "gfx" : "script", modName[0] ? modName : "<unknown>", offs,
                (unsigned)(ULONG_PTR)p, (unsigned)(dwSize / 1024), stack[0]);
        }
        // Track local reserves >= 1 MB so DumpUnfreedAssets can list survivors.
        if (dwSize >= 1 * 1024 * 1024)
            RegisterDiagnosticAlloc(p, dwSize, stack[0]);
    }
    if (p)
        TS3VASEtw::EmitVirtualAllocHook(
            (UINT32)(ULONG_PTR)lpAddress, (UINT32)dwSize,
            flAllocationType, flProtect,
            (UINT32)(ULONG_PTR)p,
            /*redirected*/ usedRealPath ? 0 : 1,
            /*source=VirtualAlloc*/ 1);
    SetInHook(false);
    return p;
}

BOOL WINAPI Hooked_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    // Retire the unfreed-asset record at the release boundary (provenance: who freed).
    if ((dwFreeType & MEM_RELEASE) && lpAddress) {
        void* fstk[1] = {};
        RtlCaptureStackBackTrace(1, 1, fstk, nullptr);
        RemoveDiagnosticAlloc(lpAddress, fstk[0]);
    }

    // Corral slots live inside our reserved write-watch zone — a MEM_RELEASE of a
    // mid-reservation address would fail, so intercept it: recycle the slot (decommit
    // its pages, keep the zone) and report success to the game.
    if ((dwFreeType & MEM_RELEASE) && lpAddress &&
        s_memManager && s_memManager->IsCorralAddress(lpAddress)) {
        s_memManager->CorralFree(lpAddress);
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("ScriptArena_Freed");
        return TRUE;
    }

    SIZE_T trackedSz = 0;
    if ((dwFreeType & MEM_RELEASE) && VatUntrack((UINT_PTR)lpAddress, &trackedSz)) {
        VirtualFree(lpAddress, trackedSz, MEM_DECOMMIT);
        if (s_memManager)
            s_memManager->GetProxyAllocator().Free(lpAddress, trackedSz);
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("VirtualAlloc_RedirectedFreed");
        TS3VASEtw::EmitProxySlotReleased((UINT32)(ULONG_PTR)lpAddress, (UINT32)trackedSz);
        TS3VASEtw::EmitVirtualFreeHook((UINT32)(ULONG_PTR)lpAddress, (UINT32)trackedSz, dwFreeType, /*wasProxy*/1);
        return TRUE;
    }
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualFree)
        return Real_VirtualFree ? Real_VirtualFree(lpAddress, dwSize, dwFreeType) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_VirtualFree(lpAddress, dwSize, dwFreeType);
    TS3VASEtw::EmitVirtualFreeHook((UINT32)(ULONG_PTR)lpAddress, (UINT32)dwSize, dwFreeType, /*wasProxy*/0);
    Logger* log = Logger::GetInstance();
    if (log && !ok)
        log->NamedInfo("MEMHOOK", "VirtualFree addr=%p size=%zu freeType=0x%X -> FAIL",
                       lpAddress, dwSize, dwFreeType);
    SetInHook(false);
    return ok;
}

LPVOID WINAPI Hooked_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualAllocEx)
        return Real_VirtualAllocEx ? Real_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = Real_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    EmitApiHookWin32("VirtualAllocEx",
        (UINT64)(ULONG_PTR)hProcess, (UINT64)(ULONG_PTR)lpAddress,
        (UINT64)dwSize, ((UINT64)flAllocationType << 32) | flProtect,
        (UINT64)(ULONG_PTR)p, p != nullptr);
    SetInHook(false);
    return p;
}

BOOL WINAPI Hooked_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualFreeEx)
        return Real_VirtualFreeEx ? Real_VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
    EmitApiHookWin32("VirtualFreeEx",
        (UINT64)(ULONG_PTR)hProcess, (UINT64)(ULONG_PTR)lpAddress,
        (UINT64)dwSize, (UINT64)dwFreeType, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

BOOL WINAPI Hooked_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualProtect)
        return Real_VirtualProtect ? Real_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    const UINT64 oldProt = (lpflOldProtect && ok) ? (UINT64)(*lpflOldProtect) : 0;
    EmitApiHookWin32("VirtualProtect",
        (UINT64)(ULONG_PTR)lpAddress, (UINT64)dwSize,
        (UINT64)flNewProtect, oldProt, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

BOOL WINAPI Hooked_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualProtectEx)
        return Real_VirtualProtectEx ? Real_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    const UINT64 oldProt = (lpflOldProtect && ok) ? (UINT64)(*lpflOldProtect) : 0;
    EmitApiHookWin32("VirtualProtectEx",
        (UINT64)(ULONG_PTR)hProcess, (UINT64)(ULONG_PTR)lpAddress,
        (UINT64)dwSize, ((UINT64)flNewProtect << 32) | oldProt, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

SIZE_T WINAPI Hooked_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualQuery)
        return Real_VirtualQuery ? Real_VirtualQuery(lpAddress, lpBuffer, dwLength) : 0;

    RtlHookScope scope;
    SetInHook(true);
    SIZE_T ret = Real_VirtualQuery(lpAddress, lpBuffer, dwLength);
    EmitApiHookWin32Size("VirtualQuery",
        (UINT64)(ULONG_PTR)lpAddress, (UINT64)(ULONG_PTR)lpBuffer,
        (UINT64)dwLength, 0, (UINT64)ret, ret == 0);
    SetInHook(false);
    return ret;
}

SIZE_T WINAPI Hooked_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualQueryEx)
        return Real_VirtualQueryEx ? Real_VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength) : 0;

    RtlHookScope scope;
    SetInHook(true);
    SIZE_T ret = Real_VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
    EmitApiHookWin32Size("VirtualQueryEx",
        (UINT64)(ULONG_PTR)hProcess, (UINT64)(ULONG_PTR)lpAddress,
        (UINT64)(ULONG_PTR)lpBuffer, (UINT64)dwLength, (UINT64)ret, ret == 0);
    SetInHook(false);
    return ret;
}

BOOL WINAPI Hooked_VirtualLock(LPVOID lpAddress, SIZE_T dwSize)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualLock)
        return Real_VirtualLock ? Real_VirtualLock(lpAddress, dwSize) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_VirtualLock(lpAddress, dwSize);
    EmitApiHookWin32("VirtualLock",
        (UINT64)(ULONG_PTR)lpAddress, (UINT64)dwSize, 0, 0, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

BOOL WINAPI Hooked_VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualUnlock)
        return Real_VirtualUnlock ? Real_VirtualUnlock(lpAddress, dwSize) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_VirtualUnlock(lpAddress, dwSize);
    EmitApiHookWin32("VirtualUnlock",
        (UINT64)(ULONG_PTR)lpAddress, (UINT64)dwSize, 0, 0, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

LPVOID WINAPI Hooked_VirtualAlloc2(HANDLE Process, LPVOID BaseAddress, SIZE_T Size, DWORD AllocationType, DWORD PageProtection, PVOID ExtendedParameters, ULONG ParameterCount)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualAlloc2)
        return Real_VirtualAlloc2 ? Real_VirtualAlloc2(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = Real_VirtualAlloc2(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount);
    EmitApiHookWin32("VirtualAlloc2",
        (UINT64)(ULONG_PTR)Process, (UINT64)(ULONG_PTR)BaseAddress,
        (UINT64)Size, ((UINT64)AllocationType << 32) | PageProtection,
        (UINT64)(ULONG_PTR)p, p != nullptr);
    SetInHook(false);
    return p;
}

LPVOID WINAPI Hooked_VirtualAllocFromApp(PVOID BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualAllocFromApp)
        return Real_VirtualAllocFromApp ? Real_VirtualAllocFromApp(BaseAddress, Size, AllocationType, PageProtection) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = Real_VirtualAllocFromApp(BaseAddress, Size, AllocationType, PageProtection);
    EmitApiHookWin32("VirtualAllocFromApp",
        (UINT64)(ULONG_PTR)BaseAddress, (UINT64)Size,
        (UINT64)AllocationType, (UINT64)PageProtection,
        (UINT64)(ULONG_PTR)p, p != nullptr);
    SetInHook(false);
    return p;
}

LPVOID WINAPI Hooked_VirtualAlloc2FromApp(HANDLE Process, PVOID BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection, PVOID ExtendedParameters, ULONG ParameterCount)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_VirtualAlloc2FromApp)
        return Real_VirtualAlloc2FromApp ? Real_VirtualAlloc2FromApp(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = Real_VirtualAlloc2FromApp(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount);
    EmitApiHookWin32("VirtualAlloc2FromApp",
        (UINT64)(ULONG_PTR)Process, (UINT64)(ULONG_PTR)BaseAddress,
        (UINT64)Size, ((UINT64)AllocationType << 32) | PageProtection,
        (UINT64)(ULONG_PTR)p, p != nullptr);
    SetInHook(false);
    return p;
}

NTSTATUS NTAPI Hooked_NtAllocateVirtualMemoryEx(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationType, ULONG PageProtection, PVOID ExtendedParameters, ULONG ExtendedParameterCount)
{
    if (TlsIsBootstrapping())
        return Real_NtAllocateVirtualMemoryEx ? Real_NtAllocateVirtualMemoryEx(ProcessHandle, BaseAddress, RegionSize, AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount) : STATUS_NOT_IMPLEMENTED;
    if (s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_NtAllocateVirtualMemoryEx || !s_memManager || !BaseAddress || !RegionSize)
        return Real_NtAllocateVirtualMemoryEx ? Real_NtAllocateVirtualMemoryEx(ProcessHandle, BaseAddress, RegionSize, AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount) : STATUS_NOT_IMPLEMENTED;

    RtlHookScope scope;
    SetInHook(true);
    InterlockedIncrement(&s_activeHookCalls);

    const bool currentProc = (ProcessHandle == GetCurrentProcess() ||
                               ProcessHandle == (HANDLE)(ULONG_PTR)-1);
    void* requestedBasePtr = (BaseAddress ? *BaseAddress : nullptr);
    const UINT32 requestedBaseIn = (BaseAddress && *BaseAddress)
        ? (UINT32)(ULONG_PTR)(*BaseAddress) : 0;
    if (currentProc && RegionSize && *RegionSize > 0)
        RecordVaMixCounters(*RegionSize, AllocationType, PageProtection);

    const bool redirect =
        currentProc &&
        (BaseAddress && *BaseAddress == nullptr) &&
        (AllocationType & MEM_RESERVE) &&
        // MEM_WRITE_WATCH excluded — proxy slot cannot satisfy GetWriteWatch.
        !(AllocationType & (MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_LARGE_PAGES)) &&
        !(PageProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
        (*RegionSize >= HEAP_CAPTURE_THRESHOLD || *RegionSize >= kForceVirtualAllocMinSize) &&
        (ExtendedParameters == nullptr || ExtendedParameterCount == 0) &&
        s_memManager &&
        (!s_memManager->GetProxyMaxBytes() || *RegionSize < s_memManager->GetProxyMaxBytes()) &&
        WorkingHooks::IsProxyActive();

    if (redirect) {
        const SIZE_T requested = *RegionSize;
        LPVOID slot = s_memManager->GetProxyAllocator().Allocate(requested, s_memManager->GetProxyAllocator().PrefersTopDown(requested));
        if (slot && VirtualAlloc(slot, requested, MEM_COMMIT, PageProtection)) {
            *BaseAddress = slot;
            *RegionSize = requested;
            VatTrack((UINT_PTR)slot, requested);
            char moduleName[MAX_PATH] = {};
            AllocCallerKind callerKind = ClassifyCallerModule(_ReturnAddress(), moduleName, MAX_PATH);
            ContainmentLane lane = ContainmentLane_FromCallerKind((int)callerKind);
            TS3VASEtw::EmitProxySlotAssigned((UINT32)(ULONG_PTR)slot, (UINT32)requested,
                                             (UINT8)(unsigned)lane, PageProtection);
            TS3VASEtw::EmitVirtualAllocHook(
                requestedBaseIn, (UINT32)requested, AllocationType, PageProtection,
                (UINT32)(ULONG_PTR)slot, /*redirected*/1, /*source=NtEx*/2);
            LogRoGameContext("NtAllocateVirtualMemoryEx",
                requestedBasePtr, requested, AllocationType, PageProtection,
                /*redirectEligible*/true, /*redirected*/true);
            EmitApiHookNt("NtAllocateVirtualMemoryEx",
                (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)requestedBaseIn,
                (UINT64)requested, ((UINT64)AllocationType << 32) | PageProtection,
                (UINT64)(ULONG_PTR)slot, 0);
            InterlockedDecrement(&s_activeHookCalls);
            return 0;
        }
        if (slot)
            s_memManager->GetProxyAllocator().Free(slot, requested);
    }

    NTSTATUS status = Real_NtAllocateVirtualMemoryEx(ProcessHandle, BaseAddress, RegionSize, AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount);
    if (!redirect && currentProc && RegionSize && *RegionSize > 0 && Analytics::GetInstance()) {
        const SIZE_T sz = *RegionSize;
        Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected");
        Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_Bytes", (uint64_t)sz);
        if (BaseAddress && *BaseAddress != nullptr)
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_NonNullBase");
        if (!(AllocationType & MEM_RESERVE))
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_NoReserve");
        if ((AllocationType & MEM_COMMIT) && !(AllocationType & MEM_RESERVE)) {
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_CommitOnly");
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_CommitOnlyBytes", (uint64_t)sz);
        }
        if (AllocationType & MEM_WRITE_WATCH) {
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_WriteWatch");
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_WriteWatchBytes", (uint64_t)sz);
        }
        if (IsExecProtect(PageProtection)) {
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_ExecProtect");
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_ExecProtectBytes", (uint64_t)sz);
        }
        if ((AllocationType & MEM_WRITE_WATCH) && IsExecProtect(PageProtection)) {
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_WriteWatchExec");
            Analytics::GetInstance()->IncrementCounter("NtAllocVMEx_NotRedirected_WriteWatchExecBytes", (uint64_t)sz);
        }
    }
    if (currentProc && RegionSize && *RegionSize > 0) {
        LogRoGameContext("NtAllocateVirtualMemoryEx",
            requestedBasePtr, *RegionSize, AllocationType, PageProtection,
            /*redirectEligible*/redirect, /*redirected*/false);
    }
    if (NT_SUCCESS(status) && currentProc && BaseAddress && *BaseAddress)
        TS3VASEtw::EmitVirtualAllocHook(
            requestedBaseIn, (UINT32)(RegionSize ? *RegionSize : 0), AllocationType, PageProtection,
            (UINT32)(ULONG_PTR)*BaseAddress, /*redirected*/0, /*source=NtEx*/2);

    EmitApiHookNt("NtAllocateVirtualMemoryEx",
        (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)requestedBaseIn,
        (UINT64)(RegionSize ? *RegionSize : 0), ((UINT64)AllocationType << 32) | PageProtection,
        (UINT64)(BaseAddress && *BaseAddress ? (ULONG_PTR)*BaseAddress : 0), status);
    InterlockedDecrement(&s_activeHookCalls);
    return status;
}

HANDLE WINAPI Hooked_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapCreate)
        return Real_HeapCreate ? Real_HeapCreate(flOptions, dwInitialSize, dwMaximumSize) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    HANDLE h = Real_HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
    EmitApiHookWin32("HeapCreate",
        (UINT64)flOptions, (UINT64)dwInitialSize, (UINT64)dwMaximumSize, 0,
        (UINT64)(ULONG_PTR)h, h != nullptr);
    SetInHook(false);
    return h;
}

BOOL WINAPI Hooked_HeapDestroy(HANDLE hHeap)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapDestroy)
        return Real_HeapDestroy ? Real_HeapDestroy(hHeap) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_HeapDestroy(hHeap);
    EmitApiHookWin32("HeapDestroy",
        (UINT64)(ULONG_PTR)hHeap, 0, 0, 0, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

SIZE_T WINAPI Hooked_HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)
{
    // Proxy-heap sub-allocation: a size query on a shard pointer must use the shard.
    if (lpMem && ProxyHeapShardOf(lpMem) >= 0)
        return ProxyHeapSize(dwFlags, lpMem);

    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapSize)
        return Real_HeapSize ? Real_HeapSize(hHeap, dwFlags, lpMem) : (SIZE_T)-1;

    RtlHookScope scope;
    SetInHook(true);
    SIZE_T sz = Real_HeapSize(hHeap, dwFlags, lpMem);
    EmitApiHookWin32Size("HeapSize",
        (UINT64)(ULONG_PTR)hHeap, (UINT64)dwFlags, (UINT64)(ULONG_PTR)lpMem, 0,
        (UINT64)sz, sz == (SIZE_T)-1);
    SetInHook(false);
    return sz;
}

BOOL WINAPI Hooked_HeapValidate(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapValidate)
        return Real_HeapValidate ? Real_HeapValidate(hHeap, dwFlags, lpMem) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_HeapValidate(hHeap, dwFlags, lpMem);
    EmitApiHookWin32("HeapValidate",
        (UINT64)(ULONG_PTR)hHeap, (UINT64)dwFlags, (UINT64)(ULONG_PTR)lpMem, 0, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

SIZE_T WINAPI Hooked_HeapCompact(HANDLE hHeap, DWORD dwFlags)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapCompact)
        return Real_HeapCompact ? Real_HeapCompact(hHeap, dwFlags) : 0;

    RtlHookScope scope;
    SetInHook(true);
    SIZE_T sz = Real_HeapCompact(hHeap, dwFlags);
    EmitApiHookWin32Size("HeapCompact",
        (UINT64)(ULONG_PTR)hHeap, (UINT64)dwFlags, 0, 0, (UINT64)sz, sz == 0);
    SetInHook(false);
    return sz;
}

BOOL WINAPI Hooked_HeapWalk(HANDLE hHeap, LPPROCESS_HEAP_ENTRY lpEntry)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapWalk)
        return Real_HeapWalk ? Real_HeapWalk(hHeap, lpEntry) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_HeapWalk(hHeap, lpEntry);
    EmitApiHookWin32("HeapWalk",
        (UINT64)(ULONG_PTR)hHeap, (UINT64)(ULONG_PTR)lpEntry, 0, 0, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

BOOL WINAPI Hooked_HeapLock(HANDLE hHeap)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapLock)
        return Real_HeapLock ? Real_HeapLock(hHeap) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_HeapLock(hHeap);
    EmitApiHookWin32("HeapLock",
        (UINT64)(ULONG_PTR)hHeap, 0, 0, 0, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

BOOL WINAPI Hooked_HeapUnlock(HANDLE hHeap)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapUnlock)
        return Real_HeapUnlock ? Real_HeapUnlock(hHeap) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_HeapUnlock(hHeap);
    EmitApiHookWin32("HeapUnlock",
        (UINT64)(ULONG_PTR)hHeap, 0, 0, 0, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}

// Global*/Local* movable allocations (GMEM_MOVEABLE/LMEM_MOVEABLE) link a user value
// onto the block via RtlSetUserValueHeap, which only succeeds if the block is a REAL
// heap block. We hook these solely to run them with proxy/sardine redirection SUPPRESSED
// (save/restore the in-hook flag) so their internal RtlAllocateHeap/ReAlloc returns a
// genuine heap block — otherwise the block lands in a shard and RtlSetUserValueHeap
// faults with "Invalid address" (seen via DSOUND/msacm32 audio-driver enum at startup).
// These paths are rare (DSOUND ≈ 2 allocs/session) so bypassing the sardine costs nothing.
HGLOBAL WINAPI Hooked_GlobalAlloc(UINT uFlags, SIZE_T dwBytes) {
    if (!Real_GlobalAlloc) return nullptr;
    const bool was = IsInHook(); if (!was) SetInHook(true);
    HGLOBAL h = Real_GlobalAlloc(uFlags, dwBytes);
    if (!was) SetInHook(false);
    return h;
}
HGLOBAL WINAPI Hooked_GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags) {
    if (!Real_GlobalReAlloc) return nullptr;
    const bool was = IsInHook(); if (!was) SetInHook(true);
    HGLOBAL h = Real_GlobalReAlloc(hMem, dwBytes, uFlags);
    if (!was) SetInHook(false);
    return h;
}
HLOCAL WINAPI Hooked_LocalAlloc(UINT uFlags, SIZE_T uBytes) {
    if (!Real_LocalAlloc) return nullptr;
    const bool was = IsInHook(); if (!was) SetInHook(true);
    HLOCAL h = Real_LocalAlloc(uFlags, uBytes);
    if (!was) SetInHook(false);
    return h;
}
HLOCAL WINAPI Hooked_LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags) {
    if (!Real_LocalReAlloc) return nullptr;
    const bool was = IsInHook(); if (!was) SetInHook(true);
    HLOCAL h = Real_LocalReAlloc(hMem, uBytes, uFlags);
    if (!was) SetInHook(false);
    return h;
}

LPVOID WINAPI Hooked_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    void* const callerRA = _ReturnAddress();   // immediate caller, for graphics exclusion
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapAlloc)
        return Real_HeapAlloc ? Real_HeapAlloc(hHeap, dwFlags, dwBytes) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = nullptr;
    // Classify the heap by its first-seen caller BEFORE the sardine decision, exactly
    // as Hooked_RtlAllocateHeap does — HeapIsSardineExcluded reads that classification
    // and is meaningless until RecordHeapUse has run for this heap.
    RecordHeapUse(hHeap, dwBytes, _ReturnAddress());
    // Sardine packing: sub-64KB into the sharded LFH heaps (exec + graphics-driver
    // heaps excluded).  HeapIsSardineExcluded MUST gate this exactly as it does in
    // Hooked_RtlAllocateHeap: kernel32!HeapAlloc is the path the AMD/NV driver takes,
    // and an in-arena shard tenanted by a graphics-driver alloc gets its heap header
    // smashed when the driver hands the pointer to the GPU/kernel (xcpt DRAKKAR
    // 26-06-05: AMDXN32 -> Hooked_HeapAlloc -> ProxyHeapAlloc -> ntdll heap AV).
    if (ProxyHeapOn() && dwBytes > 0 && dwBytes < kHeapSubAllocMax && !ProxyHeapIsExecHeap(hHeap)
        && !HeapIsSardineExcluded(hHeap) && !CallerIsGraphicsModule(callerRA)) {
        p = ProxyHeapAlloc(dwFlags, dwBytes);
        if (p && Analytics::GetInstance()) {
            Analytics::GetInstance()->IncrementCounter("ProxyHeap_Alloc");
            Analytics::GetInstance()->IncrementCounter("ProxyHeap_AllocBytes", (uint64_t)dwBytes);
        }
        if (p && s_sardineLossProbe) {
            SIZE_T act = ProxyHeapSize(0, p);
            if (act != (SIZE_T)-1) RecordSardineLoss(dwBytes, act);
        }
    }
    if (!p && s_memManager && dwBytes >= kForceHeapProxyMinSize && WorkingHooks::IsProxyActive() && IsForceHeapProxyMode())
        p = s_memManager->CreateProxyAllocation(dwBytes, PAGE_READWRITE);
    if (!p)
        p = Real_HeapAlloc(hHeap, dwFlags, dwBytes);
    Logger* log = Logger::GetInstance();
    if (log && dwBytes >= HEAP_CAPTURE_THRESHOLD)
        log->NamedInfo("MEMHOOK", "HeapAlloc heap=%p flags=0x%X size=%zu -> %p",
                       hHeap, dwFlags, dwBytes, p);
    SetInHook(false);
    return p;
}

BOOL WINAPI Hooked_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    if (lpMem && ProxyHeapFree(dwFlags, lpMem)) {
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("ProxyHeap_Free");
        return TRUE;
    }

    if (lpMem && s_memManager && s_memManager->IsProxyAddress(lpMem)) {
        s_memManager->FreeProxyAllocation(lpMem);
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("HeapFree_Proxy");
        return TRUE;
    }

    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapFree)
        return Real_HeapFree ? Real_HeapFree(hHeap, dwFlags, lpMem) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_HeapFree(hHeap, dwFlags, lpMem);
    Logger* log = Logger::GetInstance();
    if (log)
    {
        if (!ok)
        {
            log->NamedInfo("MEMHOOK", "HeapFree heap=%p flags=0x%X ptr=%p -> FAIL",
                           hHeap, dwFlags, lpMem);
        }
        else
        {
            InterlockedIncrement64(&s_heapFreeOkCount);
        }
    }
    SetInHook(false);
    return ok;
}

LPVOID WINAPI Hooked_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    // Proxy-heap sub-allocation: realloc within the owning shard (route by address).
    if (lpMem && ProxyHeapShardOf(lpMem) >= 0)
        return ProxyHeapReAlloc(dwFlags, lpMem, dwBytes);

    if (lpMem && s_memManager && s_memManager->IsProxyAddress(lpMem)) {
        LPVOID new_ptr = nullptr;
        if ((dwBytes >= HEAP_CAPTURE_THRESHOLD || (dwBytes >= kForceHeapProxyMinSize && IsForceHeapProxyMode())) &&
            WorkingHooks::IsProxyActive() && !WorkingHooks::IsShuttingDown())
            new_ptr = s_memManager->CreateProxyAllocation(dwBytes, PAGE_READWRITE);
        if (!new_ptr)
            new_ptr = Real_HeapAlloc(hHeap, dwFlags, dwBytes);

        if (new_ptr) {
            MemoryManager::ProxyAllocRecord old_rec = {};
            if (s_memManager->FindRecordByAddress(lpMem, &old_rec) &&
                old_rec.proxy_base && old_rec.proxy_size > 0 && dwBytes > 0) {
                SIZE_T copy_sz = std::min(old_rec.proxy_size, dwBytes);
                memcpy(new_ptr, old_rec.proxy_base, copy_sz);
            }
            s_memManager->FreeProxyAllocation(lpMem);
        } else {
            s_memManager->FreeProxyAllocation(lpMem);
        }
        return new_ptr;
    }

    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_HeapReAlloc)
        return Real_HeapReAlloc ? Real_HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = nullptr;
    if (s_memManager && dwBytes >= kForceHeapProxyMinSize && WorkingHooks::IsProxyActive() && IsForceHeapProxyMode()) {
        p = s_memManager->CreateProxyAllocation(dwBytes, PAGE_READWRITE);
        if (p && lpMem) {
            SIZE_T oldSize = HeapSize(hHeap, dwFlags, lpMem);
            if (oldSize != (SIZE_T)-1) {
                SIZE_T copy_sz = std::min(oldSize, dwBytes);
                memcpy(p, lpMem, copy_sz);
            }
            Real_HeapFree(hHeap, dwFlags, lpMem);
        }
    }
    if (!p)
        p = Real_HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);
    Logger* log = Logger::GetInstance();
    if (log && dwBytes >= HEAP_CAPTURE_THRESHOLD)
        log->NamedInfo("MEMHOOK", "HeapReAlloc heap=%p flags=0x%X old=%p size=%zu -> %p",
                       hHeap, dwFlags, lpMem, dwBytes, p);
    SetInHook(false);
    return p;
}

LPVOID WINAPI Hooked_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
                                   DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_MapViewOfFile)
        return Real_MapViewOfFile ? Real_MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap) : nullptr;

    void* const callerRet = _ReturnAddress();
    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = Real_MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
    EmitApiHookWin32("MapViewOfFile",
        (UINT64)(ULONG_PTR)hFileMappingObject, (UINT64)dwDesiredAccess,
        ((UINT64)dwFileOffsetHigh << 32) | dwFileOffsetLow, (UINT64)dwNumberOfBytesToMap,
        (UINT64)(ULONG_PTR)p, p != nullptr);

    // SCRIPT_PROBE: when dwNumberOfBytesToMap == 0 (map whole file) the caller
    // did not specify a size, so we resolve it from the live region before
    // passing to the scanner.  Without this the scanner receives size=0 and
    // returns zero types, silencing every whole-file map.
    if (p && dwNumberOfBytesToMap == 0) {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T effectiveSize = (VirtualQuery(p, &mbi, sizeof(mbi)) == sizeof(mbi)) ? mbi.RegionSize : 0;
        if (effectiveSize > 0) {
            static const uint32_t kMaxTypeStats = 128;
            DbpfTypeStats typeStats[kMaxTypeStats];
            uint32_t typeCount = SafeScanDbpfIndex(p, effectiveSize, typeStats, kMaxTypeStats);
            Logger* log = Logger::GetInstance();
            if (log)
                log->NamedInfo("SCRIPT_PROBE",
                    "MapViewOfFile map=%p resolved_size=%zu KB dbpf_types=%u",
                    p, effectiveSize / 1024, typeCount);
            ProbeScriptAssembly(typeStats, typeCount, p, effectiveSize, callerRet);
        }
    }

    Logger* log = Logger::GetInstance();
    if (log)
        log->NamedInfo("MEMHOOK", "MapViewOfFile map=%p access=0x%X off=%08X:%08X size=%zu -> %p",
                       hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, p);
    SetInHook(false);
    return p;
}

LPVOID WINAPI Hooked_MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
                                     DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_MapViewOfFileEx)
        return Real_MapViewOfFileEx ? Real_MapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress) : nullptr;

    void* const callerRet = _ReturnAddress();
    RtlHookScope scope;
    SetInHook(true);
    LPVOID p = Real_MapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress);
    EmitApiHookWin32("MapViewOfFileEx",
        (UINT64)(ULONG_PTR)hFileMappingObject, (UINT64)dwDesiredAccess,
        ((UINT64)dwFileOffsetHigh << 32) | dwFileOffsetLow, (UINT64)dwNumberOfBytesToMap,
        (UINT64)(ULONG_PTR)p, p != nullptr);

    // SCRIPT_PROBE: same VirtualQuery fallback as Hooked_MapViewOfFile.
    if (p && dwNumberOfBytesToMap == 0) {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T effectiveSize = (VirtualQuery(p, &mbi, sizeof(mbi)) == sizeof(mbi)) ? mbi.RegionSize : 0;
        if (effectiveSize > 0) {
            static const uint32_t kMaxTypeStats = 128;
            DbpfTypeStats typeStats[kMaxTypeStats];
            uint32_t typeCount = SafeScanDbpfIndex(p, effectiveSize, typeStats, kMaxTypeStats);
            ProbeScriptAssembly(typeStats, typeCount, p, effectiveSize, callerRet);
            Logger* log = Logger::GetInstance();
            if (log)
                log->NamedInfo("SCRIPT_PROBE",
                    "MapViewOfFileEx map=%p base=%p resolved_size=%zu KB dbpf_types=%u",
                    p, lpBaseAddress, effectiveSize / 1024, typeCount);
        }
    }

    Logger* log = Logger::GetInstance();
    if (log)
        log->NamedInfo("MEMHOOK", "MapViewOfFileEx map=%p access=0x%X off=%08X:%08X size=%zu base=%p -> %p",
                       hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress, p);
    SetInHook(false);
    return p;
}

BOOL WINAPI Hooked_UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_UnmapViewOfFile)
        return Real_UnmapViewOfFile ? Real_UnmapViewOfFile(lpBaseAddress) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_UnmapViewOfFile(lpBaseAddress);
    EmitApiHookWin32("UnmapViewOfFile",
        (UINT64)(ULONG_PTR)lpBaseAddress, 0, 0, 0, ok ? 1 : 0, ok);
    Logger* log = Logger::GetInstance();
    if (log)
        log->NamedInfo("MEMHOOK", "UnmapViewOfFile base=%p -> %s", lpBaseAddress, ok ? "OK" : "FAIL");
    SetInHook(false);
    return ok;
}

HANDLE WINAPI Hooked_CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_CreateFileMappingA)
        return Real_CreateFileMappingA ? Real_CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    HANDLE h = Real_CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
    EmitApiHookWin32("CreateFileMappingA",
        (UINT64)(ULONG_PTR)hFile, (UINT64)flProtect,
        ((UINT64)dwMaximumSizeHigh << 32) | dwMaximumSizeLow, (UINT64)(ULONG_PTR)lpName,
        (UINT64)(ULONG_PTR)h, h != nullptr);
    SetInHook(false);
    return h;
}

HANDLE WINAPI Hooked_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_CreateFileMappingW)
        return Real_CreateFileMappingW ? Real_CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    HANDLE h = Real_CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
    EmitApiHookWin32("CreateFileMappingW",
        (UINT64)(ULONG_PTR)hFile, (UINT64)flProtect,
        ((UINT64)dwMaximumSizeHigh << 32) | dwMaximumSizeLow, (UINT64)(ULONG_PTR)lpName,
        (UINT64)(ULONG_PTR)h, h != nullptr);
    SetInHook(false);
    return h;
}

HANDLE WINAPI Hooked_OpenFileMappingA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_OpenFileMappingA)
        return Real_OpenFileMappingA ? Real_OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    HANDLE h = Real_OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName);
    EmitApiHookWin32("OpenFileMappingA",
        (UINT64)dwDesiredAccess, (UINT64)bInheritHandle, (UINT64)(ULONG_PTR)lpName, 0,
        (UINT64)(ULONG_PTR)h, h != nullptr);
    SetInHook(false);
    return h;
}

HANDLE WINAPI Hooked_OpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_OpenFileMappingW)
        return Real_OpenFileMappingW ? Real_OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName) : nullptr;

    RtlHookScope scope;
    SetInHook(true);
    HANDLE h = Real_OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName);
    EmitApiHookWin32("OpenFileMappingW",
        (UINT64)dwDesiredAccess, (UINT64)bInheritHandle, (UINT64)(ULONG_PTR)lpName, 0,
        (UINT64)(ULONG_PTR)h, h != nullptr);
    SetInHook(false);
    return h;
}

BOOL WINAPI Hooked_FlushViewOfFile(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown() || !Real_FlushViewOfFile)
        return Real_FlushViewOfFile ? Real_FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush) : FALSE;

    RtlHookScope scope;
    SetInHook(true);
    BOOL ok = Real_FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush);
    EmitApiHookWin32("FlushViewOfFile",
        (UINT64)(ULONG_PTR)lpBaseAddress, (UINT64)dwNumberOfBytesToFlush, 0, 0, ok ? 1 : 0, ok);
    SetInHook(false);
    return ok;
}


// ── NtMapViewOfSection / NtUnmapViewOfSection ─────────────────────────────────
// The Sims 3 loads .package assets via CreateFileMapping → MapViewOfFile which
// calls NtMapViewOfSection.
//
// We intercept, identify .package views, and log/count them for telemetry.  The
// content-redirect path that once moved views into the proxy arena was retired
// with the server (see "Proxy redirect retired" below); package views now pass
// through to the game's own mapped view unchanged.

typedef NTSTATUS (NTAPI* NtMapViewOfSection_t)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);

typedef NTSTATUS (NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);

static NtMapViewOfSection_t   Real_NtMapViewOfSection   = nullptr;
static NtUnmapViewOfSection_t Real_NtUnmapViewOfSection = nullptr;

static void GetMappedBaseName(PVOID addr, char* out, DWORD outBytes)
{
    out[0] = '\0';
    char fullPath[MAX_PATH * 2] = {};
    if (!GetMappedFileNameA(GetCurrentProcess(), addr, fullPath, sizeof(fullPath)))
        return;
    const char* slash = strrchr(fullPath, '\\');
    strncpy_s(out, outBytes, slash ? slash + 1 : fullPath, _TRUNCATE);
}

static void GetMappedFullPath(PVOID addr, char* out, DWORD outBytes)
{
    out[0] = '\0';
    // GetMappedFileNameA returns a device path like \Device\HarddiskVolume3\...
    // Convert to a drive-letter path.
    char devPath[MAX_PATH * 2] = {};
    if (!GetMappedFileNameA(GetCurrentProcess(), addr, devPath, sizeof(devPath)))
        return;
    // Walk drive letters to find matching device
    char drives[512] = {};
    GetLogicalDriveStringsA(sizeof(drives), drives);
    for (char* drv = drives; *drv; drv += strlen(drv) + 1) {
        char drive[3] = { drv[0], drv[1], 0 };  // e.g. "E:"
        char device[MAX_PATH] = {};
        if (QueryDosDeviceA(drive, device, MAX_PATH)) {
            size_t devLen = strlen(device);
            if (_strnicmp(devPath, device, devLen) == 0 && devPath[devLen] == '\\') {
                sprintf_s(out, outBytes, "%s%s", drive, devPath + devLen);
                return;
            }
        }
    }
    // Fallback: return the device path as-is
    strncpy_s(out, outBytes, devPath, _TRUNCATE);
}

static bool IsPackageExtension(const char* filename)
{
    if (!filename || !*filename) return false;
    const char* dot = strrchr(filename, '.');
    if (!dot) return false;
    return _stricmp(dot, ".package") == 0 ||
           _stricmp(dot, ".world")   == 0 ||
           _stricmp(dot, ".sims3")   == 0;
}

// ── Safe memcpy for mapped views ─────────────────────────────────────────────
// MSVC C2712: __try cannot appear in a function that has C++ objects requiring
// unwinding (i.e. anything with a destructor on the stack).  Hooked_NtMapViewOfSection
// uses RtlHookScope, so we isolate the SEH copy here in a plain C helper.
// Returning 0 means the copy faulted (partial or zero bytes copied).
static SIZE_T SafeMapViewCopy(void* dst, const void* src, SIZE_T size)
{
    __try {
        memcpy(dst, src, size);
        return size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

NTSTATUS NTAPI Hooked_NtMapViewOfSection(
    HANDLE         SectionHandle,
    HANDLE         ProcessHandle,
    PVOID*         BaseAddress,
    ULONG_PTR      ZeroBits,
    SIZE_T         CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T        ViewSize,
    ULONG          InheritDisposition,
    ULONG          AllocationType,
    ULONG          Win32Protect)
{
    if (TlsIsBootstrapping())
        return Real_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
            ZeroBits, CommitSize, SectionOffset, ViewSize,
            InheritDisposition, AllocationType, Win32Protect);
    if (s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown())
        return Real_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
            ZeroBits, CommitSize, SectionOffset, ViewSize,
            InheritDisposition, AllocationType, Win32Protect);

    RtlHookScope scope;
    SetInHook(true);
    InterlockedIncrement(&s_activeHookCalls);

    // Always let the real mapping proceed first so we have a valid readable view
    // to inspect (and copy from if we redirect).
    NTSTATUS status = Real_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
        ZeroBits, CommitSize, SectionOffset, ViewSize,
        InheritDisposition, AllocationType, Win32Protect);

    if (!NT_SUCCESS(status) || !BaseAddress || !*BaseAddress || !ViewSize || !*ViewSize) {
        InterlockedDecrement(&s_activeHookCalls);
        return status;
    }

    HANDLE cur = GetCurrentProcess();
    if (ProcessHandle != cur && ProcessHandle != (HANDLE)(ULONG_PTR)-1) {
        InterlockedDecrement(&s_activeHookCalls);
        return status;
    }

    // ── Classify the view ──────────────────────────────────────────────────────
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery(*BaseAddress, &mbi, sizeof(mbi))) {
        InterlockedDecrement(&s_activeHookCalls);
        return status;
    }

    const SIZE_T   viewSz = *ViewSize;
    const LONGLONG secOff = SectionOffset ? SectionOffset->QuadPart : 0;

    // ── Anonymous / image sections — count and log, no redirect ───────────────
    // MEM_PRIVATE = anonymous mapping (no backing file).
    // MEM_IMAGE   = SEC_IMAGE (PE / .dll / .exe) — never a .package.
    if (mbi.Type != MEM_MAPPED) {
        MapViewTypeTracker* tracker = MapViewTypeTracker::GetInstance();
        if (tracker) {
            MapViewTypeTracker::ViewKind k = (mbi.Type == MEM_IMAGE)
                ? MapViewTypeTracker::ViewKind::ImageSection
                : MapViewTypeTracker::ViewKind::Anonymous;
            tracker->RecordView(k, nullptr, (uint64_t)viewSz, false);
        }
        if (Analytics::GetInstance()) {
            Analytics::GetInstance()->IncrementCounter("MapView_Total");
            Analytics::GetInstance()->IncrementCounter(
                mbi.Type == MEM_IMAGE ? "MapView_ImageSection" : "MapView_Anonymous");
        }
        // Log large anonymous/image views — these may explain unexpected VAS drops.
        if (viewSz >= 16 * 1024 * 1024 && Logger::GetInstance()) {
            Logger::GetInstance()->Info(
                "[MAPVIEW] Large %s: size=%zu MB  protect=0x%X",
                mbi.Type == MEM_IMAGE ? "IMAGE" : "ANON",
                viewSz / (1024 * 1024), Win32Protect);
        }
        InterlockedDecrement(&s_activeHookCalls);
        return status;
    }

    // ── MEM_MAPPED file-backed view ────────────────────────────────────────────
    // GetMappedFileNameA returns a device path e.g. \Device\HarddiskVolumeN\...
    // On failure (anonymous section from INVALID_HANDLE_VALUE, Wine quirk, etc.)
    // devPath stays empty — we count and log those separately.
    char devPath[MAX_PATH * 2] = {};
    char baseName[MAX_PATH]    = {};
    bool gotName = (GetMappedFileNameA(cur, *BaseAddress, devPath, sizeof(devPath)) != 0);

    if (gotName && devPath[0]) {
        const char* slash = strrchr(devPath, '\\');
        strncpy_s(baseName, sizeof(baseName), slash ? slash + 1 : devPath, _TRUNCATE);
    }

    // Belt-and-suspenders: also check the drive-letter path for the extension.
    // GetMappedBaseName only uses the device path; some Windows/Wine configs
    // format it differently, so we validate against both representations.
    char fullPath[MAX_PATH * 2] = {};
    if (gotName)
        GetMappedFullPath(*BaseAddress, fullPath, sizeof(fullPath));

    bool isPackageExt = IsPackageExtension(baseName) || IsPackageExtension(fullPath);

    // Global counters — always increment so the analytics report is complete.
    if (Analytics::GetInstance()) {
        Analytics::GetInstance()->IncrementCounter("MapView_Total");
        Analytics::GetInstance()->IncrementCounter("MapView_FileMapped");
        if (!gotName || !devPath[0])
            Analytics::GetInstance()->IncrementCounter("MapView_FileMapped_NoName");
        else if (isPackageExt)
            Analytics::GetInstance()->IncrementCounter("MapView_Package");
        else
            Analytics::GetInstance()->IncrementCounter("MapView_FileMapped_Other");
    }

    // ── No-name MEM_MAPPED view ────────────────────────────────────────────────
    if (!gotName || !devPath[0]) {
        MapViewTypeTracker* tracker = MapViewTypeTracker::GetInstance();
        if (tracker)
            tracker->RecordView(MapViewTypeTracker::ViewKind::FileMappedNoName,
                                nullptr, (uint64_t)viewSz, false);
        if (viewSz >= 4 * 1024 * 1024 && Logger::GetInstance()) {
            Logger::GetInstance()->Info(
                "[MAPVIEW] MEM_MAPPED no-name: size=%zu MB  off=%lld  protect=0x%X"
                "  (GetMappedFileNameA err=%lu)",
                viewSz / (1024 * 1024), secOff, Win32Protect, GetLastError());
        }
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("MapView_FileMapped_NoName_Bytes",
                                                       (uint64_t)viewSz);
        InterlockedDecrement(&s_activeHookCalls);
        return status;
    }

    // ── Non-package file-backed view — log if large, pass through ─────────────
    if (!isPackageExt) {
        MapViewTypeTracker* tracker = MapViewTypeTracker::GetInstance();
        if (tracker)
            tracker->RecordView(MapViewTypeTracker::ViewKind::FileMappedOther,
                                baseName, (uint64_t)viewSz, false);
        if (viewSz >= 4 * 1024 * 1024 && Logger::GetInstance()) {
            Logger::GetInstance()->Info(
                "[MAPVIEW] Other file: %-40s  size=%zu MB  off=%lld",
                baseName, viewSz / (1024 * 1024), secOff);
        }
        InterlockedDecrement(&s_activeHookCalls);
        return status;
    }

    // ── Package-extension view ─────────────────────────────────────────────────
    // Scan the DBPF index regardless of proxy state — we always want the
    // type inventory even on runs where redirect is disabled or not yet ready.
    static const uint32_t kMaxTypeStats = 128;
    DbpfTypeStats typeStats[kMaxTypeStats];
    uint32_t      typeCount = ScanDbpfIndex(*BaseAddress, viewSz, typeStats, kMaxTypeStats);
    bool          hasDbpf   = (typeCount > 0);
    if (hasDbpf)
        InterlockedExchange64(&s_lastDbpfMapTickMs, (LONG64)GetTickCount64());

    // S3SA script-assembly detection (NtMapViewOfSection is the primary package
    // load path).  Reuses the scan above; logs to the dedicated SCRIPT_HIGHWAY
    // channel only when a script assembly is present.
    if (hasDbpf)
        ProbeScriptAssembly(typeStats, typeCount, *BaseAddress, viewSz, _ReturnAddress());

    {
        MapViewTypeTracker* tracker = MapViewTypeTracker::GetInstance();
        if (tracker) {
            MapViewTypeTracker::ViewKind k = hasDbpf
                ? MapViewTypeTracker::ViewKind::FileMappedDbpf
                : MapViewTypeTracker::ViewKind::FileMappedPackage;
            tracker->RecordView(k, baseName, (uint64_t)viewSz, false);
            if (hasDbpf)
                tracker->RecordDbpfTypes(typeStats, typeCount);
        }
    }

    if (Analytics::GetInstance())
        Analytics::GetInstance()->IncrementCounter("MapView_PackageBytes", (uint64_t)viewSz);

    // Log every package view — this is the primary diagnostic signal.
    if (Logger::GetInstance()) {
        Logger::GetInstance()->Info(
            "[MAPVIEW] Package: %-40s  size=%zu KB  off=%lld  dbpf=%s  types=%u",
            baseName, viewSz / 1024, secOff,
            hasDbpf ? "YES" : "NO (not DBPF or offset view)", typeCount);
    }

    // Per-package resource catalog — what comes out of this DBPF, by type and size.
    // One line per resource type: readable type name + entry count + total bytes.
    if (hasDbpf && typeCount > 0 && Logger::GetInstance()) {
        for (uint32_t ti = 0; ti < typeCount; ++ti) {
            Logger::GetInstance()->NamedInfo("DBPF_CATALOG",
                "%-36s  type=%-12s  count=%-5u  bytes=%llu KB",
                baseName, DbpfTypeName(typeStats[ti].typeId),
                (unsigned)typeStats[ti].entryCount,
                (unsigned long long)(typeStats[ti].totalMemBytes / 1024));
        }
    }

    // ── Proxy redirect retired ─────────────────────────────────────────────────
    // The DBPF stub/restore path required the (now-removed) server.
    // Package views are inspected for telemetry above, then pass through to the
    // game's own mapped view unchanged.
    InterlockedDecrement(&s_activeHookCalls);
    return status;
}

NTSTATUS NTAPI Hooked_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
    if (TlsIsBootstrapping() || s_tlHookActive || IsInHook() || WorkingHooks::IsShuttingDown())
        return Real_NtUnmapViewOfSection(ProcessHandle, BaseAddress);

    // If this is a proxy address we redirected, free the proxy allocation.
    if (s_memManager && s_memManager->IsProxyAddress(BaseAddress)) {
        s_memManager->FreeProxyAllocation(BaseAddress);
        if (Analytics::GetInstance())
            Analytics::GetInstance()->IncrementCounter("UnmapView_ProxyFreed");
        return 0; // STATUS_SUCCESS
    }

    if (Analytics::GetInstance())
        Analytics::GetInstance()->IncrementCounter("UnmapView_Total");

#ifdef TS3VAS_TELEMETRY
    // Free-side counterpart to the PACKAGE_LOAD report: is a file-mapped (package) view
    // being released?  If this stays ~0 while packages keep loading, mapped packages
    // accumulate in VAS and are never reclaimed.
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(BaseAddress, &mbi, sizeof(mbi)) && mbi.Type == MEM_MAPPED) {
            char dev[MAX_PATH * 2] = {};
            const char* base = nullptr;
            if (GetMappedFileNameA(GetCurrentProcess(), BaseAddress, dev, sizeof(dev)) && dev[0]) {
                const char* slash = strrchr(dev, '\\');
                base = slash ? slash + 1 : dev;
            }
            const bool pkg = base && IsPackageExtension(base);
            if (Analytics::GetInstance()) {
                Analytics::GetInstance()->IncrementCounter(pkg ? "Packages_Unmapped"
                                                               : "MapView_FileMapped_Unmapped");
                Analytics::GetInstance()->IncrementCounter("MapView_FileMapped_Unmapped_KB",
                                                           (uint64_t)(mbi.RegionSize / 1024));
            }
            if (pkg && Logger::GetInstance())
                Logger::GetInstance()->NamedInfo("PACKAGE_LOAD", "UNMAP %-42s  size=%zu KB",
                                                 base, mbi.RegionSize / 1024);
        }
    }
#endif

    return Real_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

// ── DumpUnfreedAssets ─────────────────────────────────────────────────────────
// Snapshot every still-tracked large local VirtualAlloc reserve at world-exit
// time.  Called from HeartbeatMonitor when the wall-time world-exit trigger
// fires.  Dedicated "UNFREED_ASSETS" channel — no other traffic on it, so it
// parses cleanly.  Declared extern so HeartbeatMonitor.cpp can call it without
// a shared header.
void DumpUnfreedAssets()
{
    Logger* log = Logger::GetInstance();
    if (!log || !s_diagCSInit) return;

    EnterCriticalSection(&s_diagCS);
    const LONG n = s_diagCount;
    if (n == 0) {
        LeaveCriticalSection(&s_diagCS);
        log->NamedInfo("UNFREED_ASSETS", "World-exit snapshot: no tracked local reserves outstanding.");
        return;
    }

    log->NamedInfo("UNFREED_ASSETS",
        "World-exit snapshot: %ld un-freed local reserve(s) still tracked:", n);
    for (LONG i = 0; i < n; i++) {
        const DiagnosticAllocRecord& r = s_diagRecords[i];
        if (!r.address) continue;
        log->NamedInfo("UNFREED_ASSETS",
            "  [%ld] addr=0x%08IX size=%zu KB module=%s retAddr=%p",
            i, (UINT_PTR)r.address, r.size / 1024,
            r.moduleName[0] ? r.moduleName : "<unknown>", r.retAddr);
    }
    LeaveCriticalSection(&s_diagCS);
}

bool WorkingHooks::Install(MemoryManager* memManager)
{
    EmergencyLog("WorkingHooks_Install", "Enter.");
    InterlockedExchange(&s_shuttingDown, 0);
    s_tlsIndex = TlsAlloc();
    if (s_tlsIndex == TLS_OUT_OF_INDEXES) {
        EmergencyLog("WorkingHooks_Install", "TlsAlloc failed.");
        return false;
    }
    s_memManager = memManager;

    // Proxy size policy (tunable per run): lower heap floor = more aggressive capture.
    {
        char v[16] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_PROXY_HEAP_MIN_KB", v, (DWORD)sizeof(v));
        if (n > 0 && n < sizeof(v)) {
            SIZE_T kb = (SIZE_T)atoi(v);
            if (kb > 0) kForceHeapProxyMinSize = kb * 1024;
        }
        const SIZE_T proxyMax = memManager ? memManager->GetProxyMaxBytes() : 0;
        if (proxyMax)
            EmergencyLogF("WorkingHooks_Install",
                "Proxy size window: heap >= %zu KB, VirtualAlloc >= %zu KB, max < %zu MB",
                kForceHeapProxyMinSize / 1024, kForceVirtualAllocMinSize / 1024,
                proxyMax / (1024 * 1024));
        else
            EmergencyLogF("WorkingHooks_Install",
                "Proxy size window: heap >= %zu KB, VirtualAlloc >= %zu KB, max = uncapped",
                kForceHeapProxyMinSize / 1024, kForceVirtualAllocMinSize / 1024);
    }

    // Stand up the sub-64KB proxy heaps (sardine packing) before hooks go live, so
    // they capture from the first allocation.  No-op unless TS3VAS_PROXY_HEAP_SUBALLOC=1.
    ProxyHeapInit();

    MapViewTypeTracker::Initialize();

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hKernelBase = GetModuleHandleA("KernelBase.dll");
    if (!hNtdll) {
        EmergencyLog("WorkingHooks_Install", "ntdll.dll not found.");
        return false;
    }

    VatInit();
    DiagInit();

    Real_RtlCreateHeap           = (RtlCreateHeap_t)          GetProcAddress(hNtdll, "RtlCreateHeap");
    Real_RtlAllocateHeap         = (RtlAllocateHeap_t)        GetProcAddress(hNtdll, "RtlAllocateHeap");
    Real_RtlFreeHeap             = (RtlFreeHeap_t)            GetProcAddress(hNtdll, "RtlFreeHeap");
    Real_RtlReAllocateHeap       = (RtlReAllocateHeap_t)      GetProcAddress(hNtdll, "RtlReAllocateHeap");
    Real_NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    Real_NtFreeVirtualMemory     = (NtFreeVirtualMemory_t)    GetProcAddress(hNtdll, "NtFreeVirtualMemory");
    Real_NtAllocateVirtualMemoryEx = (NtAllocateVirtualMemoryEx_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemoryEx");
    Real_NtMapViewOfSection      = (NtMapViewOfSection_t)     GetProcAddress(hNtdll, "NtMapViewOfSection");
    Real_NtUnmapViewOfSection    = (NtUnmapViewOfSection_t)   GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    Real_VirtualAlloc            = (VirtualAlloc_t)           GetProcAddress(hKernel32, "VirtualAlloc");
    Real_VirtualFree             = (VirtualFree_t)            GetProcAddress(hKernel32, "VirtualFree");
    Real_VirtualAllocEx          = (VirtualAllocEx_t)         GetProcAddress(hKernel32, "VirtualAllocEx");
    Real_VirtualFreeEx           = (VirtualFreeEx_t)          GetProcAddress(hKernel32, "VirtualFreeEx");
    Real_VirtualProtect          = (VirtualProtect_t)         GetProcAddress(hKernel32, "VirtualProtect");
    Real_VirtualProtectEx        = (VirtualProtectEx_t)       GetProcAddress(hKernel32, "VirtualProtectEx");
    Real_VirtualQuery            = (VirtualQuery_t)           GetProcAddress(hKernel32, "VirtualQuery");
    Real_VirtualQueryEx          = (VirtualQueryEx_t)         GetProcAddress(hKernel32, "VirtualQueryEx");
    Real_VirtualLock             = (VirtualLock_t)            GetProcAddress(hKernel32, "VirtualLock");
    Real_VirtualUnlock           = (VirtualUnlock_t)          GetProcAddress(hKernel32, "VirtualUnlock");
    Real_VirtualAlloc2           = (VirtualAlloc2_t)          GetProcAddress(hKernel32, "VirtualAlloc2");
    Real_VirtualAllocFromApp     = (VirtualAllocFromApp_t)    GetProcAddress(hKernel32, "VirtualAllocFromApp");
    Real_VirtualAlloc2FromApp    = (VirtualAlloc2FromApp_t)   GetProcAddress(hKernel32, "VirtualAlloc2FromApp");
    Real_HeapAlloc               = (HeapAlloc_t)              GetProcAddress(hKernel32, "HeapAlloc");
    Real_HeapFree                = (HeapFree_t)               GetProcAddress(hKernel32, "HeapFree");
    Real_HeapReAlloc             = (HeapReAlloc_t)            GetProcAddress(hKernel32, "HeapReAlloc");
    Real_HeapCreate              = (HeapCreate_t)             GetProcAddress(hKernel32, "HeapCreate");
    Real_HeapDestroy             = (HeapDestroy_t)            GetProcAddress(hKernel32, "HeapDestroy");
    Real_HeapSize                = (HeapSize_t)               GetProcAddress(hKernel32, "HeapSize");
    Real_HeapValidate            = (HeapValidate_t)           GetProcAddress(hKernel32, "HeapValidate");
    Real_HeapCompact             = (HeapCompact_t)            GetProcAddress(hKernel32, "HeapCompact");
    Real_HeapWalk                = (HeapWalk_t)               GetProcAddress(hKernel32, "HeapWalk");
    Real_HeapLock                = (HeapLock_t)               GetProcAddress(hKernel32, "HeapLock");
    Real_HeapUnlock              = (HeapUnlock_t)             GetProcAddress(hKernel32, "HeapUnlock");
    Real_GlobalAlloc             = (GlobalAlloc_t)            GetProcAddress(hKernel32, "GlobalAlloc");
    Real_GlobalReAlloc           = (GlobalReAlloc_t)          GetProcAddress(hKernel32, "GlobalReAlloc");
    Real_LocalAlloc              = (LocalAlloc_t)             GetProcAddress(hKernel32, "LocalAlloc");
    Real_LocalReAlloc            = (LocalReAlloc_t)           GetProcAddress(hKernel32, "LocalReAlloc");
    Real_MapViewOfFile           = (MapViewOfFile_t)          GetProcAddress(hKernel32, "MapViewOfFile");
    Real_MapViewOfFileEx         = (MapViewOfFileEx_t)        GetProcAddress(hKernel32, "MapViewOfFileEx");
    Real_UnmapViewOfFile         = (UnmapViewOfFile_t)        GetProcAddress(hKernel32, "UnmapViewOfFile");
    Real_CreateFileMappingA      = (CreateFileMappingA_t)     GetProcAddress(hKernel32, "CreateFileMappingA");
    Real_CreateFileMappingW      = (CreateFileMappingW_t)     GetProcAddress(hKernel32, "CreateFileMappingW");
    Real_OpenFileMappingA        = (OpenFileMappingA_t)       GetProcAddress(hKernel32, "OpenFileMappingA");
    Real_OpenFileMappingW        = (OpenFileMappingW_t)       GetProcAddress(hKernel32, "OpenFileMappingW");
    Real_FlushViewOfFile         = (FlushViewOfFile_t)        GetProcAddress(hKernel32, "FlushViewOfFile");
    if (!Real_VirtualAlloc && hKernelBase)
        Real_VirtualAlloc = (VirtualAlloc_t)GetProcAddress(hKernelBase, "VirtualAlloc");
    if (!Real_VirtualFree && hKernelBase)
        Real_VirtualFree = (VirtualFree_t)GetProcAddress(hKernelBase, "VirtualFree");
    if (!Real_VirtualAllocEx && hKernelBase)
        Real_VirtualAllocEx = (VirtualAllocEx_t)GetProcAddress(hKernelBase, "VirtualAllocEx");
    if (!Real_VirtualFreeEx && hKernelBase)
        Real_VirtualFreeEx = (VirtualFreeEx_t)GetProcAddress(hKernelBase, "VirtualFreeEx");
    if (!Real_VirtualProtect && hKernelBase)
        Real_VirtualProtect = (VirtualProtect_t)GetProcAddress(hKernelBase, "VirtualProtect");
    if (!Real_VirtualProtectEx && hKernelBase)
        Real_VirtualProtectEx = (VirtualProtectEx_t)GetProcAddress(hKernelBase, "VirtualProtectEx");
    if (!Real_VirtualQuery && hKernelBase)
        Real_VirtualQuery = (VirtualQuery_t)GetProcAddress(hKernelBase, "VirtualQuery");
    if (!Real_VirtualQueryEx && hKernelBase)
        Real_VirtualQueryEx = (VirtualQueryEx_t)GetProcAddress(hKernelBase, "VirtualQueryEx");
    if (!Real_VirtualLock && hKernelBase)
        Real_VirtualLock = (VirtualLock_t)GetProcAddress(hKernelBase, "VirtualLock");
    if (!Real_VirtualUnlock && hKernelBase)
        Real_VirtualUnlock = (VirtualUnlock_t)GetProcAddress(hKernelBase, "VirtualUnlock");
    if (!Real_VirtualAlloc2 && hKernelBase)
        Real_VirtualAlloc2 = (VirtualAlloc2_t)GetProcAddress(hKernelBase, "VirtualAlloc2");
    if (!Real_VirtualAllocFromApp && hKernelBase)
        Real_VirtualAllocFromApp = (VirtualAllocFromApp_t)GetProcAddress(hKernelBase, "VirtualAllocFromApp");
    if (!Real_VirtualAlloc2FromApp && hKernelBase)
        Real_VirtualAlloc2FromApp = (VirtualAlloc2FromApp_t)GetProcAddress(hKernelBase, "VirtualAlloc2FromApp");
    if (!Real_HeapAlloc && hKernelBase)
        Real_HeapAlloc = (HeapAlloc_t)GetProcAddress(hKernelBase, "HeapAlloc");
    if (!Real_HeapFree && hKernelBase)
        Real_HeapFree = (HeapFree_t)GetProcAddress(hKernelBase, "HeapFree");
    if (!Real_HeapReAlloc && hKernelBase)
        Real_HeapReAlloc = (HeapReAlloc_t)GetProcAddress(hKernelBase, "HeapReAlloc");
    if (!Real_HeapCreate && hKernelBase)
        Real_HeapCreate = (HeapCreate_t)GetProcAddress(hKernelBase, "HeapCreate");
    if (!Real_HeapDestroy && hKernelBase)
        Real_HeapDestroy = (HeapDestroy_t)GetProcAddress(hKernelBase, "HeapDestroy");
    if (!Real_HeapSize && hKernelBase)
        Real_HeapSize = (HeapSize_t)GetProcAddress(hKernelBase, "HeapSize");
    if (!Real_HeapValidate && hKernelBase)
        Real_HeapValidate = (HeapValidate_t)GetProcAddress(hKernelBase, "HeapValidate");
    if (!Real_HeapCompact && hKernelBase)
        Real_HeapCompact = (HeapCompact_t)GetProcAddress(hKernelBase, "HeapCompact");
    if (!Real_HeapWalk && hKernelBase)
        Real_HeapWalk = (HeapWalk_t)GetProcAddress(hKernelBase, "HeapWalk");
    if (!Real_HeapLock && hKernelBase)
        Real_HeapLock = (HeapLock_t)GetProcAddress(hKernelBase, "HeapLock");
    if (!Real_HeapUnlock && hKernelBase)
        Real_HeapUnlock = (HeapUnlock_t)GetProcAddress(hKernelBase, "HeapUnlock");
    if (!Real_GlobalAlloc && hKernelBase)
        Real_GlobalAlloc = (GlobalAlloc_t)GetProcAddress(hKernelBase, "GlobalAlloc");
    if (!Real_GlobalReAlloc && hKernelBase)
        Real_GlobalReAlloc = (GlobalReAlloc_t)GetProcAddress(hKernelBase, "GlobalReAlloc");
    if (!Real_LocalAlloc && hKernelBase)
        Real_LocalAlloc = (LocalAlloc_t)GetProcAddress(hKernelBase, "LocalAlloc");
    if (!Real_LocalReAlloc && hKernelBase)
        Real_LocalReAlloc = (LocalReAlloc_t)GetProcAddress(hKernelBase, "LocalReAlloc");
    if (!Real_MapViewOfFile && hKernelBase)
        Real_MapViewOfFile = (MapViewOfFile_t)GetProcAddress(hKernelBase, "MapViewOfFile");
    if (!Real_MapViewOfFileEx && hKernelBase)
        Real_MapViewOfFileEx = (MapViewOfFileEx_t)GetProcAddress(hKernelBase, "MapViewOfFileEx");
    if (!Real_UnmapViewOfFile && hKernelBase)
        Real_UnmapViewOfFile = (UnmapViewOfFile_t)GetProcAddress(hKernelBase, "UnmapViewOfFile");
    if (!Real_CreateFileMappingA && hKernelBase)
        Real_CreateFileMappingA = (CreateFileMappingA_t)GetProcAddress(hKernelBase, "CreateFileMappingA");
    if (!Real_CreateFileMappingW && hKernelBase)
        Real_CreateFileMappingW = (CreateFileMappingW_t)GetProcAddress(hKernelBase, "CreateFileMappingW");
    if (!Real_OpenFileMappingA && hKernelBase)
        Real_OpenFileMappingA = (OpenFileMappingA_t)GetProcAddress(hKernelBase, "OpenFileMappingA");
    if (!Real_OpenFileMappingW && hKernelBase)
        Real_OpenFileMappingW = (OpenFileMappingW_t)GetProcAddress(hKernelBase, "OpenFileMappingW");
    if (!Real_FlushViewOfFile && hKernelBase)
        Real_FlushViewOfFile = (FlushViewOfFile_t)GetProcAddress(hKernelBase, "FlushViewOfFile");

    if (!Real_RtlCreateHeap || !Real_RtlAllocateHeap || !Real_RtlFreeHeap ||
        !Real_RtlReAllocateHeap || !Real_NtAllocateVirtualMemory ||
        !Real_NtFreeVirtualMemory || !Real_NtMapViewOfSection || !Real_NtUnmapViewOfSection) {
        EmergencyLog("WorkingHooks_Install", "One or more ntdll exports not found.");
        return false;
    }

    EmergencyLogF("WorkingHooks_Install", "Target: RtlCreateHeap           @ %p", (void*)Real_RtlCreateHeap);
    EmergencyLogF("WorkingHooks_Install", "Target: RtlAllocateHeap         @ %p", (void*)Real_RtlAllocateHeap);
    EmergencyLogF("WorkingHooks_Install", "Target: RtlFreeHeap             @ %p", (void*)Real_RtlFreeHeap);
    EmergencyLogF("WorkingHooks_Install", "Target: RtlReAllocateHeap       @ %p", (void*)Real_RtlReAllocateHeap);
    EmergencyLogF("WorkingHooks_Install", "Target: NtAllocateVirtualMemory @ %p", (void*)Real_NtAllocateVirtualMemory);
    EmergencyLogF("WorkingHooks_Install", "Target: NtFreeVirtualMemory     @ %p", (void*)Real_NtFreeVirtualMemory);
    EmergencyLogF("WorkingHooks_Install", "Target: NtMapViewOfSection      @ %p", (void*)Real_NtMapViewOfSection);
    EmergencyLogF("WorkingHooks_Install", "Target: NtUnmapViewOfSection    @ %p", (void*)Real_NtUnmapViewOfSection);
    EmergencyLogF("WorkingHooks_Install", "Target: VirtualAlloc            @ %p", (void*)Real_VirtualAlloc);
    EmergencyLogF("WorkingHooks_Install", "Target: VirtualFree             @ %p", (void*)Real_VirtualFree);
    EmergencyLogF("WorkingHooks_Install", "Target: HeapAlloc               @ %p", (void*)Real_HeapAlloc);
    EmergencyLogF("WorkingHooks_Install", "Target: HeapFree                @ %p", (void*)Real_HeapFree);
    EmergencyLogF("WorkingHooks_Install", "Target: HeapReAlloc             @ %p", (void*)Real_HeapReAlloc);
    EmergencyLogF("WorkingHooks_Install", "Target: MapViewOfFile           @ %p", (void*)Real_MapViewOfFile);
    EmergencyLogF("WorkingHooks_Install", "Target: MapViewOfFileEx         @ %p", (void*)Real_MapViewOfFileEx);
    EmergencyLogF("WorkingHooks_Install", "Target: UnmapViewOfFile         @ %p", (void*)Real_UnmapViewOfFile);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_RtlCreateHeap,           Hooked_RtlCreateHeap);
    DetourAttach(&(PVOID&)Real_RtlAllocateHeap,         Hooked_RtlAllocateHeap);
    DetourAttach(&(PVOID&)Real_RtlFreeHeap,             Hooked_RtlFreeHeap);
    DetourAttach(&(PVOID&)Real_RtlReAllocateHeap,       Hooked_RtlReAllocateHeap);
    DetourAttach(&(PVOID&)Real_NtAllocateVirtualMemory, Hooked_NtAllocateVirtualMemory);
    DetourAttach(&(PVOID&)Real_NtFreeVirtualMemory,     Hooked_NtFreeVirtualMemory);
    if (Real_NtAllocateVirtualMemoryEx) DetourAttach(&(PVOID&)Real_NtAllocateVirtualMemoryEx, Hooked_NtAllocateVirtualMemoryEx);
#ifdef TS3VAS_TELEMETRY   // observe-only: not installed in the play build
    DetourAttach(&(PVOID&)Real_NtMapViewOfSection,      Hooked_NtMapViewOfSection);
#endif
    DetourAttach(&(PVOID&)Real_NtUnmapViewOfSection,    Hooked_NtUnmapViewOfSection);
    if (Real_VirtualAlloc)    DetourAttach(&(PVOID&)Real_VirtualAlloc,    Hooked_VirtualAlloc);
    if (Real_VirtualFree)     DetourAttach(&(PVOID&)Real_VirtualFree,     Hooked_VirtualFree);
#ifdef TS3VAS_TELEMETRY   // observe-only Virtual* hooks: not installed in the play build
    if (Real_VirtualAllocEx)  DetourAttach(&(PVOID&)Real_VirtualAllocEx,  Hooked_VirtualAllocEx);
    if (Real_VirtualFreeEx)   DetourAttach(&(PVOID&)Real_VirtualFreeEx,   Hooked_VirtualFreeEx);
    if (Real_VirtualProtect)  DetourAttach(&(PVOID&)Real_VirtualProtect,  Hooked_VirtualProtect);
    if (Real_VirtualProtectEx)DetourAttach(&(PVOID&)Real_VirtualProtectEx,Hooked_VirtualProtectEx);
    if (Real_VirtualQuery)    DetourAttach(&(PVOID&)Real_VirtualQuery,    Hooked_VirtualQuery);
    if (Real_VirtualQueryEx)  DetourAttach(&(PVOID&)Real_VirtualQueryEx,  Hooked_VirtualQueryEx);
    if (Real_VirtualLock)     DetourAttach(&(PVOID&)Real_VirtualLock,     Hooked_VirtualLock);
    if (Real_VirtualUnlock)   DetourAttach(&(PVOID&)Real_VirtualUnlock,   Hooked_VirtualUnlock);
    if (Real_VirtualAlloc2)   DetourAttach(&(PVOID&)Real_VirtualAlloc2,   Hooked_VirtualAlloc2);
    if (Real_VirtualAllocFromApp) DetourAttach(&(PVOID&)Real_VirtualAllocFromApp, Hooked_VirtualAllocFromApp);
    if (Real_VirtualAlloc2FromApp)DetourAttach(&(PVOID&)Real_VirtualAlloc2FromApp, Hooked_VirtualAlloc2FromApp);
#endif
    if (Real_HeapAlloc)       DetourAttach(&(PVOID&)Real_HeapAlloc,       Hooked_HeapAlloc);
    if (Real_HeapFree)        DetourAttach(&(PVOID&)Real_HeapFree,        Hooked_HeapFree);
    if (Real_HeapReAlloc)     DetourAttach(&(PVOID&)Real_HeapReAlloc,     Hooked_HeapReAlloc);
    if (Real_HeapCreate)      DetourAttach(&(PVOID&)Real_HeapCreate,      Hooked_HeapCreate);
    if (Real_GlobalAlloc)     DetourAttach(&(PVOID&)Real_GlobalAlloc,     Hooked_GlobalAlloc);
    if (Real_GlobalReAlloc)   DetourAttach(&(PVOID&)Real_GlobalReAlloc,   Hooked_GlobalReAlloc);
    if (Real_LocalAlloc)      DetourAttach(&(PVOID&)Real_LocalAlloc,      Hooked_LocalAlloc);
    if (Real_LocalReAlloc)    DetourAttach(&(PVOID&)Real_LocalReAlloc,    Hooked_LocalReAlloc);
#ifdef TS3VAS_TELEMETRY   // observe-only HeapDestroy: not installed in the play build
    if (Real_HeapDestroy)     DetourAttach(&(PVOID&)Real_HeapDestroy,     Hooked_HeapDestroy);
#endif
    if (Real_HeapSize)        DetourAttach(&(PVOID&)Real_HeapSize,        Hooked_HeapSize);
#ifdef TS3VAS_TELEMETRY   // observe-only Heap introspection + map-view/file-mapping hooks
    if (Real_HeapValidate)    DetourAttach(&(PVOID&)Real_HeapValidate,    Hooked_HeapValidate);
    if (Real_HeapCompact)     DetourAttach(&(PVOID&)Real_HeapCompact,     Hooked_HeapCompact);
    if (Real_HeapWalk)        DetourAttach(&(PVOID&)Real_HeapWalk,        Hooked_HeapWalk);
    if (Real_HeapLock)        DetourAttach(&(PVOID&)Real_HeapLock,        Hooked_HeapLock);
    if (Real_HeapUnlock)      DetourAttach(&(PVOID&)Real_HeapUnlock,      Hooked_HeapUnlock);
    if (Real_MapViewOfFile)   DetourAttach(&(PVOID&)Real_MapViewOfFile,   Hooked_MapViewOfFile);
    if (Real_MapViewOfFileEx) DetourAttach(&(PVOID&)Real_MapViewOfFileEx, Hooked_MapViewOfFileEx);
    if (Real_UnmapViewOfFile) DetourAttach(&(PVOID&)Real_UnmapViewOfFile, Hooked_UnmapViewOfFile);
    if (Real_CreateFileMappingA) DetourAttach(&(PVOID&)Real_CreateFileMappingA, Hooked_CreateFileMappingA);
    if (Real_CreateFileMappingW) DetourAttach(&(PVOID&)Real_CreateFileMappingW, Hooked_CreateFileMappingW);
    if (Real_OpenFileMappingA)   DetourAttach(&(PVOID&)Real_OpenFileMappingA,   Hooked_OpenFileMappingA);
    if (Real_OpenFileMappingW)   DetourAttach(&(PVOID&)Real_OpenFileMappingW,   Hooked_OpenFileMappingW);
    if (Real_FlushViewOfFile)    DetourAttach(&(PVOID&)Real_FlushViewOfFile,    Hooked_FlushViewOfFile);
#endif
    LONG err = DetourTransactionCommit();

    if (err != NO_ERROR) {
        EmergencyLogF("WorkingHooks_Install", "DetourTransactionCommit FAILED err=%ld", err);
        if (Logger::GetInstance())
            Logger::GetInstance()->Error("[RTL] CRITICAL: Detours transaction failed (err=%ld) — all hooks UNINSTALLED.", err);
        return false;
    }

    EmergencyLogF("WorkingHooks_Install", "Trampoline: RtlCreateHeap           @ %p", (void*)Real_RtlCreateHeap);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: RtlAllocateHeap         @ %p", (void*)Real_RtlAllocateHeap);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: RtlFreeHeap             @ %p", (void*)Real_RtlFreeHeap);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: RtlReAllocateHeap       @ %p", (void*)Real_RtlReAllocateHeap);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: NtAllocateVirtualMemory @ %p", (void*)Real_NtAllocateVirtualMemory);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: NtFreeVirtualMemory     @ %p", (void*)Real_NtFreeVirtualMemory);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: NtMapViewOfSection      @ %p", (void*)Real_NtMapViewOfSection);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: NtUnmapViewOfSection    @ %p", (void*)Real_NtUnmapViewOfSection);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: VirtualAlloc            @ %p", (void*)Real_VirtualAlloc);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: VirtualFree             @ %p", (void*)Real_VirtualFree);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: HeapAlloc               @ %p", (void*)Real_HeapAlloc);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: HeapFree                @ %p", (void*)Real_HeapFree);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: HeapReAlloc             @ %p", (void*)Real_HeapReAlloc);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: MapViewOfFile           @ %p", (void*)Real_MapViewOfFile);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: MapViewOfFileEx         @ %p", (void*)Real_MapViewOfFileEx);
    EmergencyLogF("WorkingHooks_Install", "Trampoline: UnmapViewOfFile         @ %p", (void*)Real_UnmapViewOfFile);

    if (Logger::GetInstance())
        Logger::GetInstance()->Info(
            "[RTL] Detours transaction committed — all hooks live. "
            "NtMapViewOfSection inspected for .package view telemetry.");

    if (IsForceProxyActiveMode()) {
        WorkingHooks::ActivateProxy();
        if (Logger::GetInstance())
            Logger::GetInstance()->Info("[PROXY] Force-active enabled at install (TS3VAS_FORCE_PROXY_ACTIVE=1).");
    }
    EmergencyLog("WorkingHooks_Install", "Exit success.");
    return true;
}

void WorkingHooks::EnableHooks()
{
    EmergencyLog("WorkingHooks_EnableHooks", "Detours hooks already live — no-op.");
    if (Logger::GetInstance())
        Logger::GetInstance()->Info("[RTL] All hooks enabled.");
}

void WorkingHooks::Uninstall()
{
    EmergencyLog("WorkingHooks_Uninstall", "Enter.");
    WorkingHooks::BeginShutdown();

    EmergencyLogF("WorkingHooks_Uninstall", "Removing RtlCreateHeap           trampoline @ %p", (void*)Real_RtlCreateHeap);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing RtlAllocateHeap         trampoline @ %p", (void*)Real_RtlAllocateHeap);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing RtlFreeHeap             trampoline @ %p", (void*)Real_RtlFreeHeap);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing RtlReAllocateHeap       trampoline @ %p", (void*)Real_RtlReAllocateHeap);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing NtAllocateVirtualMemory trampoline @ %p", (void*)Real_NtAllocateVirtualMemory);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing NtFreeVirtualMemory     trampoline @ %p", (void*)Real_NtFreeVirtualMemory);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing NtMapViewOfSection      trampoline @ %p", (void*)Real_NtMapViewOfSection);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing NtUnmapViewOfSection    trampoline @ %p", (void*)Real_NtUnmapViewOfSection);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing VirtualAlloc            trampoline @ %p", (void*)Real_VirtualAlloc);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing VirtualFree             trampoline @ %p", (void*)Real_VirtualFree);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing HeapAlloc               trampoline @ %p", (void*)Real_HeapAlloc);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing HeapFree                trampoline @ %p", (void*)Real_HeapFree);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing HeapReAlloc             trampoline @ %p", (void*)Real_HeapReAlloc);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing MapViewOfFile           trampoline @ %p", (void*)Real_MapViewOfFile);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing MapViewOfFileEx         trampoline @ %p", (void*)Real_MapViewOfFileEx);
    EmergencyLogF("WorkingHooks_Uninstall", "Removing UnmapViewOfFile         trampoline @ %p", (void*)Real_UnmapViewOfFile);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_RtlCreateHeap,           Hooked_RtlCreateHeap);
    DetourDetach(&(PVOID&)Real_RtlAllocateHeap,         Hooked_RtlAllocateHeap);
    DetourDetach(&(PVOID&)Real_RtlFreeHeap,             Hooked_RtlFreeHeap);
    DetourDetach(&(PVOID&)Real_RtlReAllocateHeap,       Hooked_RtlReAllocateHeap);
    DetourDetach(&(PVOID&)Real_NtAllocateVirtualMemory, Hooked_NtAllocateVirtualMemory);
    DetourDetach(&(PVOID&)Real_NtFreeVirtualMemory,     Hooked_NtFreeVirtualMemory);
    if (Real_NtAllocateVirtualMemoryEx) DetourDetach(&(PVOID&)Real_NtAllocateVirtualMemoryEx, Hooked_NtAllocateVirtualMemoryEx);
#ifdef TS3VAS_TELEMETRY
    DetourDetach(&(PVOID&)Real_NtMapViewOfSection,      Hooked_NtMapViewOfSection);
#endif
    DetourDetach(&(PVOID&)Real_NtUnmapViewOfSection,    Hooked_NtUnmapViewOfSection);
    if (Real_VirtualAlloc)    DetourDetach(&(PVOID&)Real_VirtualAlloc,    Hooked_VirtualAlloc);
    if (Real_VirtualFree)     DetourDetach(&(PVOID&)Real_VirtualFree,     Hooked_VirtualFree);
#ifdef TS3VAS_TELEMETRY
    if (Real_VirtualAllocEx)  DetourDetach(&(PVOID&)Real_VirtualAllocEx,  Hooked_VirtualAllocEx);
    if (Real_VirtualFreeEx)   DetourDetach(&(PVOID&)Real_VirtualFreeEx,   Hooked_VirtualFreeEx);
    if (Real_VirtualProtect)  DetourDetach(&(PVOID&)Real_VirtualProtect,  Hooked_VirtualProtect);
    if (Real_VirtualProtectEx)DetourDetach(&(PVOID&)Real_VirtualProtectEx,Hooked_VirtualProtectEx);
    if (Real_VirtualQuery)    DetourDetach(&(PVOID&)Real_VirtualQuery,    Hooked_VirtualQuery);
    if (Real_VirtualQueryEx)  DetourDetach(&(PVOID&)Real_VirtualQueryEx,  Hooked_VirtualQueryEx);
    if (Real_VirtualLock)     DetourDetach(&(PVOID&)Real_VirtualLock,     Hooked_VirtualLock);
    if (Real_VirtualUnlock)   DetourDetach(&(PVOID&)Real_VirtualUnlock,   Hooked_VirtualUnlock);
    if (Real_VirtualAlloc2)   DetourDetach(&(PVOID&)Real_VirtualAlloc2,   Hooked_VirtualAlloc2);
    if (Real_VirtualAllocFromApp) DetourDetach(&(PVOID&)Real_VirtualAllocFromApp, Hooked_VirtualAllocFromApp);
    if (Real_VirtualAlloc2FromApp)DetourDetach(&(PVOID&)Real_VirtualAlloc2FromApp, Hooked_VirtualAlloc2FromApp);
#endif
    if (Real_HeapAlloc)       DetourDetach(&(PVOID&)Real_HeapAlloc,       Hooked_HeapAlloc);
    if (Real_HeapFree)        DetourDetach(&(PVOID&)Real_HeapFree,        Hooked_HeapFree);
    if (Real_HeapReAlloc)     DetourDetach(&(PVOID&)Real_HeapReAlloc,     Hooked_HeapReAlloc);
    if (Real_HeapCreate)      DetourDetach(&(PVOID&)Real_HeapCreate,      Hooked_HeapCreate);
    if (Real_GlobalAlloc)     DetourDetach(&(PVOID&)Real_GlobalAlloc,     Hooked_GlobalAlloc);
    if (Real_GlobalReAlloc)   DetourDetach(&(PVOID&)Real_GlobalReAlloc,   Hooked_GlobalReAlloc);
    if (Real_LocalAlloc)      DetourDetach(&(PVOID&)Real_LocalAlloc,      Hooked_LocalAlloc);
    if (Real_LocalReAlloc)    DetourDetach(&(PVOID&)Real_LocalReAlloc,    Hooked_LocalReAlloc);
#ifdef TS3VAS_TELEMETRY
    if (Real_HeapDestroy)     DetourDetach(&(PVOID&)Real_HeapDestroy,     Hooked_HeapDestroy);
#endif
    if (Real_HeapSize)        DetourDetach(&(PVOID&)Real_HeapSize,        Hooked_HeapSize);
#ifdef TS3VAS_TELEMETRY
    if (Real_HeapValidate)    DetourDetach(&(PVOID&)Real_HeapValidate,    Hooked_HeapValidate);
    if (Real_HeapCompact)     DetourDetach(&(PVOID&)Real_HeapCompact,     Hooked_HeapCompact);
    if (Real_HeapWalk)        DetourDetach(&(PVOID&)Real_HeapWalk,        Hooked_HeapWalk);
    if (Real_HeapLock)        DetourDetach(&(PVOID&)Real_HeapLock,        Hooked_HeapLock);
    if (Real_HeapUnlock)      DetourDetach(&(PVOID&)Real_HeapUnlock,      Hooked_HeapUnlock);
    if (Real_MapViewOfFile)   DetourDetach(&(PVOID&)Real_MapViewOfFile,   Hooked_MapViewOfFile);
    if (Real_MapViewOfFileEx) DetourDetach(&(PVOID&)Real_MapViewOfFileEx, Hooked_MapViewOfFileEx);
    if (Real_UnmapViewOfFile) DetourDetach(&(PVOID&)Real_UnmapViewOfFile, Hooked_UnmapViewOfFile);
    if (Real_CreateFileMappingA) DetourDetach(&(PVOID&)Real_CreateFileMappingA, Hooked_CreateFileMappingA);
    if (Real_CreateFileMappingW) DetourDetach(&(PVOID&)Real_CreateFileMappingW, Hooked_CreateFileMappingW);
    if (Real_OpenFileMappingA)   DetourDetach(&(PVOID&)Real_OpenFileMappingA,   Hooked_OpenFileMappingA);
    if (Real_OpenFileMappingW)   DetourDetach(&(PVOID&)Real_OpenFileMappingW,   Hooked_OpenFileMappingW);
    if (Real_FlushViewOfFile)    DetourDetach(&(PVOID&)Real_FlushViewOfFile,    Hooked_FlushViewOfFile);
#endif
    LONG err = DetourTransactionCommit();
    if (err != NO_ERROR)
        EmergencyLogF("WorkingHooks_Uninstall", "DetourTransactionCommit FAILED err=%ld", err);

    if (s_vatCSInit)  { DeleteCriticalSection(&s_vatCS);  s_vatCSInit  = false; }
    if (s_diagCSInit) { DeleteCriticalSection(&s_diagCS); s_diagCSInit = false; }
    InterlockedExchange(&s_vatCount,  0);
    InterlockedExchange(&s_diagCount, 0);

    if (s_tlsIndex != TLS_OUT_OF_INDEXES) {
        EmergencyLog("WorkingHooks_Uninstall", "Free TLS index.");
        TlsFree(s_tlsIndex);
        s_tlsIndex = TLS_OUT_OF_INDEXES;
    }

    if (MapViewTypeTracker::GetInstance())
        MapViewTypeTracker::GetInstance()->Report("MAPVIEW_REPORT");
    MapViewTypeTracker::Shutdown();

    s_memManager = nullptr;
    EmergencyLog("WorkingHooks_Uninstall", "Exit.");
}
