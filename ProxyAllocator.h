#pragma once
#include <Windows.h>

class ProxyAllocator {
public:
    struct Stats {
        SIZE_T arenaSize;
        SIZE_T usedBytes;
        SIZE_T freeBytes;
        SIZE_T largestFreeSpan;
        ULONGLONG activeAllocations;
        ULONGLONG totalAllocationRequests;
        ULONGLONG totalAllocationFailures;
        ULONGLONG totalGrantedBytes;
        ULONGLONG totalFreedBytes;
        ULONGLONG totalReusedBytes;
        ULONGLONG classCachedBytes;      // address space held in size-class reuse caches
        SIZE_T    liveRequestedBytes;    // sum of requested (pre-64KB-rounding) sizes, live
        // Per-band cumulative requested vs granted (64KB-rounded slot) bytes — the arena
        // analogue of the sardine PROXY_HEAP loss probe.  Index = size band (same 8 bands
        // as ALLOC_SIZE_DIST).  Per band, loss% = (slotBytes-reqBytes)/slotBytes.
        ULONGLONG bandReqBytes[8];
        ULONGLONG bandSlotBytes[8];
    };

    ProxyAllocator();
    ~ProxyAllocator();

    bool Initialize(SIZE_T arenaSize);
    // Attach to an already-mapped shared section instead of doing a private VirtualAlloc.
    // The caller owns the mapping lifetime; Shutdown() will NOT VirtualFree it.
    bool InitFromShared(LPVOID base, SIZE_T size);
    void Shutdown();
    // fromTop=true carves fresh space from the high end of the arena (big reserves),
    // false from the low end (sardine carve, mid churn) — opposite-ends placement keeps
    // the two size populations from interleaving and chopping up the middle.
    LPVOID Allocate(SIZE_T size, bool fromTop = false);
    void Free(LPVOID ptr);
    void Free(LPVOID ptr, SIZE_T size);
    bool IsProxyAddress(LPCVOID address) const;
    Stats GetStats();
    // Size-based direction: allocs >= the top-down threshold prefer the high end.
    bool PrefersTopDown(SIZE_T size) const { return size >= m_topDownBytes; }

    // Accessors for WorkingHooks heap redirection
    LPVOID GetBase() const { return m_arenaBase; }
    SIZE_T GetSize() const { return m_arenaSize; }
    DWORD  GetGranularity() const { return m_allocGranularity; }   // active slot granularity

    static SIZE_T AlignUp(SIZE_T v, SIZE_T a);
    static void SetContextTag(BYTE tag);
    static BYTE GetContextTag();

private:
    struct Block { LPVOID address; SIZE_T size; Block* next; };

    static LPVOID AlignUpPtr(LPVOID p, SIZE_T a);

    bool InitNodePool();
    void DestroyNodePool();
    Block* AllocNode();
    void FreeNode(Block* n);

    bool InsertFreeSortedAndCoalesce(LPVOID addr, SIZE_T size);
    Block* TakeFreeFit(SIZE_T size, bool fromTop, SIZE_T& grantedSize, LPVOID& grantedAddr);

    // Size-class reuse caches: keep freed blocks segregated by their (granularity-
    // rounded) size so the next same-size request reuses one directly — a freed
    // 40 MB slot fills the next 40 MB alloc with no split/coalesce, so same-size
    // churn never fragments the arena.  Empty class → fall back to TakeFreeFit.
    Block* PopSizeClass(SIZE_T classSize);              // exact-class reuse, or null
    bool   PushSizeClass(LPVOID addr, SIZE_T classSize); // cache; false → coalesce
    void   ReclaimCache();                               // flush all caches to free list

    LPVOID ReserveArenaContiguous(SIZE_T size);

    static void IncTlsDepth();
    static void DecTlsDepth();
    static DWORD GetTlsDepth();

    LPVOID m_arenaBase;
    SIZE_T m_arenaSize;
    DWORD  m_allocGranularity;
    SIZE_T m_topDownBytes;   // allocs >= this carve from the high end (env TS3VAS_PROXY_TOPDOWN_KB)
    bool   m_ownsArena;   // false when arena is a shared mapping (InitFromShared)

    CRITICAL_SECTION m_cs;

    LPVOID m_nodePoolMem;
    SIZE_T m_nodePoolSize;
    Block* m_nodeFreeList;
    Block* m_freeListHead;
    SIZE_T m_usedBytes;
    SIZE_T m_liveRequestedBytes;   // sum of REQUESTED (pre-rounding) sizes for live allocs
    ULONGLONG m_activeAllocations;
    ULONGLONG m_totalAllocationRequests;
    ULONGLONG m_totalAllocationFailures;
    ULONGLONG m_totalGrantedBytes;
    ULONGLONG m_totalFreedBytes;
    ULONGLONG m_totalReusedBytes;
    bool m_hasMainArenaFree;

    // Size-class reuse caches (one free list per distinct granularity-rounded size).
    struct SizeClassList { SIZE_T classSize; Block* head; int count; };
    static const int kMaxSizeClasses    = 256;  // distinct sizes tracked (4KB gran => more)
    static const int kMaxCachedPerClass = 16;   // cap per class → overflow coalesces
    SizeClassList m_sizeClasses[kMaxSizeClasses];
    int           m_sizeClassCount;
    ULONGLONG     m_classCachedBytes;

    // Cumulative per-band requested vs granted (slot) bytes for the slot-rounding loss
    // meter (the ≥64KB arena analogue of the sub-64KB sardine loss probe).  Updated
    // under m_cs on every Allocate; never decremented (lifetime totals, like the sardine).
    ULONGLONG     m_bandReqBytes[8];
    ULONGLONG     m_bandSlotBytes[8];

    static DWORD s_tlsIndexDepth;
    static DWORD s_tlsIndexCtx;

    ProxyAllocator(const ProxyAllocator&) = delete;
    ProxyAllocator& operator=(const ProxyAllocator&) = delete;

    friend DWORD ProxyAllocator_GetTlsDepth();
    friend BYTE ProxyAllocator_GetContextTag();
};

extern "C" {
    __declspec(dllexport) void     ProxyTrace_SetContextTag(BYTE tag);
    __declspec(dllexport) BYTE     ProxyTrace_GetContextTag();
    __declspec(dllexport) SIZE_T   ProxyTrace_CopySnapshot(void* dst, SIZE_T bytes);
    __declspec(dllexport) void     ProxyTrace_Mark(DWORD code, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx);
    __declspec(dllexport) DWORD    ProxyTrace_SpanBegin(DWORD code, HANDLE h, SIZE_T a, SIZE_T b, BYTE ctx);
    __declspec(dllexport) void     ProxyTrace_SpanEnd(DWORD spanId, DWORD code, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx);
}
