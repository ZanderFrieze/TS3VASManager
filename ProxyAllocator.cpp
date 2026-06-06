#include "ProxyAllocator.h"
#include "ProxyAllocatorTrace.h"
#include "EmergencyLogger.h"
#include <intrin.h>
#include <cstdlib>

static const SIZE_T kNodePoolBytes    = 1024 * 1024;   // 4KB granularity -> finer free list -> more nodes

DWORD ProxyAllocator::s_tlsIndexDepth = TLS_OUT_OF_INDEXES;
DWORD ProxyAllocator::s_tlsIndexCtx   = TLS_OUT_OF_INDEXES;

DWORD ProxyAllocator_GetTlsDepth() { return ProxyAllocator::GetTlsDepth(); }
BYTE ProxyAllocator_GetContextTag() { return ProxyAllocator::GetContextTag(); }

extern "C" __declspec(dllexport) void   ProxyTrace_SetContextTag(BYTE tag) { ProxyAllocator::SetContextTag(tag); }
extern "C" __declspec(dllexport) BYTE   ProxyTrace_GetContextTag() { return ProxyAllocator::GetContextTag(); }
extern "C" __declspec(dllexport) SIZE_T ProxyTrace_CopySnapshot(void* dst, SIZE_T bytes) { return ProxyAllocatorTrace::CopySnapshot(dst, bytes); }
extern "C" __declspec(dllexport) void   ProxyTrace_Mark(DWORD code, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx) { ProxyAllocatorTrace::Mark(code, h, a, b, err, ctx); }
extern "C" __declspec(dllexport) DWORD  ProxyTrace_SpanBegin(DWORD code, HANDLE h, SIZE_T a, SIZE_T b, BYTE ctx) { return ProxyAllocatorTrace::SpanBegin(code, h, a, b, ctx); }
extern "C" __declspec(dllexport) void   ProxyTrace_SpanEnd(DWORD spanId, DWORD code, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx) { ProxyAllocatorTrace::SpanEnd(spanId, code, h, a, b, err, ctx); }

ProxyAllocator::ProxyAllocator()
    : m_arenaBase(nullptr), m_arenaSize(0), m_allocGranularity(0),
      m_nodePoolMem(nullptr), m_nodePoolSize(0), m_nodeFreeList(nullptr),
      m_freeListHead(nullptr), m_usedBytes(0), m_liveRequestedBytes(0), m_activeAllocations(0),
      m_totalAllocationRequests(0), m_totalAllocationFailures(0),
      m_totalGrantedBytes(0), m_totalFreedBytes(0), m_totalReusedBytes(0),
      m_hasMainArenaFree(false), m_ownsArena(false),
      m_sizeClassCount(0), m_classCachedBytes(0), m_topDownBytes(256 * 1024) {
    InitializeCriticalSection(&m_cs);
    memset(m_sizeClasses, 0, sizeof(m_sizeClasses));
    memset(m_bandReqBytes,  0, sizeof(m_bandReqBytes));
    memset(m_bandSlotBytes, 0, sizeof(m_bandSlotBytes));
    SYSTEM_INFO si; GetSystemInfo(&si);
    // 4KB PAGE granularity, not the 64KB allocation granularity: mid-size slots round
    // tight (a 65KB alloc takes ~68KB instead of a 128KB slot, killing the ~50% loss in
    // the 64-256KB band).  The arena is one big reserve and sub-slots commit/decommit at
    // page granularity, so 4KB slots are safe.  Env override TS3VAS_PROXY_ARENA_GRAN_KB.
    DWORD granKB = (si.dwPageSize ? si.dwPageSize : 4096) / 1024;
    {
        char gv[8] = {};
        DWORD gn = GetEnvironmentVariableA("TS3VAS_PROXY_ARENA_GRAN_KB", gv, (DWORD)sizeof(gv));
        if (gn > 0 && gn < sizeof(gv)) {
            int k = atoi(gv);
            if (k == 4 || k == 8 || k == 16 || k == 32 || k == 64) granKB = (DWORD)k;
        }
    }
    m_allocGranularity = granKB * 1024;
    {
        // Allocs >= this carve from the high end of the arena (big reserves cluster at the
        // top); smaller allocs and the sardine carve fill from the low end.
        char tv[8] = {};
        DWORD tn = GetEnvironmentVariableA("TS3VAS_PROXY_TOPDOWN_KB", tv, (DWORD)sizeof(tv));
        if (tn > 0 && tn < sizeof(tv)) { int kb = atoi(tv); if (kb > 0) m_topDownBytes = (SIZE_T)kb * 1024; }
    }
    if (s_tlsIndexDepth == TLS_OUT_OF_INDEXES) { s_tlsIndexDepth = TlsAlloc(); }
    if (s_tlsIndexCtx   == TLS_OUT_OF_INDEXES) { s_tlsIndexCtx   = TlsAlloc(); }
    ProxyAllocatorTrace::Initialize();
    ProxyAllocatorTrace::Mark(0x1000, nullptr, (SIZE_T)m_allocGranularity, 0, 0, 0);
}

ProxyAllocator::~ProxyAllocator() {
    Shutdown();
    DeleteCriticalSection(&m_cs);
    if (s_tlsIndexDepth != TLS_OUT_OF_INDEXES) { TlsFree(s_tlsIndexDepth); s_tlsIndexDepth = TLS_OUT_OF_INDEXES; }
    if (s_tlsIndexCtx   != TLS_OUT_OF_INDEXES) { TlsFree(s_tlsIndexCtx);   s_tlsIndexCtx   = TLS_OUT_OF_INDEXES; }
    ProxyAllocatorTrace::Mark(0x1001, nullptr, 0, 0, 0, GetContextTag());
}

void ProxyAllocator::SetContextTag(BYTE tag) {
    if (s_tlsIndexCtx == TLS_OUT_OF_INDEXES) return;
    TlsSetValue(s_tlsIndexCtx, (PVOID)(SIZE_T)tag);
}

BYTE ProxyAllocator::GetContextTag() {
    if (s_tlsIndexCtx == TLS_OUT_OF_INDEXES) return 0;
    return (BYTE)(SIZE_T)TlsGetValue(s_tlsIndexCtx);
}

SIZE_T ProxyAllocator::AlignUp(SIZE_T v, SIZE_T a) { return (v + (a - 1)) & ~(a - 1); }
LPVOID ProxyAllocator::AlignUpPtr(LPVOID p, SIZE_T a) { return (LPVOID)AlignUp((SIZE_T)p, a); }

void ProxyAllocator::IncTlsDepth() {
    if (s_tlsIndexDepth == TLS_OUT_OF_INDEXES) return;
    DWORD v = (DWORD)(SIZE_T)TlsGetValue(s_tlsIndexDepth);
    TlsSetValue(s_tlsIndexDepth, (PVOID)(SIZE_T)(v + 1));
}
void ProxyAllocator::DecTlsDepth() {
    if (s_tlsIndexDepth == TLS_OUT_OF_INDEXES) return;
    DWORD v = (DWORD)(SIZE_T)TlsGetValue(s_tlsIndexDepth);
    if (v > 0) v -= 1;
    TlsSetValue(s_tlsIndexDepth, (PVOID)(SIZE_T)v);
}
DWORD ProxyAllocator::GetTlsDepth() {
    if (s_tlsIndexDepth == TLS_OUT_OF_INDEXES) return 0;
    return (DWORD)(SIZE_T)TlsGetValue(s_tlsIndexDepth);
}

bool ProxyAllocator::InitNodePool() {
    if (m_nodePoolMem) return true;
    m_nodePoolSize = kNodePoolBytes;
    m_nodePoolMem = VirtualAlloc(nullptr, m_nodePoolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!m_nodePoolMem) return false;
    SIZE_T cap = m_nodePoolSize / sizeof(Block);
    Block* it = (Block*)m_nodePoolMem;
    m_nodeFreeList = nullptr;
    for (SIZE_T i = 0; i < cap; ++i) { it[i].next = m_nodeFreeList; m_nodeFreeList = &it[i]; }
    ProxyAllocatorTrace::Mark(0x1100, nullptr, cap, m_nodePoolSize, 0, GetContextTag());
    return true;
}

void ProxyAllocator::DestroyNodePool() {
    m_nodeFreeList = nullptr;
    if (m_nodePoolMem) { VirtualFree(m_nodePoolMem, 0, MEM_RELEASE); m_nodePoolMem = nullptr; m_nodePoolSize = 0; }
    ProxyAllocatorTrace::Mark(0x1101, nullptr, 0, 0, 0, GetContextTag());
}

ProxyAllocator::Block* ProxyAllocator::AllocNode() {
    if (!m_nodeFreeList) { ProxyAllocatorTrace::Mark(0x1102, nullptr, 0, 0, ERROR_OUTOFMEMORY, GetContextTag()); return nullptr; }
    Block* n = m_nodeFreeList; m_nodeFreeList = m_nodeFreeList->next;
    n->next = nullptr; n->address = nullptr; n->size = 0;
    return n;
}

void ProxyAllocator::FreeNode(Block* n) { if (!n) return; n->next = m_nodeFreeList; m_nodeFreeList = n; }

bool ProxyAllocator::InsertFreeSortedAndCoalesce(LPVOID addr, SIZE_T size) {
    ProxyAllocatorTrace::Mark(0x2000, nullptr, (SIZE_T)addr, size, 0, GetContextTag());
    Block* node = AllocNode(); if (!node) return FALSE;
    node->address = addr; node->size = size;
    if (!m_freeListHead || m_freeListHead->address > addr) { node->next = m_freeListHead; m_freeListHead = node; }
    else { Block* cur = m_freeListHead; while (cur->next && cur->next->address < addr) cur = cur->next; node->next = cur->next; cur->next = node; }
    Block* cur = m_freeListHead;
    while (cur && cur->next) {
        BYTE* curEnd = (BYTE*)cur->address + cur->size;
        if (curEnd == cur->next->address) { Block* nxt = cur->next; cur->size += nxt->size; cur->next = nxt->next; FreeNode(nxt); ProxyAllocatorTrace::Mark(0x2001, nullptr, (SIZE_T)cur->address, cur->size, 0, GetContextTag()); }
        else { cur = cur->next; }
    }
    return true;
}

ProxyAllocator::Block* ProxyAllocator::TakeFreeFit(SIZE_T size, bool fromTop, SIZE_T& grantedSize, LPVOID& grantedAddr) {
    SIZE_T need = AlignUp(size, m_allocGranularity);
    ProxyAllocatorTrace::Mark(0x2100, nullptr, need, 0, 0, GetContextTag());
    if (!fromTop) {
        // Bottom-up: first-fit from the lowest address, carve from the START of the block.
        Block* prev = nullptr; Block* cur = m_freeListHead;
        while (cur) {
            if (cur->size >= need) {
                grantedAddr = cur->address;
                SIZE_T remain = cur->size - need;
                if (remain >= m_allocGranularity) { cur->address = (BYTE*)cur->address + need; cur->size = remain; grantedSize = need; ProxyAllocatorTrace::Mark(0x2101, nullptr, (SIZE_T)grantedAddr, grantedSize, 0, GetContextTag()); return nullptr; }
                else { Block* taken = cur; grantedSize = cur->size; grantedAddr = taken->address; if (prev) prev->next = cur->next; else m_freeListHead = cur->next; taken->next = nullptr; ProxyAllocatorTrace::Mark(0x2102, nullptr, (SIZE_T)grantedAddr, grantedSize, 0, GetContextTag()); return taken; }
            }
            prev = cur; cur = cur->next;
        }
    } else {
        // Top-down: last-fit (highest-address block that fits), carve from the END so big
        // reserves cluster at the top of the arena instead of fragmenting the low/middle.
        Block* prev = nullptr; Block* cur = m_freeListHead;
        Block* bestPrev = nullptr; Block* best = nullptr;
        while (cur) { if (cur->size >= need) { bestPrev = prev; best = cur; } prev = cur; cur = cur->next; }
        if (best) {
            SIZE_T remain = best->size - need;
            if (remain >= m_allocGranularity) { grantedAddr = (BYTE*)best->address + remain; best->size = remain; grantedSize = need; ProxyAllocatorTrace::Mark(0x2101, nullptr, (SIZE_T)grantedAddr, grantedSize, 0, GetContextTag()); return nullptr; }
            else { Block* taken = best; grantedSize = best->size; grantedAddr = best->address; if (bestPrev) bestPrev->next = best->next; else m_freeListHead = best->next; taken->next = nullptr; ProxyAllocatorTrace::Mark(0x2102, nullptr, (SIZE_T)grantedAddr, grantedSize, 0, GetContextTag()); return taken; }
        }
    }
    grantedSize = 0; grantedAddr = nullptr; ProxyAllocatorTrace::Mark(0x2103, nullptr, need, 0, ERROR_NOT_ENOUGH_MEMORY, GetContextTag()); return nullptr;
}

// ── Size-class reuse caches (called under m_cs) ───────────────────────────────
ProxyAllocator::Block* ProxyAllocator::PopSizeClass(SIZE_T classSize) {
    for (int i = 0; i < m_sizeClassCount; ++i) {
        if (m_sizeClasses[i].classSize == classSize && m_sizeClasses[i].head) {
            Block* n = m_sizeClasses[i].head;
            m_sizeClasses[i].head = n->next;
            m_sizeClasses[i].count--;
            n->next = nullptr;
            return n;
        }
    }
    return nullptr;
}

// Drain ALL size-class caches back into the main free list so coalescing can serve
// large requests.  Called when the free list is too small to satisfy an allocation —
// keeps the cache from locking up the arena when the game's working set shifts sizes.
// Caller must hold m_cs.
void ProxyAllocator::ReclaimCache() {
    for (int i = 0; i < m_sizeClassCount; ++i) {
        Block* n = m_sizeClasses[i].head;
        while (n) {
            Block* next = n->next;
            InsertFreeSortedAndCoalesce(n->address, n->size);
            m_hasMainArenaFree = true;
            if (m_classCachedBytes >= n->size) m_classCachedBytes -= n->size;
            FreeNode(n);
            n = next;
        }
        m_sizeClasses[i].head  = nullptr;
        m_sizeClasses[i].count = 0;
    }
}

bool ProxyAllocator::PushSizeClass(LPVOID addr, SIZE_T classSize) {
    int idx = -1;
    for (int i = 0; i < m_sizeClassCount; ++i)
        if (m_sizeClasses[i].classSize == classSize) { idx = i; break; }
    if (idx < 0) {
        if (m_sizeClassCount >= kMaxSizeClasses) return false;   // too many sizes → coalesce
        idx = m_sizeClassCount++;
        m_sizeClasses[idx].classSize = classSize;
        m_sizeClasses[idx].head = nullptr;
        m_sizeClasses[idx].count = 0;
    }
    if (m_sizeClasses[idx].count >= kMaxCachedPerClass) return false;  // cap → coalesce overflow
    Block* n = AllocNode();
    if (!n) return false;
    n->address = addr; n->size = classSize; n->next = m_sizeClasses[idx].head;
    m_sizeClasses[idx].head = n;
    m_sizeClasses[idx].count++;
    return true;
}

LPVOID ProxyAllocator::ReserveArenaContiguous(SIZE_T size) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    BYTE* minA = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* maxA = (BYTE*)si.lpMaximumApplicationAddress;
    SIZE_T gran = m_allocGranularity;
    SIZE_T want = AlignUp(size, gran);
    // Preferred range: extreme-end 1 GB of 32-bit VAS (0xC0000000..0xFFFFFFFF).
    // Keep local fallback aligned with shared-mode pointer geometry.
    const UINT_PTR kArenaBase32 = 0xC0000000u;
    const SIZE_T kArenaSize = (SIZE_T)(1024ULL * 1024ULL * 1024ULL);
    BYTE* prefStart = (BYTE*)kArenaBase32;
    BYTE* prefEnd = prefStart + kArenaSize;
    if (prefStart < minA) prefStart = minA; if (prefEnd > maxA) prefEnd = maxA;
    ProxyAllocatorTrace::Mark(0x1200, nullptr, (SIZE_T)prefStart, (SIZE_T)prefEnd, (DWORD)want, GetContextTag());
    BYTE* p = prefStart;
    while (p < prefEnd) {
        MEMORY_BASIC_INFORMATION mbi; if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_FREE) {
            LPVOID cand = AlignUpPtr(mbi.BaseAddress, gran);
            BYTE* cend = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            if ((BYTE*)cand + want <= cend) {
                LPVOID reserved = VirtualAlloc(cand, want, MEM_RESERVE, PAGE_NOACCESS);
                if (reserved) { ProxyAllocatorTrace::Mark(0x1201, nullptr, (SIZE_T)reserved, want, 0, GetContextTag()); return reserved; }
            }
        }
        BYTE* next = (BYTE*)mbi.BaseAddress + mbi.RegionSize; if (next <= p) break; p = next;
    }
    LPVOID any = VirtualAlloc(nullptr, want, MEM_RESERVE, PAGE_NOACCESS);
    if (any) { ProxyAllocatorTrace::Mark(0x1203, nullptr, (SIZE_T)any, want, 0, GetContextTag()); return any; }
    ProxyAllocatorTrace::Mark(0x12FF, nullptr, want, 0, GetLastError(), GetContextTag());
    return nullptr;
}

bool ProxyAllocator::Initialize(SIZE_T arenaSize) {
    ProxyAllocatorTrace::Mark(0x1002, nullptr, arenaSize, 0, 0, GetContextTag());
    EnterCriticalSection(&m_cs);
    if (m_arenaBase) { LeaveCriticalSection(&m_cs); ProxyAllocatorTrace::Mark(0x1003, nullptr, 0, 0, 0, GetContextTag()); return true; }
    if (!InitNodePool()) { LeaveCriticalSection(&m_cs); ProxyAllocatorTrace::Mark(0x10E0, nullptr, 0, 0, GetLastError(), GetContextTag()); return false; }
    LPVOID reserved = ReserveArenaContiguous(arenaSize);
    if (!reserved) { LeaveCriticalSection(&m_cs); ProxyAllocatorTrace::Mark(0x10EF, nullptr, arenaSize, 0, GetLastError(), GetContextTag()); return false; }
    m_arenaBase = reserved; m_arenaSize = AlignUp(arenaSize, m_allocGranularity); m_freeListHead = nullptr;
    m_ownsArena = true;
    if (!InsertFreeSortedAndCoalesce(m_arenaBase, m_arenaSize)) {
        VirtualFree(m_arenaBase, 0, MEM_RELEASE); m_arenaBase = nullptr; m_arenaSize = 0; m_ownsArena = false;
        LeaveCriticalSection(&m_cs); ProxyAllocatorTrace::Mark(0x10ED, nullptr, 0, 0, ERROR_OUTOFMEMORY, GetContextTag()); return false;
    }
    LeaveCriticalSection(&m_cs);
    ProxyAllocatorTrace::Mark(0x1004, m_arenaBase, m_arenaSize, 0, 0, GetContextTag());
    return true;
}

bool ProxyAllocator::InitFromShared(LPVOID base, SIZE_T size) {
    ProxyAllocatorTrace::Mark(0x1010, base, size, 0, 0, GetContextTag());
    EnterCriticalSection(&m_cs);
    if (m_arenaBase) { LeaveCriticalSection(&m_cs); ProxyAllocatorTrace::Mark(0x1011, nullptr, 0, 0, 0, GetContextTag()); return true; }
    if (!InitNodePool()) { LeaveCriticalSection(&m_cs); ProxyAllocatorTrace::Mark(0x10E3, nullptr, 0, 0, GetLastError(), GetContextTag()); return false; }
    m_arenaBase  = base;
    m_arenaSize  = AlignUp(size, m_allocGranularity);
    m_ownsArena  = false;  // shared mapping — caller unmaps via UnmapViewOfFile
    m_freeListHead = nullptr;
    if (!InsertFreeSortedAndCoalesce(m_arenaBase, m_arenaSize)) {
        m_arenaBase = nullptr; m_arenaSize = 0;
        LeaveCriticalSection(&m_cs); ProxyAllocatorTrace::Mark(0x10E6, nullptr, 0, 0, ERROR_OUTOFMEMORY, GetContextTag()); return false;
    }
    LeaveCriticalSection(&m_cs);
    ProxyAllocatorTrace::Mark(0x1012, m_arenaBase, m_arenaSize, 0, 0, GetContextTag());
    return true;
}

void ProxyAllocator::Shutdown() {
    ProxyAllocatorTrace::Mark(0x1005, nullptr, 0, 0, 0, GetContextTag());
    EmergencyLogF("ProxyAllocator_Shutdown", "Enter. base=%p size=%zu used=%zu active=%llu",
        m_arenaBase, m_arenaSize, m_usedBytes, m_activeAllocations);
    EnterCriticalSection(&m_cs);
    if (m_arenaBase && m_ownsArena) { VirtualFree(m_arenaBase, 0, MEM_RELEASE); }
    m_arenaBase = nullptr; m_arenaSize = 0; m_ownsArena = false;
    m_freeListHead = nullptr;
    m_usedBytes = 0;
    m_activeAllocations = 0;
    m_hasMainArenaFree = false;
    DestroyNodePool();
    LeaveCriticalSection(&m_cs);
    ProxyAllocatorTrace::Mark(0x1006, nullptr, 0, 0, 0, GetContextTag());
    EmergencyLog("ProxyAllocator_Shutdown", "Exit.");
}

// Size band for the slot-rounding loss meter — same 8 bands as ALLOC_SIZE_DIST / the
// proxy size histogram, so the arena loss lines line up with those reports.
static int ProxyArenaBand(SIZE_T size) {
    return (size <       4 * 1024) ? 0 :
           (size <      64 * 1024) ? 1 :
           (size <     256 * 1024) ? 2 :
           (size <     512 * 1024) ? 3 :
           (size <    1024 * 1024) ? 4 :
           (size <  4 * 1024 * 1024) ? 5 :
           (size < 16 * 1024 * 1024) ? 6 : 7;
}

LPVOID ProxyAllocator::Allocate(SIZE_T size, bool fromTop) {
    ProxyAllocatorTrace::Mark(0x3000, nullptr, size, 0, 0, GetContextTag());
    IncTlsDepth();
    // Slab/EBA side allocators removed — everything goes to the main arena so the
    // proxy captures the full small/mid churn (up to the caller's size cap).  Node
    // allocation is pool-backed (not the hooked heap), so Allocate never re-enters
    // itself; the lock is simply blocking on contention.
    if (!TryEnterCriticalSection(&m_cs)) {
        EnterCriticalSection(&m_cs); ProxyAllocatorTrace::Mark(0x3005, nullptr, size, 1, 0, GetContextTag());
    }
    m_totalAllocationRequests++;
    if (!m_arenaBase) { m_totalAllocationFailures++; LeaveCriticalSection(&m_cs); DecTlsDepth(); ProxyAllocatorTrace::Mark(0x30FF, nullptr, size, 0, ERROR_INVALID_ADDRESS, GetContextTag()); return nullptr; }
    SIZE_T grantedSize = 0; LPVOID grantedAddr = nullptr;
    // Size-class reuse first: a freed block of this exact (rounded) size is handed
    // straight back, so same-size churn (40MB→40MB, …) never fragments the arena.
    Block* cached = PopSizeClass(AlignUp(size, m_allocGranularity));
    if (cached) {
        grantedAddr = cached->address;
        grantedSize = cached->size;
        FreeNode(cached);
        if (m_classCachedBytes >= grantedSize) m_classCachedBytes -= grantedSize;
        m_totalReusedBytes += grantedSize;
    } else {
        Block* removed = TakeFreeFit(size, fromTop, grantedSize, grantedAddr);
        if (!grantedAddr && m_classCachedBytes > 0) {
            // Free list couldn't fit the request but the size-class cache holds
            // memory — drain it back so coalescing can produce a large enough block.
            ReclaimCache();
            removed = TakeFreeFit(size, fromTop, grantedSize, grantedAddr);
        }
        if (!grantedAddr) { m_totalAllocationFailures++; LeaveCriticalSection(&m_cs); DecTlsDepth(); ProxyAllocatorTrace::Mark(0x30FE, nullptr, size, 0, ERROR_NOT_ENOUGH_MEMORY, GetContextTag()); return nullptr; }
        if (removed) FreeNode(removed);
    }
    m_usedBytes += grantedSize;
    m_liveRequestedBytes += size;          // pre-rounding requested — tracks both VA and heap paths
    { const int b = ProxyArenaBand(size);  // cumulative per-band req vs slot for the loss meter
      m_bandReqBytes[b]  += size;
      m_bandSlotBytes[b] += grantedSize; }
    m_activeAllocations++;
    m_totalGrantedBytes += grantedSize;
    if (m_hasMainArenaFree) m_totalReusedBytes += grantedSize;
    LeaveCriticalSection(&m_cs);
    DecTlsDepth();
    ProxyAllocatorTrace::Mark(0x3006, nullptr, (SIZE_T)grantedAddr, grantedSize, 0, GetContextTag());
    return grantedAddr;
}

void ProxyAllocator::Free(LPVOID ptr) {
    Free(ptr, m_allocGranularity);
}

void ProxyAllocator::Free(LPVOID ptr, SIZE_T size) {
    if (!ptr) return;
    ProxyAllocatorTrace::Mark(0x3100, nullptr, (SIZE_T)ptr, 0, 0, GetContextTag());
    if (!IsProxyAddress(ptr)) { ProxyAllocatorTrace::Mark(0x31FF, nullptr, (SIZE_T)ptr, 0, ERROR_INVALID_ADDRESS, GetContextTag()); return; }
    if (!TryEnterCriticalSection(&m_cs)) EnterCriticalSection(&m_cs);
    SIZE_T sz = AlignUp(size, m_allocGranularity);
    // Cache the freed block in its size class for exact same-size reuse; coalesce
    // into the main free list only when the class is full / capacity-capped.
    if (PushSizeClass(ptr, sz)) {
        m_classCachedBytes += sz;
    } else {
        InsertFreeSortedAndCoalesce(ptr, sz);
        m_hasMainArenaFree = true;
    }
    m_usedBytes = (m_usedBytes >= sz) ? m_usedBytes - sz : 0;
    m_liveRequestedBytes = (m_liveRequestedBytes >= size) ? m_liveRequestedBytes - size : 0;
    if (m_activeAllocations > 0) m_activeAllocations--;
    m_totalFreedBytes += sz;
    LeaveCriticalSection(&m_cs);
    ProxyAllocatorTrace::Mark(0x3103, nullptr, (SIZE_T)ptr, sz, 0, GetContextTag());
}

bool ProxyAllocator::IsProxyAddress(LPCVOID address) const {
    if (!m_arenaBase) return false;
    const BYTE* b = (const BYTE*)m_arenaBase;
    return address >= m_arenaBase && address < (b + m_arenaSize);
}

ProxyAllocator::Stats ProxyAllocator::GetStats() {
    Stats stats = {};
    EnterCriticalSection(&m_cs);
    stats.arenaSize = m_arenaSize;
    stats.usedBytes = m_usedBytes;
    stats.activeAllocations = m_activeAllocations;
    stats.totalAllocationRequests = m_totalAllocationRequests;
    stats.totalAllocationFailures = m_totalAllocationFailures;
    stats.totalGrantedBytes = m_totalGrantedBytes;
    stats.totalFreedBytes = m_totalFreedBytes;
    stats.totalReusedBytes = m_totalReusedBytes;
    stats.classCachedBytes   = m_classCachedBytes;
    stats.liveRequestedBytes = m_liveRequestedBytes;
    for (int i = 0; i < 8; ++i) {
        stats.bandReqBytes[i]  = m_bandReqBytes[i];
        stats.bandSlotBytes[i] = m_bandSlotBytes[i];
    }

    for (Block* cur = m_freeListHead; cur; cur = cur->next) {
        stats.freeBytes += cur->size;
        if (cur->size > stats.largestFreeSpan)
            stats.largestFreeSpan = cur->size;
    }
    LeaveCriticalSection(&m_cs);
    return stats;
}
