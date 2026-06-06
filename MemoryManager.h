#pragma once
// MemoryManager.h  (TS3VASManager.dll — 32-bit, in-game)
// ─────────────────────────────────────────────────────────────────────────────
// Lightweight proxy-allocation manager.  Allocations are carved from a single
// private 1 GB arena (ProxyAllocator); the game's large allocs are redirected
// into it so they land in one contiguous, recyclable region of address space.
//
// Key behaviours:
//   • The arena is a single private reservation (ProxyAllocator::Initialize).
//   • Each slot is eager-committed at allocation, so proxy pages are usable the
//     moment the game receives the pointer — no page-fault handler needed.
// ─────────────────────────────────────────────────────────────────────────────

#include <windows.h>
#include <map>
#include <vector>
#include <utility>
#include <cstdint>
#include "ProxyAllocator.h"
#include "ContainmentLane.h"   // ContainmentLane

class MemoryManager {
public:
    // ── Stats ─────────────────────────────────────────────────────────────────
    struct Stats {
        SIZE_T    proxyArenaSize;
        SIZE_T    proxyUsedBytes;
        SIZE_T    proxyFreeBytes;
        SIZE_T    proxyLargestFreeSpan;
        ULONGLONG activeAllocations;
        ULONGLONG totalAllocationRequests;
        ULONGLONG totalAllocationFailures;
        ULONGLONG totalGrantedBytes;
        ULONGLONG totalFreedBytes;
        ULONGLONG totalReusedBytes;
    };

    // ── Per-allocation record — intentionally minimal ─────────────────────────
    // Intentionally minimal — no per-page maps or backing buffers.
    struct ProxyAllocRecord {
        LPVOID          proxy_base;
        SIZE_T          proxy_size;
        DWORD           protection;
        ContainmentLane lane;
        DWORD           alloc_tick;
    };

    MemoryManager();
    ~MemoryManager();

    bool Initialize();

    // ── Core allocation API ───────────────────────────────────────────────────
    // lane defaults to CONTAINED_A; EXCLUDED_* labels graphics-driver allocations.
    // The lane is telemetry only — it does not change placement.
    LPVOID CreateProxyAllocation(SIZE_T size, DWORD protect,
                                  ContainmentLane lane = ContainmentLane::LANE_CONTAINED_A);
    bool   FreeProxyAllocation(LPVOID proxy_ptr);

    // True if the most recent CreateProxyAllocation on this thread declined
    // because the caller was our own DLL (CallerIsSelf) — an intentional skip,
    // not a capture failure.  Read by the RtlAllocateHeap hook.
    static bool LastCreateWasSelfSkip();

    // ── Graphics write-watch corral ───────────────────────────────────────────
    // A reserved MEM_WRITE_WATCH zone CLAIMED at init so the game cannot scatter its
    // write-watch graphics reserves across VAS.  We sub-allocate slots from it (the
    // game commits + GetWriteWatch within its own slot); the slot's VirtualFree is
    // intercepted and recycled.  Peak fill is tracked so the reservation can be
    // right-sized — ReportCorralUsage flags <50% peak fill as oversized.
    LPVOID CorralReserve(SIZE_T size, DWORD allocType, DWORD protect);
    bool   CorralFree(LPVOID addr);
    bool   IsCorralAddress(LPCVOID addr) const;
    void   ReportCorralUsage();

    // ── Address queries ───────────────────────────────────────────────────────
    bool IsProxyAddress(LPCVOID p);
    bool FindRecordByAddress(LPCVOID address, ProxyAllocRecord* out_rec);

    LPVOID GetProxyArenaBase() const;
    SIZE_T GetProxyArenaSize() const;

    // Upper bound on proxy eligibility: allocations >= this stay local (the game's
    // only >4MB allocs are 3 one-shot load-screen reserves — not worth a contiguous
    // arena slice).  0 = no cap.  Env TS3VAS_PROXY_MAX_MB, set in Initialize().
    SIZE_T GetProxyMaxBytes() const { return m_proxyMaxBytes; }

    // Direct allocator access for the VirtualAlloc redirect path
    ProxyAllocator& GetProxyAllocator() { return m_proxyAllocator; }

    Stats GetStats();
    void  ReportStats(const char* logName);

    // Returns the current live bytes used across all script-arena (corral) segments.
    // Used as a fallback for script_heap when the C# companion shared-memory bridge
    // is not connected (ProxyGc::GetScriptHeapBytes() == 0).
    SIZE_T GetCorralUsedBytes();

private:
    bool InitScriptArena();               // reserve the first write-watch segment
    bool AddCorralSegment(SIZE_T size);   // append a new zone (caller holds m_corralCS)

    ProxyAllocator m_proxyAllocator;

    // Graphics write-watch corral: a reserved+guarded zone + its sub-allocator.
    // ── Script write-watch arena (was the "GFX corral") ───────────────────────
    // The data shows d3d9 issues no write-watch reserves; the only customers are
    // Mono's script/JIT exec write-watch reserves.  So this catches ALL write-watch
    // reserves to pull the script heap out of loose VAS, and GROWS on demand (an
    // append-only segment list) so we can measure its live peak.  Each segment is
    // its own MEM_RESERVE|MEM_WRITE_WATCH zone with its own sub-allocator;
    // GetWriteWatch works per sub-range because every zone carries the flag, and we
    // never reset the watch ourselves — the JIT owns that lifecycle.
    static const int         kMaxCorralSegs = 64;
    ProxyAllocator*          m_corralSegAlloc[kMaxCorralSegs]; // one sub-allocator / zone
    LPVOID                   m_corralSegBase[kMaxCorralSegs];
    SIZE_T                   m_corralSegSize[kMaxCorralSegs];
    volatile LONG            m_corralSegCount;   // append-only → lock-free readers ok
    SIZE_T                   m_corralStartBytes; // first segment size
    SIZE_T                   m_corralGrowFloor;  // min size of a grown segment
    SIZE_T                   m_corralMaxReserved;// VAS safety cap on total reservation
    SIZE_T                   m_corralTotalReserved;
    CRITICAL_SECTION         m_corralCS;         // guards growth + m_corralSizes
    std::map<LPVOID, SIZE_T> m_corralSizes;      // slot base -> size (needed to free)
    volatile LONG64          m_corralPeakBytes;  // high-water used across all segments
    bool                     m_corralReady;

    std::map<LPVOID, ProxyAllocRecord>     m_allocations;
    CRITICAL_SECTION                         m_mapCS;
    DWORD                                    m_pageSize;       // for the slot alignment check
    SIZE_T                                   m_proxyMaxBytes;  // proxy upper bound (0=none)
};
