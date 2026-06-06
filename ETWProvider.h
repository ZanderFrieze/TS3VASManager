#pragma once
#include <windows.h>

// ── TS3VASManager ETW provider ────────────────────────────────────────────────
//
// Provider:  "TS3VASManager-Memory"
// GUID:      {3A1F8D2C-BE47-4C9A-85E0-2A6F3D9C1B74}
//
// Keywords:
//   0x1  TS3VAS_KW_PROXY   — proxy slot lifecycle (assign/release)
//   0x2  TS3VAS_KW_VALLOC  — VirtualAlloc hook events
//   0x4  TS3VAS_KW_VFREE   — VirtualFree hook events
//   0x8  TS3VAS_KW_API     — generic API hook passthrough telemetry
//
// Levels:
//   INFO     — proxy lifecycle events (low-frequency, bounded by active allocs)
//   WARNING  — retired lifecycle events (eviction/restore no longer occur)
//   VERBOSE  — per-call hook events (very low overhead when no consumer)
//
// Usage in WPA / PerfView:
//   Enable provider  {3A1F8D2C-BE47-4C9A-85E0-2A6F3D9C1B74}
//   Correlate ProxySlotAssigned.ProxyAddr with kernel VirtualAlloc events
//   to verify every OS reservation has a corresponding internal tracking ID.
//   Any OS VirtualAlloc without a matching ProxySlotAssigned = untracked path.

namespace TS3VASEtw {

    // Call once at DLL startup (before any hooks go live).
    void Register();

    // Call at DLL shutdown — must come before provider members are destroyed.
    void Unregister();

    // ── Proxy-layer semantic events (keyword 0x1) ─────────────────────────────

    // Emitted from MemoryManager::CreateProxyAllocation on success.
    void EmitProxySlotAssigned(UINT32 proxyAddr, UINT32 size,
                               UINT8  lane,      UINT32 protect);

    // Emitted from MemoryManager::FreeProxyAllocation on success.
    void EmitProxySlotReleased(UINT32 proxyAddr, UINT32 size);

    // Retired with the server (eviction/restore no longer occur); kept so the
    // ETW event layout stays stable for any existing trace consumers.
    void EmitProxySlotEvicted (UINT32 proxyAddr, UINT32 size);
    void EmitProxySlotRestored(UINT32 proxyAddr, UINT32 pageBase);

    // ── OS hook events ────────────────────────────────────────────────────────

    // Emitted from Hooked_NtAllocateVirtualMemory, Hooked_VirtualAlloc,
    // and Hooked_NtAllocateVirtualMemoryEx.
    // source: 0 = NtAllocateVirtualMemory path, 1 = VirtualAlloc path, 2 = NtAllocateVirtualMemoryEx path.
    // redirected: 1 = we intercepted to proxy arena, 0 = passed through to OS.
    void EmitVirtualAllocHook(UINT32 reqAddr,    UINT32 size,
                              UINT32 allocType,  UINT32 protect,
                              UINT32 resultAddr, UINT8  redirected,
                              UINT8  source);

    // Emitted from Hooked_NtFreeVirtualMemory.
    // wasProxy: 1 = address was in our proxy arena.
    void EmitVirtualFreeHook (UINT32 addr,     UINT32 size,
                              UINT32 freeType, UINT8  wasProxy);

    // Generic API hook event for broad kernel32/kernelbase coverage.
    // source: 0=Win32 API path (kernel32 or kernelbase export), 2=ntdll path
    // status: Win32 GLE for Win32 APIs (0 on success), NTSTATUS for Nt* APIs.
    void EmitApiHookCall(const char* api,
                         UINT64 a0, UINT64 a1, UINT64 a2, UINT64 a3,
                         UINT64 result, UINT32 status,
                         UINT8 source);

} // namespace TS3VASEtw
