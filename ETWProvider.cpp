#include "ETWProvider.h"

// TraceLogging is header-only — no extra .lib needed beyond advapi32 (already linked).
// evntprov.h supplies WINEVENT_LEVEL_* and EVENT_DESCRIPTOR; include it explicitly
// before TraceLoggingProvider.h to ensure the constants are in scope.
#pragma warning(push)
#pragma warning(disable: 4201)   // nameless struct/union inside Windows headers
#include <evntrace.h>            // canonical ETW header; pulls in evntprov.h
#include <TraceLoggingProvider.h>
#pragma warning(pop)

// Defensive fallbacks — these are stable Windows ETW constants that have
// never changed; defined here so WIN32_LEAN_AND_MEAN + SDK quirks can't
// leave them undeclared.
#ifndef WINEVENT_LEVEL_LOG_ALWAYS
#  define WINEVENT_LEVEL_LOG_ALWAYS  0
#  define WINEVENT_LEVEL_CRITICAL    1
#  define WINEVENT_LEVEL_ERROR       2
#  define WINEVENT_LEVEL_WARNING     3
#  define WINEVENT_LEVEL_INFO        4
#  define WINEVENT_LEVEL_VERBOSE     5
#endif

// ── Provider definition ────────────────────────────────────────────────────────
// GUID: {3A1F8D2C-BE47-4C9A-85E0-2A6F3D9C1B74}
// Regenerate with: uuidgen /c  (keep the same value across builds so PerfView
// session files don't need updating).
TRACELOGGING_DEFINE_PROVIDER(
    g_TS3VASProvider,
    "TS3VASManager-Memory",
    (0x3a1f8d2c, 0xbe47, 0x4c9a, 0x85, 0xe0, 0x2a, 0x6f, 0x3d, 0x9c, 0x1b, 0x74)
);

// ── Keywords ──────────────────────────────────────────────────────────────────
#define TS3VAS_KW_PROXY   (0x0000000000000001ULL)
#define TS3VAS_KW_VALLOC  (0x0000000000000002ULL)
#define TS3VAS_KW_VFREE   (0x0000000000000004ULL)
#define TS3VAS_KW_API     (0x0000000000000008ULL)

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void TS3VASEtw::Register() {
    TraceLoggingRegister(g_TS3VASProvider);
}

void TS3VASEtw::Unregister() {
    TraceLoggingUnregister(g_TS3VASProvider);
}

// ── Proxy slot events ─────────────────────────────────────────────────────────

void TS3VASEtw::EmitProxySlotAssigned(UINT32 proxyAddr, UINT32 size,
                                      UINT8  lane,      UINT32 protect) {
    TraceLoggingWrite(g_TS3VASProvider, "ProxySlotAssigned",
        TraceLoggingLevel  (WINEVENT_LEVEL_INFO),
        TraceLoggingKeyword(TS3VAS_KW_PROXY),
        TraceLoggingHexUInt32(proxyAddr, "ProxyAddr"),
        TraceLoggingUInt32   (size,      "Size"),
        TraceLoggingUInt8    (lane,      "Lane"),
        TraceLoggingHexUInt32(protect,   "Protect")
    );
}

void TS3VASEtw::EmitProxySlotReleased(UINT32 proxyAddr, UINT32 size) {
    TraceLoggingWrite(g_TS3VASProvider, "ProxySlotReleased",
        TraceLoggingLevel  (WINEVENT_LEVEL_INFO),
        TraceLoggingKeyword(TS3VAS_KW_PROXY),
        TraceLoggingHexUInt32(proxyAddr, "ProxyAddr"),
        TraceLoggingUInt32   (size,      "Size")
    );
}

void TS3VASEtw::EmitProxySlotEvicted(UINT32 proxyAddr, UINT32 size) {
    TraceLoggingWrite(g_TS3VASProvider, "ProxySlotEvicted",
        TraceLoggingLevel  (WINEVENT_LEVEL_WARNING),
        TraceLoggingKeyword(TS3VAS_KW_PROXY),
        TraceLoggingHexUInt32(proxyAddr, "ProxyAddr"),
        TraceLoggingUInt32   (size,      "Size")
    );
}

void TS3VASEtw::EmitProxySlotRestored(UINT32 proxyAddr, UINT32 pageBase) {
    TraceLoggingWrite(g_TS3VASProvider, "ProxySlotRestored",
        TraceLoggingLevel  (WINEVENT_LEVEL_INFO),
        TraceLoggingKeyword(TS3VAS_KW_PROXY),
        TraceLoggingHexUInt32(proxyAddr, "ProxyAddr"),
        TraceLoggingHexUInt32(pageBase,  "PageBase")
    );
}

// ── Hook events ───────────────────────────────────────────────────────────────

void TS3VASEtw::EmitVirtualAllocHook(UINT32 reqAddr,    UINT32 size,
                                     UINT32 allocType,  UINT32 protect,
                                     UINT32 resultAddr, UINT8  redirected,
                                     UINT8  source) {
    TraceLoggingWrite(g_TS3VASProvider, "VirtualAllocHook",
        TraceLoggingLevel  (WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(TS3VAS_KW_VALLOC),
        TraceLoggingHexUInt32(reqAddr,    "RequestedAddr"),
        TraceLoggingUInt32   (size,       "Size"),
        TraceLoggingHexUInt32(allocType,  "AllocType"),
        TraceLoggingHexUInt32(protect,    "Protect"),
        TraceLoggingHexUInt32(resultAddr, "ResultAddr"),
        TraceLoggingUInt8    (redirected, "Redirected"),  // 1=proxy, 0=OS passthrough
        TraceLoggingUInt8    (source,     "Source")       // 0=NtAlloc, 1=VirtualAlloc, 2=NtAllocateVirtualMemoryEx
    );
}

void TS3VASEtw::EmitVirtualFreeHook(UINT32 addr,     UINT32 size,
                                    UINT32 freeType, UINT8  wasProxy) {
    TraceLoggingWrite(g_TS3VASProvider, "VirtualFreeHook",
        TraceLoggingLevel  (WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(TS3VAS_KW_VFREE),
        TraceLoggingHexUInt32(addr,     "Addr"),
        TraceLoggingUInt32   (size,     "Size"),
        TraceLoggingHexUInt32(freeType, "FreeType"),
        TraceLoggingUInt8    (wasProxy, "WasProxy")   // 1=was in proxy arena
    );
}

void TS3VASEtw::EmitApiHookCall(const char* api,
                                UINT64 a0, UINT64 a1, UINT64 a2, UINT64 a3,
                                UINT64 result, UINT32 status,
                                UINT8 source) {
    TraceLoggingWrite(g_TS3VASProvider, "ApiHookCall",
        TraceLoggingLevel  (WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(TS3VAS_KW_API),
        TraceLoggingString (api ? api : "<null>", "Api"),
        TraceLoggingHexUInt64(a0, "A0"),
        TraceLoggingHexUInt64(a1, "A1"),
        TraceLoggingHexUInt64(a2, "A2"),
        TraceLoggingHexUInt64(a3, "A3"),
        TraceLoggingHexUInt64(result, "Result"),
        TraceLoggingHexUInt32(status, "Status"),
        TraceLoggingUInt8(source, "Source"),
        TraceLoggingUInt32(GetCurrentThreadId(), "Tid")
    );
}
