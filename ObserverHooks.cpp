#include "ObserverHooks.h"
#ifdef TS3VAS_TELEMETRY   // entire observe layer compiles out in the "play" build
#include "Logger.h"
#include "HitchDetector.h"
#include "StackWalker.h"
#include "WorkingHooks.h"
#include "Analytics.h"
#include "ScriptScanDedup.h"
#include <detours.h>
#include <d3d9.h>
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>

#pragma comment(lib, "d3d9.lib")

// ── Activation role removed. ──────────────────────────────────────────────
// RtlAllocateHeap hook is live from process start.
// D3D9 hook is now optional frame-hitch telemetry only.
// Do NOT call PatchActivator from here.

typedef HRESULT(WINAPI *Present_t)(IDirect3DDevice9*, const RECT*,
                                    const RECT*, HWND, const RGNDATA*);
static Present_t Real_Present = nullptr;
static HMODULE g_hD3D9 = nullptr;
static std::atomic<bool> g_installed(false);
static std::atomic<bool> g_capInit(false);
static std::atomic<DWORD> g_targetFps(0);
static std::atomic<bool> g_captureHitchStacks(false);
static std::atomic<DWORD> g_hitchLogInterval(25);
static thread_local bool g_inPresentHook = false;

static LARGE_INTEGER g_lastPresentTime = {0};
static LARGE_INTEGER g_qpcFrequency    = {0};
static std::atomic<DWORD> g_presentCallCount(0);
static std::atomic<DWORD> g_hitchCount(0);
static std::atomic<DWORD> g_stackCaptureFailures(0);

// ── D3D9 resource-creation interception (containment-lane classifier) ─────────
// Every texture/buffer the game allocates originates inside d3d9.dll, so the
// low-level caller-module hook can only lump them into one coarse "Graphics"
// bucket.  Hooking the IDirect3DDevice9 resource-creation vtable slots exposes
// each resource's TYPE + POOL + USAGE + SIZE, which is what splits "graphics"
// into the two containment lanes:
//   • EXCLUDED: DEFAULT-pool resources and DYNAMIC vertex/index buffers — the GPU
//     reads these directly and there is no system copy, so they stay out.
//   • CONTAINED: MANAGED / SYSTEMMEM textures — these keep a cold system-memory
//     copy (re-read only on device-lost), the bulk of CAS clothing-texture VAS.
// This is measurement only: intercept + classify + count via analytics counters.
typedef HRESULT (WINAPI* CreateTexture_t)(IDirect3DDevice9*, UINT, UINT, UINT, DWORD, D3DFORMAT, D3DPOOL, IDirect3DTexture9**, HANDLE*);
typedef HRESULT (WINAPI* CreateCubeTexture_t)(IDirect3DDevice9*, UINT, UINT, DWORD, D3DFORMAT, D3DPOOL, IDirect3DCubeTexture9**, HANDLE*);
typedef HRESULT (WINAPI* CreateVolumeTexture_t)(IDirect3DDevice9*, UINT, UINT, UINT, UINT, DWORD, D3DFORMAT, D3DPOOL, IDirect3DVolumeTexture9**, HANDLE*);
typedef HRESULT (WINAPI* CreateVertexBuffer_t)(IDirect3DDevice9*, UINT, DWORD, DWORD, D3DPOOL, IDirect3DVertexBuffer9**, HANDLE*);
typedef HRESULT (WINAPI* CreateIndexBuffer_t)(IDirect3DDevice9*, UINT, DWORD, D3DFORMAT, D3DPOOL, IDirect3DIndexBuffer9**, HANDLE*);

static CreateTexture_t       Real_CreateTexture       = nullptr;
static CreateCubeTexture_t   Real_CreateCubeTexture   = nullptr;
static CreateVolumeTexture_t Real_CreateVolumeTexture = nullptr;
static CreateVertexBuffer_t  Real_CreateVertexBuffer  = nullptr;
static CreateIndexBuffer_t   Real_CreateIndexBuffer   = nullptr;
static std::atomic<bool>     g_resourceHooksInstalled(false);

// ── Device-lost guard (vtable slot 37) ────────────────────────────────────────
// The recurring crash is d3d9!CD3DBase::SetRenderTarget dispatching through a null
// driver thunk (eip=0) after a GPU TDR / device-lost that Sims 3's old renderer
// never guards with TestCooperativeLevel()+Reset().  We cannot Reset the game's
// device for it (the game owns the DEFAULT-pool resources), but we CAN intercept
// the exact faulting call: hook SetRenderTarget and, while the device reports lost,
// return the cooperative-level error instead of letting d3d9 call through the null
// slot.  Converts a guaranteed crash-to-desktop into a survivable no-render state.
typedef HRESULT (WINAPI* SetRenderTarget_t)(IDirect3DDevice9*, DWORD, IDirect3DSurface9*);
static SetRenderTarget_t  Real_SetRenderTarget = nullptr;
static std::atomic<bool>  g_deviceGuard(true);     // TS3VAS_D3D9_DEVICE_GUARD=0 disables
static std::atomic<bool>  g_deviceLost(false);     // last observed cooperative state
static std::atomic<DWORD> g_deviceLostEvents(0);   // # of OK->lost transitions logged
static std::atomic<DWORD> g_guardedCallCount(0);   // # of d3d9 calls short-circuited

// Update the cached lost flag from a TestCooperativeLevel() result, logging the
// OK<->lost transitions exactly once each (never per-frame spam).
static void NoteCoopLevel(HRESULT coop) {
    const bool lost = (coop != D3D_OK);
    const bool was  = g_deviceLost.exchange(lost);
    if (lost && !was) {
        g_deviceLostEvents.fetch_add(1);
        if (Logger::GetInstance())
            Logger::GetInstance()->Warn(
                "[D3D9] DEVICE LOST (TestCooperativeLevel=0x%08X) — render calls guarded; "
                "SetRenderTarget shielded from null driver dispatch. Awaiting device reset.",
                coop);
    } else if (!lost && was) {
        if (Logger::GetInstance())
            Logger::GetInstance()->Info("[D3D9] Device recovered (TestCooperativeLevel=D3D_OK).");
    }
}

static DWORD ResolveTargetFps() {
    if (!g_capInit.exchange(true)) {
        char value[32] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_FPS_CAP", value, (DWORD)sizeof(value));
        DWORD fps = 60; // default cap for smoother testing while preserving TS3 stability
        if (n > 0) {
            fps = (DWORD)strtoul(value, nullptr, 10);
            if (fps > 240) fps = 240;
        }
        g_targetFps.store(fps);

        ZeroMemory(value, sizeof(value));
        n = GetEnvironmentVariableA("TS3VAS_D3D9_CAPTURE_STACKS", value, (DWORD)sizeof(value));
        const bool captureStacks = (n > 0 && n < sizeof(value) &&
            (value[0] == '1' || value[0] == 'y' || value[0] == 'Y' || value[0] == 't' || value[0] == 'T'));
        g_captureHitchStacks.store(captureStacks);

        ZeroMemory(value, sizeof(value));
        n = GetEnvironmentVariableA("TS3VAS_D3D9_HITCH_LOG_INTERVAL", value, (DWORD)sizeof(value));
        if (n > 0 && n < sizeof(value)) {
            DWORD interval = (DWORD)strtoul(value, nullptr, 10);
            if (interval >= 1 && interval <= 1000) {
                g_hitchLogInterval.store(interval);
            }
        }
    }
    return g_targetFps.load();
}

// Park the render thread until `remainingTicks` (QPC units) elapse, WITHOUT a
// busy-spin. A high-resolution waitable timer (~0.5ms, Win10 1803+) lets the
// scheduler sleep the thread and wake it on time, so we pace frames without
// pinning a CPU core (the old SwitchToThread tail did, adding heat under load).
// No process-global timeBeginPeriod side effect. The timer is created once per
// render thread and reused; falls back to a coarse Sleep if it can't be made.
static void FrameCapWait(LONGLONG remainingTicks) {
    if (remainingTicks <= 0 || g_qpcFrequency.QuadPart <= 0) return;
    // QPC ticks -> 100ns units for SetWaitableTimer's relative due time.
    const LONGLONG hundredNs =
        (remainingTicks * 10000000LL) / g_qpcFrequency.QuadPart;
    if (hundredNs <= 0) return;

    static thread_local HANDLE s_timer = nullptr;
    static thread_local bool   s_tried = false;
    if (!s_timer && !s_tried) {
        s_tried = true;
        s_timer = CreateWaitableTimerExW(nullptr, nullptr,
            CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
        if (!s_timer)  // pre-1803: fall back to a standard waitable timer
            s_timer = CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_ALL_ACCESS);
    }
    if (s_timer) {
        LARGE_INTEGER due;
        due.QuadPart = -hundredNs;  // negative = relative time
        if (SetWaitableTimer(s_timer, &due, 0, nullptr, nullptr, FALSE)) {
            WaitForSingleObject(s_timer, INFINITE);
            return;
        }
    }
    // Last-resort fallback: coarse millisecond sleep (never busy-spin).
    const DWORD ms = (DWORD)(hundredNs / 10000LL);
    if (ms > 0) Sleep(ms);
}

HRESULT WINAPI Hooked_Present(
    IDirect3DDevice9* pDevice, const RECT* pSourceRect,
    const RECT* pDestRect,     HWND hDestWindowOverride,
    const RGNDATA* pDirtyRegion)
{
    if (!Real_Present) {
        return D3DERR_INVALIDCALL;
    }
    if (g_inPresentHook || WorkingHooks::IsShuttingDown()) {
        return Real_Present(pDevice, pSourceRect, pDestRect,
                            hDestWindowOverride, pDirtyRegion);
    }
    g_inPresentHook = true;
    struct ScopeExitReset {
        ~ScopeExitReset() { g_inPresentHook = false; }
    } scopeExitReset;

    const DWORD targetFps = ResolveTargetFps();
    const DWORD hitchLogEvery = g_hitchLogInterval.load(std::memory_order_relaxed);
    const bool captureStacks = g_captureHitchStacks.load(std::memory_order_relaxed);

    // Hitch detection only — no activation logic
    if (!WorkingHooks::IsShuttingDown() && HitchDetector::GetInstance())
        HitchDetector::GetInstance()->CheckApiFrequency();

    LARGE_INTEGER currentTime;
    QueryPerformanceCounter(&currentTime);

    if (g_lastPresentTime.QuadPart > 0) {
        LONGLONG elapsed    = currentTime.QuadPart - g_lastPresentTime.QuadPart;
        DWORD    frameTimeMs = (DWORD)((elapsed * 1000) / g_qpcFrequency.QuadPart);

        if (frameTimeMs > HITCH_THRESHOLD_MS) {
            DWORD n = g_hitchCount.fetch_add(1) + 1;
            if (hitchLogEvery > 0 && (n % hitchLogEvery) == 0) {
                bool captured = false;
                if (captureStacks && StackWalker::GetInstance())
                    captured = StackWalker::GetInstance()->CaptureAndLogStackAsync("LongFrame");
                if (captureStacks && !captured) g_stackCaptureFailures.fetch_add(1);
                if (Logger::GetInstance())
                    Logger::GetInstance()->Warn(
                        "[D3D9_HITCH] %lu ms (threshold %d ms) hitch #%lu%s",
                        frameTimeMs, HITCH_THRESHOLD_MS, n,
                        captureStacks ? (captured ? " [trace captured]" : " [trace failed]")
                                      : " [trace disabled]");
            }
        }
    }

    // Device-lost probe: TestCooperativeLevel is the canonical recovery-loop query
    // and is safe to call on a lost device.  Drives the SetRenderTarget shield and
    // lets us skip the FPS busy-spin so we don't pin a core during a freeze.
    bool deviceLost = false;
    if (g_deviceGuard.load(std::memory_order_relaxed) && pDevice) {
        const HRESULT coop = pDevice->TestCooperativeLevel();
        NoteCoopLevel(coop);
        deviceLost = (coop != D3D_OK);
    }

    // Optional FPS cap (default 60). Set TS3VAS_FPS_CAP=0 to disable. Skipped while
    // the device is lost — pacing during a freeze is pointless. The wait is a
    // blocking high-res timer (FrameCapWait), not a busy-spin, so it never pins a core.
    if (!deviceLost && targetFps > 0 && g_qpcFrequency.QuadPart > 0 && g_lastPresentTime.QuadPart > 0) {
        const LONGLONG targetTicks = (LONGLONG)(g_qpcFrequency.QuadPart / (LONGLONG)targetFps);
        const LONGLONG elapsedTicks = currentTime.QuadPart - g_lastPresentTime.QuadPart;
        if (elapsedTicks < targetTicks) {
            FrameCapWait(targetTicks - elapsedTicks);
            QueryPerformanceCounter(&currentTime);  // re-read post-wait for accurate pacing baseline
        }
    }

    g_lastPresentTime = currentTime;
    g_presentCallCount.fetch_add(1);
    return Real_Present(pDevice, pSourceRect, pDestRect,
                        hDestWindowOverride, pDirtyRegion);
}

// Approximate the system-memory footprint of a texture surface chain.  Telemetry
// only, so a close estimate (block-compressed formats included) is sufficient.
static double D3DFmtBytesPerPixel(D3DFORMAT fmt) {
    switch (fmt) {
        case D3DFMT_DXT1:                                          return 0.5; // 4 bits/texel
        case D3DFMT_DXT2: case D3DFMT_DXT3:
        case D3DFMT_DXT4: case D3DFMT_DXT5:                        return 1.0; // 8 bits/texel
        case D3DFMT_A8: case D3DFMT_L8: case D3DFMT_P8:           return 1.0;
        case D3DFMT_R5G6B5: case D3DFMT_X1R5G5B5:
        case D3DFMT_A1R5G5B5: case D3DFMT_A4R4G4B4: case D3DFMT_A8L8: return 2.0;
        case D3DFMT_A8R8G8B8: case D3DFMT_X8R8G8B8:
        case D3DFMT_A8B8G8R8: case D3DFMT_X8B8G8R8:
        case D3DFMT_A2R10G10B10:                                  return 4.0;
        default:                                                  return 4.0; // assume 32-bit
    }
}

static SIZE_T ApproxTextureBytes(UINT w, UINT h, UINT levels, D3DFORMAT fmt) {
    if (w == 0) w = 1;
    if (h == 0) h = 1;
    const double bpp = D3DFmtBytesPerPixel(fmt);
    SIZE_T total = 0;
    UINT lw = w, lh = h, count = 0;
    const UINT maxLevels = (levels == 0) ? 32u : levels;  // 0 = full mip chain
    while (count < maxLevels) {
        total += (SIZE_T)((double)lw * (double)lh * bpp);
        ++count;
        if (lw == 1 && lh == 1) break;
        if (lw > 1) lw >>= 1;
        if (lh > 1) lh >>= 1;
    }
    return total;
}

static const char* PoolTag(D3DPOOL pool) {
    switch (pool) {
        case D3DPOOL_DEFAULT:   return "Default";
        case D3DPOOL_MANAGED:   return "Managed";
        case D3DPOOL_SYSTEMMEM: return "SystemMem";
        case D3DPOOL_SCRATCH:   return "Scratch";
        default:                return "Other";
    }
}

// MANAGED/SYSTEMMEM keep a reclaimable system-memory copy → CONTAINED lane.
// DEFAULT lives in VRAM with no system copy → EXCLUDED lane.
static bool PoolIsContained(D3DPOOL pool) {
    return pool == D3DPOOL_MANAGED || pool == D3DPOOL_SYSTEMMEM;
}

static void TallyResource(const char* kind, D3DPOOL pool, SIZE_T bytes, bool dynamic) {
    Analytics* a = Analytics::GetInstance();
    if (!a) return;
    char ctr[96];
    sprintf_s(ctr, "D3D9_%s_%s_Count", kind, PoolTag(pool)); a->IncrementCounter(ctr);
    sprintf_s(ctr, "D3D9_%s_%s_Bytes", kind, PoolTag(pool)); a->IncrementCounter(ctr, (uint64_t)bytes);
    // Roll up the two containment lanes so the report shows the split directly.
    if (PoolIsContained(pool) && !dynamic) {
        a->IncrementCounter("D3D9_Contained_Count");
        a->IncrementCounter("D3D9_Contained_Bytes", (uint64_t)bytes);
    } else {
        a->IncrementCounter("D3D9_Excluded_Count");
        a->IncrementCounter("D3D9_Excluded_Bytes", (uint64_t)bytes);
    }
}

HRESULT WINAPI Hooked_CreateTexture(IDirect3DDevice9* dev, UINT W, UINT H, UINT L,
        DWORD Usage, D3DFORMAT Fmt, D3DPOOL Pool, IDirect3DTexture9** ppTex, HANDLE* pH) {
    if (!Real_CreateTexture) return D3DERR_INVALIDCALL;
    HRESULT hr = Real_CreateTexture(dev, W, H, L, Usage, Fmt, Pool, ppTex, pH);
    if (SUCCEEDED(hr) && !WorkingHooks::IsShuttingDown())
        TallyResource("Texture", Pool, ApproxTextureBytes(W, H, L, Fmt),
                      (Usage & D3DUSAGE_DYNAMIC) != 0);
    return hr;
}

HRESULT WINAPI Hooked_CreateCubeTexture(IDirect3DDevice9* dev, UINT Edge, UINT L,
        DWORD Usage, D3DFORMAT Fmt, D3DPOOL Pool, IDirect3DCubeTexture9** ppTex, HANDLE* pH) {
    if (!Real_CreateCubeTexture) return D3DERR_INVALIDCALL;
    HRESULT hr = Real_CreateCubeTexture(dev, Edge, L, Usage, Fmt, Pool, ppTex, pH);
    if (SUCCEEDED(hr) && !WorkingHooks::IsShuttingDown())
        TallyResource("CubeTex", Pool, ApproxTextureBytes(Edge, Edge, L, Fmt) * 6,
                      (Usage & D3DUSAGE_DYNAMIC) != 0);
    return hr;
}

HRESULT WINAPI Hooked_CreateVolumeTexture(IDirect3DDevice9* dev, UINT W, UINT H, UINT D,
        UINT L, DWORD Usage, D3DFORMAT Fmt, D3DPOOL Pool, IDirect3DVolumeTexture9** ppTex, HANDLE* pH) {
    if (!Real_CreateVolumeTexture) return D3DERR_INVALIDCALL;
    HRESULT hr = Real_CreateVolumeTexture(dev, W, H, D, L, Usage, Fmt, Pool, ppTex, pH);
    if (SUCCEEDED(hr) && !WorkingHooks::IsShuttingDown())
        TallyResource("VolumeTex", Pool, ApproxTextureBytes(W, H, L, Fmt) * (D ? D : 1),
                      (Usage & D3DUSAGE_DYNAMIC) != 0);
    return hr;
}

HRESULT WINAPI Hooked_CreateVertexBuffer(IDirect3DDevice9* dev, UINT Len, DWORD Usage,
        DWORD FVF, D3DPOOL Pool, IDirect3DVertexBuffer9** ppVB, HANDLE* pH) {
    if (!Real_CreateVertexBuffer) return D3DERR_INVALIDCALL;
    HRESULT hr = Real_CreateVertexBuffer(dev, Len, Usage, FVF, Pool, ppVB, pH);
    if (SUCCEEDED(hr) && !WorkingHooks::IsShuttingDown())
        TallyResource("VertexBuf", Pool, Len, (Usage & D3DUSAGE_DYNAMIC) != 0);
    return hr;
}

HRESULT WINAPI Hooked_CreateIndexBuffer(IDirect3DDevice9* dev, UINT Len, DWORD Usage,
        D3DFORMAT Fmt, D3DPOOL Pool, IDirect3DIndexBuffer9** ppIB, HANDLE* pH) {
    if (!Real_CreateIndexBuffer) return D3DERR_INVALIDCALL;
    HRESULT hr = Real_CreateIndexBuffer(dev, Len, Usage, Fmt, Pool, ppIB, pH);
    if (SUCCEEDED(hr) && !WorkingHooks::IsShuttingDown())
        TallyResource("IndexBuf", Pool, Len, (Usage & D3DUSAGE_DYNAMIC) != 0);
    return hr;
}

// Vtable slot 37 — the recurring crash site.  When the device is lost, d3d9's real
// SetRenderTarget dispatches through a null driver thunk and the process dies at
// eip=0.  Probe cooperative level first (fresh, so a mid-frame loss is caught even
// if Present hasn't run since) and short-circuit before the null dispatch.
HRESULT WINAPI Hooked_SetRenderTarget(IDirect3DDevice9* dev, DWORD index,
                                      IDirect3DSurface9* pRenderTarget) {
    if (!Real_SetRenderTarget) return D3DERR_INVALIDCALL;
    if (g_deviceGuard.load(std::memory_order_relaxed) && dev) {
        const HRESULT coop = dev->TestCooperativeLevel();
        if (coop != D3D_OK) {
            NoteCoopLevel(coop);            // keep the cached flag fresh mid-frame
            g_guardedCallCount.fetch_add(1);
            return coop;                    // skip the null driver dispatch — survive the frame
        }
    }
    return Real_SetRenderTarget(dev, index, pRenderTarget);
}

// ════════════════════════════════════════════════════════════════════════════
//  Observe-only ReadFile hook
//  Reports .package/.world/.sims3 read activity and runs a one-shot S3SA
//  script-assembly side-scan per distinct package (SCRIPT_HIGHWAY channel).
//  Pure passthrough — never alters the game's read.  This is the old FileReadHook
//  minus the retired cache path; the S3SA detection moved back here off the
//  NtMapViewOfSection map-view path so there is a single detection site.
// ════════════════════════════════════════════════════════════════════════════
static BOOL (WINAPI *Real_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = nullptr;
static volatile LONG s_readFileHooked = 0;

// DBPF resource type IDs that mark a script assembly / tuning.
static const uint32_t kDbpfTypeScript    = 0x0175e5cdu;   // compiled .NET script
static const uint32_t kDbpfTypeScriptSym = 0x0175e5d9u;   // script debug symbols
static const uint32_t kDbpfTypeS3SAMod   = 0x073faa07u;   // modder script archive (NRaas)
static const uint32_t kDbpfTypeXml       = 0x0333406cu;   // XML tuning

#pragma pack(push, 1)
struct S3DbpfHeader {            // DBPF v2.0 header (first 96 bytes)
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
struct S3DbpfEntry {             // fixed-stride index entry
    uint32_t typeId, groupId, instanceHigh, instanceLow;
    uint32_t chunkOffset, diskSize, memSize;
    uint16_t compressionType, committed;
};
#pragma pack(pop)

// Repeat-read state, guarded by one CS.
// Script-scan dedup is shared with the map-view path via ScriptScanDedup.
static CRITICAL_SECTION s_rfCS;
static bool             s_rfCSInit = false;
struct RepeatSlot { uint64_t key; DWORD64 tick; };
// Two tables so we can split the churn into "same chunk re-read" (identical bytes,
// keyed by file^offset) vs "same package, different chunk" (file re-accessed for a
// different resource, keyed by file only).  Chunk table larger because a .package
// holds many distinct offsets.
static const size_t kChunkSlots = 16384;
static const size_t kFileSlots  = 4096;
static RepeatSlot       s_chunkSeen[kChunkSlots] = {};
static RepeatSlot       s_fileSeen [kFileSlots]  = {};

// O(1) "this package was already reported" set for the PACKAGE_LOAD report, so each
// distinct .package is logged once with its size on the hot ReadFile path without a
// linear scan.  Lock-free open addressing (0 = empty slot).
static const size_t      kPkgSlots = 8192;
static volatile LONG64   s_pkgReported[kPkgSlots] = {};
static bool PackageReportedOnce(uint64_t key) {
    if (key == 0) key = 1;
    for (size_t p = 0; p < 32; ++p) {
        const size_t i = (size_t)((key + p) % kPkgSlots);
        const LONG64 cur = InterlockedCompareExchange64(&s_pkgReported[i], 0, 0);
        if ((uint64_t)cur == key) return true;
        if (cur == 0) {
            const LONG64 prev = InterlockedCompareExchange64(&s_pkgReported[i], (LONG64)key, 0);
            if (prev == 0) return false;
            if ((uint64_t)prev == key) return true;
        }
    }
    return false;
}

// FNV-1a 64-bit path hash (case-insensitive) — stable per-file id.
static uint64_t HashPathW(const wchar_t* s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; s && *s; ++s) { h ^= (unsigned char)towlower(*s); h *= 0x100000001b3ULL; }
    return h;
}

static bool ContainsExtI(const wchar_t* path, const wchar_t* ext) {
    if (!path || !ext || !*ext) return false;
    const size_t extLen = wcslen(ext);
    for (const wchar_t* p = path; *p; ++p)
        if (_wcsnicmp(p, ext, extLen) == 0) return true;
    return false;
}

// One bounded side-scan of a package's DBPF index for script resources.  Opens
// its own handle and reads via the Real_ReadFile trampoline so neither the game's
// file pointer nor this hook are perturbed.
static void ScanPackageForScript(const wchar_t* path) {
    if (!path || !Real_ReadFile) return;
    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    S3DbpfHeader hdr = {};
    DWORD got = 0;
    bool ok = Real_ReadFile(h, &hdr, sizeof(hdr), &got, nullptr) && got == sizeof(hdr);
    if (ok) ok = (memcmp(hdr.magic, "DBPF", 4) == 0 && hdr.majorVersion == 2 &&
                  hdr.indexOffset != 0 && hdr.indexEntryCount != 0);
    if (!ok) { CloseHandle(h); return; }

    LARGE_INTEGER pos; pos.QuadPart = hdr.indexOffset;
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN)) { CloseHandle(h); return; }

    const uint32_t kMaxEntries = 16384;
    uint32_t remaining = hdr.indexEntryCount > kMaxEntries ? kMaxEntries : hdr.indexEntryCount;
    static const uint32_t kBatch = 512;
    S3DbpfEntry batch[kBatch];
    uint32_t scriptCount = 0, xmlCount = 0;
    while (remaining > 0) {
        uint32_t take = remaining > kBatch ? kBatch : remaining;
        DWORD rd = 0;
        if (!Real_ReadFile(h, batch, take * sizeof(S3DbpfEntry), &rd, nullptr)) break;
        uint32_t have = rd / sizeof(S3DbpfEntry);
        if (have == 0) break;
        for (uint32_t i = 0; i < have; ++i) {
            const uint32_t t = batch[i].typeId;
            if (t == kDbpfTypeScript || t == kDbpfTypeScriptSym || t == kDbpfTypeS3SAMod) ++scriptCount;
            else if (t == kDbpfTypeXml) ++xmlCount;
        }
        remaining -= have;
        if (have < take) break;
    }
    CloseHandle(h);

    if (scriptCount > 0) {
        const wchar_t* slash = wcsrchr(path, L'\\');
        const wchar_t* base  = slash ? slash + 1 : path;
        if (Logger* log = Logger::GetInstance())
            log->NamedInfo("SCRIPT_HIGHWAY",
                "script in package: %ls  script=%u  xml/tuning=%u", base, scriptCount, xmlCount);
        if (Analytics* a = Analytics::GetInstance()) {
            a->IncrementCounter("Script_Packages");
            a->IncrementCounter("Script_Resources", (uint64_t)scriptCount);
            a->IncrementCounter("Script_Xml_Resources", (uint64_t)xmlCount);
        }
    }
}

static BOOL WINAPI Hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nToRead,
                                   LPDWORD lpRead, LPOVERLAPPED lpOv) {
    if (!Real_ReadFile)
        return ::ReadFile(hFile, lpBuffer, nToRead, lpRead, lpOv);
    if (WorkingHooks::IsShuttingDown())
        return Real_ReadFile(hFile, lpBuffer, nToRead, lpRead, lpOv);

    Analytics* a = Analytics::GetInstance();

    // Only inspect synchronous disk reads.
    if (GetFileType(hFile) != FILE_TYPE_DISK) {
        if (a) a->IncrementCounter("ReadFile_Bypassed_NonDisk");
        return Real_ReadFile(hFile, lpBuffer, nToRead, lpRead, lpOv);
    }

    wchar_t path[MAX_PATH] = {0};
    DWORD plen = GetFinalPathNameByHandleW(hFile, path, MAX_PATH, 0);
    const bool hasPath = (plen > 0 && plen < MAX_PATH);
    const bool isPkg = hasPath && (
        ContainsExtI(path, L".package") || ContainsExtI(path, L".world") ||
        ContainsExtI(path, L".sims3")   || ContainsExtI(path, L".dbc")   ||
        ContainsExtI(path, L".ebc"));
    if (!isPkg) {
        if (a) a->IncrementCounter(hasPath ? "ReadFile_Bypassed_NonPackage"
                                           : "ReadFile_Bypassed_NoPath");
        return Real_ReadFile(hFile, lpBuffer, nToRead, lpRead, lpOv);
    }

    // Read offset (before the real read) for repeat-churn detection.
    LARGE_INTEGER off = {}, zero = {};
    SetFilePointerEx(hFile, zero, &off, FILE_CURRENT);

    BOOL r = Real_ReadFile(hFile, lpBuffer, nToRead, lpRead, lpOv);
    if (!r || !lpRead || *lpRead == 0) return r;

    const uint64_t fileHash = HashPathW(path);
    if (a) {
        a->IncrementCounter("ReadFile_Package_Reads");
        a->IncrementCounter("ReadFile_Package_Bytes", (uint64_t)*lpRead);
    }

    // Repeat-read churn within 60s, split two ways so we know WHICH kind of churn:
    //   SameChunk    = identical bytes re-read (same file AND same offset) -> pure
    //                  waste; a chunk cache would eliminate it.
    //   SamePackage  = same file re-accessed at a DIFFERENT offset -> the game pulling
    //                  another resource from a package it already touched (normal DBPF
    //                  streaming, not waste).
    // The Bytes counters let us weigh how much traffic each kind represents.
    if (s_rfCSInit) {
        const uint64_t chunkKey = fileHash ^ ((uint64_t)off.QuadPart * 0x9E3779B97F4A7C15ULL);
        const DWORD64 now = GetTickCount64();
        const size_t cslot = (size_t)(chunkKey % kChunkSlots);
        const size_t fslot = (size_t)(fileHash % kFileSlots);
        EnterCriticalSection(&s_rfCS);
        const bool sameChunk = (s_chunkSeen[cslot].key == chunkKey && (now - s_chunkSeen[cslot].tick) <= 60000);
        const bool sameFile  = (s_fileSeen[fslot].key  == fileHash && (now - s_fileSeen[fslot].tick)  <= 60000);
        if (a) {
            if (sameChunk) {
                a->IncrementCounter("ReadFile_Repeat_SameChunk_60s");
                a->IncrementCounter("ReadFile_Repeat_SameChunk_Bytes", (uint64_t)*lpRead);
            } else if (sameFile) {
                a->IncrementCounter("ReadFile_Repeat_SamePackage_60s");
                a->IncrementCounter("ReadFile_Repeat_SamePackage_Bytes", (uint64_t)*lpRead);
            }
        }
        s_chunkSeen[cslot].key = chunkKey; s_chunkSeen[cslot].tick = now;
        s_fileSeen[fslot].key  = fileHash; s_fileSeen[fslot].tick  = now;
        LeaveCriticalSection(&s_rfCS);
    }

    // One-shot S3SA script-assembly side-scan per distinct package, deduped on the
    // base filename via the set shared with the map-view path so a package counts
    // exactly once whichever path sees it first.
    const wchar_t* bslash = wcsrchr(path, L'\\');
    const wchar_t* baseName = bslash ? bslash + 1 : path;
    const uint64_t baseKey = ScriptScanDedup::KeyFromBaseNameW(baseName);

    // Package-load report: log each distinct .package once with its on-disk size, so
    // we can see what's loading and how big it is.  PACKAGE_LOAD channel = one line per
    // package in load order; Packages_Loaded/_KB counters give the running totals.
    if (!PackageReportedOnce(baseKey)) {
        LARGE_INTEGER fsz = {};
        GetFileSizeEx(hFile, &fsz);
        if (Logger* lg = Logger::GetInstance())
            lg->NamedInfo("PACKAGE_LOAD", "%-48ls  size=%llu KB",
                          baseName, (unsigned long long)(fsz.QuadPart / 1024));
        if (a) {
            a->IncrementCounter("Packages_Loaded");
            a->IncrementCounter("Packages_Loaded_KB", (uint64_t)(fsz.QuadPart / 1024));
        }
    }

    // One-shot S3SA script-assembly side-scan per distinct package, deduped on the
    // base filename via the set shared with the map-view path so a package counts
    // exactly once whichever path sees it first.
    if (!ScriptScanDedup::MarkOnce(baseKey))
        ScanPackageForScript(path);

    return r;
}

static bool InstallReadFileObserver() {
    using RF = BOOL (WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    auto p = (RF)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
    if (!p) p = (RF)GetProcAddress(GetModuleHandleA("KernelBase.dll"), "ReadFile");
    if (!p) {
        if (Logger::GetInstance()) Logger::GetInstance()->Warn("[OBSERVE] ReadFile not found — read telemetry off.");
        return false;
    }
    Real_ReadFile = p;
    if (!s_rfCSInit) { InitializeCriticalSection(&s_rfCS); s_rfCSInit = true; }
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_ReadFile, Hooked_ReadFile);
    if (DetourTransactionCommit() != NO_ERROR) {
        if (Logger::GetInstance()) Logger::GetInstance()->Warn("[OBSERVE] ReadFile DetourAttach failed — read telemetry off.");
        return false;
    }
    InterlockedExchange(&s_readFileHooked, 1);
    if (Logger::GetInstance())
        Logger::GetInstance()->Info("[OBSERVE] ReadFile hook live — .package read + S3SA script telemetry.");
    return true;
}

static void UninstallReadFileObserver() {
    if (InterlockedCompareExchange(&s_readFileHooked, 0, 0) == 0) return;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_ReadFile, Hooked_ReadFile);
    DetourTransactionCommit();
    InterlockedExchange(&s_readFileHooked, 0);
}

bool ObserverHooks::Install() {
    // ReadFile telemetry installs independently of the D3D9 device dance below,
    // so read/script observation works even on headless/driver-less hosts.
    InstallReadFileObserver();

    if (g_installed.load()) return true;
    if (!Logger::GetInstance()) return false;
    Logger::GetInstance()->Info("[D3D9] Installing Present hook (hitch telemetry + FPS cap)...");
    QueryPerformanceFrequency(&g_qpcFrequency);

    HMODULE hD3D9 = GetModuleHandleA("d3d9.dll");
    if (!hD3D9) hD3D9 = LoadLibraryA("d3d9.dll");
    if (!hD3D9) { Logger::GetInstance()->Warn("[D3D9] d3d9.dll unavailable."); return false; }
    g_hD3D9 = hD3D9;

    IDirect3D9* pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (!pD3D) { Logger::GetInstance()->Error("[D3D9] Direct3DCreate9 failed."); return false; }

    D3DPRESENT_PARAMETERS d3dpp = {};
    d3dpp.Windowed    = TRUE;
    d3dpp.SwapEffect  = D3DSWAPEFFECT_DISCARD;
    d3dpp.hDeviceWindow = GetDesktopWindow(); // safe window handle

    IDirect3DDevice9* pDev = nullptr;
    if (FAILED(pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL,
                                  d3dpp.hDeviceWindow,
                                  D3DCREATE_SOFTWARE_VERTEXPROCESSING,
                                  &d3dpp, &pDev))) {
        pD3D->Release();
        Logger::GetInstance()->Error("[D3D9] Dummy device creation failed.");
        return false;
    }

    // Read every slot we care about while the dummy device is alive.  The vtable
    // functions live in d3d9.dll and are shared across all device instances, so
    // inline-hooking them via Detours catches the game's real device too.
    //   slot 17 = Present, 23 = CreateTexture, 24 = CreateVolumeTexture,
    //   slot 25 = CreateCubeTexture, 26 = CreateVertexBuffer, 27 = CreateIndexBuffer
    void** vtbl       = *reinterpret_cast<void***>(pDev);
    void* presentAddr = vtbl[17];
    void* texAddr     = vtbl[23];
    void* volTexAddr  = vtbl[24];
    void* cubeTexAddr = vtbl[25];
    void* vbAddr      = vtbl[26];
    void* ibAddr      = vtbl[27];
    void* srtAddr     = vtbl[37];  // SetRenderTarget — device-lost crash-site shield
    pD3D->Release();
    pDev->Release();

    // Resource-creation telemetry is on by default when the D3D9 hook is enabled.
    // Set TS3VAS_D3D9_RESOURCE_HOOK=0 to install only the Present hitch hook.
    bool hookResources = true;
    {
        char v[8] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_D3D9_RESOURCE_HOOK", v, (DWORD)sizeof(v));
        if (n > 0 && (v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F'))
            hookResources = false;
    }

    // Device-lost crash shield is on by default. Set TS3VAS_D3D9_DEVICE_GUARD=0 to disable.
    {
        char v[8] = {};
        DWORD n = GetEnvironmentVariableA("TS3VAS_D3D9_DEVICE_GUARD", v, (DWORD)sizeof(v));
        if (n > 0 && (v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F'))
            g_deviceGuard.store(false);
    }

    // Initialise the Real_ pointers then attach via one Detours transaction.
    Real_Present = reinterpret_cast<Present_t>(presentAddr);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_Present, Hooked_Present);
    if (g_deviceGuard.load()) {
        Real_SetRenderTarget = reinterpret_cast<SetRenderTarget_t>(srtAddr);
        DetourAttach(&(PVOID&)Real_SetRenderTarget, Hooked_SetRenderTarget);
    }
    if (hookResources) {
        Real_CreateTexture       = reinterpret_cast<CreateTexture_t>(texAddr);
        Real_CreateVolumeTexture = reinterpret_cast<CreateVolumeTexture_t>(volTexAddr);
        Real_CreateCubeTexture   = reinterpret_cast<CreateCubeTexture_t>(cubeTexAddr);
        Real_CreateVertexBuffer  = reinterpret_cast<CreateVertexBuffer_t>(vbAddr);
        Real_CreateIndexBuffer   = reinterpret_cast<CreateIndexBuffer_t>(ibAddr);
        DetourAttach(&(PVOID&)Real_CreateTexture,       Hooked_CreateTexture);
        DetourAttach(&(PVOID&)Real_CreateVolumeTexture, Hooked_CreateVolumeTexture);
        DetourAttach(&(PVOID&)Real_CreateCubeTexture,   Hooked_CreateCubeTexture);
        DetourAttach(&(PVOID&)Real_CreateVertexBuffer,  Hooked_CreateVertexBuffer);
        DetourAttach(&(PVOID&)Real_CreateIndexBuffer,   Hooked_CreateIndexBuffer);
    }
    if (DetourTransactionCommit() != NO_ERROR) {
        Logger::GetInstance()->Error("[D3D9] Detours attach failed.");
        Real_Present = nullptr;
        Real_SetRenderTarget = nullptr;
        return false;
    }
    if (g_deviceGuard.load() && Real_SetRenderTarget) {
        Logger::GetInstance()->Info(
            "[D3D9] Device-lost guard ON — SetRenderTarget (slot 37) shielded against "
            "null driver dispatch. Set TS3VAS_D3D9_DEVICE_GUARD=0 to disable.");
    }
    if (hookResources) {
        g_resourceHooksInstalled.store(true);
        Logger::GetInstance()->Info(
            "[D3D9] Resource hooks live (Texture/Cube/Volume/VB/IB) — "
            "containment-lane telemetry active. Counters: D3D9_*_Count/_Bytes, "
            "D3D9_Contained_Bytes, D3D9_Excluded_Bytes.");
    }

    g_installed.store(true);
    Logger::GetInstance()->Info("[D3D9] Present hook installed at %p (TS3VAS_FPS_CAP=%lu).",
        presentAddr, ResolveTargetFps());
    return true;
}

void ObserverHooks::Uninstall() {
    UninstallReadFileObserver();   // independent of the D3D9 hooks below
    if (!Real_Present) return;

    if (g_resourceHooksInstalled.load()) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Real_CreateTexture)       DetourDetach(&(PVOID&)Real_CreateTexture,       Hooked_CreateTexture);
        if (Real_CreateVolumeTexture) DetourDetach(&(PVOID&)Real_CreateVolumeTexture, Hooked_CreateVolumeTexture);
        if (Real_CreateCubeTexture)   DetourDetach(&(PVOID&)Real_CreateCubeTexture,   Hooked_CreateCubeTexture);
        if (Real_CreateVertexBuffer)  DetourDetach(&(PVOID&)Real_CreateVertexBuffer,  Hooked_CreateVertexBuffer);
        if (Real_CreateIndexBuffer)   DetourDetach(&(PVOID&)Real_CreateIndexBuffer,   Hooked_CreateIndexBuffer);
        DetourTransactionCommit();
        g_resourceHooksInstalled.store(false);
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_Present, Hooked_Present);
    if (Real_SetRenderTarget) DetourDetach(&(PVOID&)Real_SetRenderTarget, Hooked_SetRenderTarget);
    DetourTransactionCommit();

    if (Logger::GetInstance()) {
        DWORD p = g_presentCallCount.load(), h = g_hitchCount.load();
        Logger::GetInstance()->Info("[D3D9] Hitch hook removed. Frames=%lu Hitches=%lu (%.2f%%)",
            p, h, p > 0 ? h * 100.0f / p : 0.0f);
        Logger::GetInstance()->Info("[D3D9] Device-lost events=%lu  guarded SetRenderTarget calls=%lu",
            g_deviceLostEvents.load(), g_guardedCallCount.load());
    }
    Real_Present = nullptr;
    Real_SetRenderTarget = nullptr;
    g_installed.store(false);
    if (g_hD3D9) {
        FreeLibrary(g_hD3D9);
        g_hD3D9 = nullptr;
    }
}

bool ObserverHooks::IsInstalled() {
    return g_installed.load();
}

#else  // !TS3VAS_TELEMETRY — "play" build: observe layer compiled out entirely.

namespace ObserverHooks {
    bool Install()     { return false; }
    void Uninstall()   {}
    bool IsInstalled() { return false; }
}

#endif // TS3VAS_TELEMETRY
