// ── TS3VAS Mono GC companion ────────────────────────────────────────────────────
// A tiny in-process script mod whose only job is to run the managed garbage
// collector when our NATIVE DLL (TS3VASManager.dll) asks it to.
//
// WHY THIS EXISTS
//   Sims 3's embedded Mono GC triggers on growth of its OWN managed heap and is
//   blind to native VAS pressure (the game never calls GC.AddMemoryPressure on the
//   native-backed wrappers).  So in a 32-bit process the native address space can
//   exhaust while collectable managed garbage sits uncollected.  Our native side IS
//   able to measure that pressure — it watches largest-free VAS every heartbeat —
//   so it signals us here, and we run the collect that Mono wouldn't have run on
//   its own.  Calling System.GC.Collect() from a managed thread is safe; calling
//   Mono's collector from the native heartbeat thread is NOT (no safe point / not
//   runtime-attached), which is exactly why this split exists.
//
//   The collect's real payoff is GC.WaitForPendingFinalizers(): finalizers on
//   collected wrappers dispose their native backing, and those native frees flow
//   back through TS3VASManager.dll's free hook to return proxy VAS.
//
// SIGNAL CONTRACT (must match ProxyGc.cpp)
//   Named auto-reset event: "Local\\TS3VAS_MonoGcRequest"
//   Native SetEvent()s it on VAS pressure (rate-limited) or a 30-min floor.
//   We wait on it and, when signaled, collect once.
//
// BUILD / PACKAGE (uses the same toolchain as the NRaas mods at K:\Relevant NRaas)
//   - Target the Sims 3 managed framework (.NET 2.0/3.5-era Mono) the way the NRaas
//     projects do; reference at minimum Sims3GameplaySystems / Sims3.SimIFace.
//   - Load via the NRaas BootStrap pattern (see BootStrapCreator / NRaasBootStrap)
//     OR any ScriptCore entry: the [Tunable] static field below makes ScriptCore run
//     the static constructor at script-load, which starts the waiter thread.
//   - Package the compiled assembly into a .package and drop it in Mods/Packages
//     alongside your NRaas set.

using System;
using System.IO;
using System.Threading;
using System.Globalization;
using System.Runtime.InteropServices;

namespace TS3VAS
{
    public static class MonoGcCompanion
    {
        // ScriptCore instantiates tunables at load, which runs our static ctor.
        // (Same "static cctor as entry point" trick the framework mods rely on.)
        public static bool kInstantiator = Init();

        const string kEventName = "Local\\TS3VAS_MonoGcRequest";
        const string kLogDir    = "C:\\ts3_tool";
        const string kLogPath   = kLogDir + "\\SCRIPT_HEAP.log";

        static Thread sWaiter;
        static volatile bool sStop;
        static readonly object sLogLock = new object();

        // ── Shared-memory bridge to the native DLL ──────────────────────────────
        // The native side (ProxyGc) creates "Local\TS3VAS_ScriptHeap" (16 bytes).
        // We open it and publish [0]=GC.GetTotalMemory bytes, [8]=tick, so the
        // heartbeat can fold the managed-heap size into the VAS_REPORT line.
        const string kShmName = "Local\\TS3VAS_ScriptHeap";
        const uint   FILE_MAP_ALL_ACCESS = 0x000F001F;
        static IntPtr sShView = IntPtr.Zero;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr OpenFileMappingW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess,
                                           uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);

        // Open the native-created section.  Returns true once mapped.  Safe to retry.
        static bool OpenShared()
        {
            if (sShView != IntPtr.Zero) return true;
            try
            {
                IntPtr h = OpenFileMappingW(FILE_MAP_ALL_ACCESS, false, kShmName);
                if (h != IntPtr.Zero)
                    sShView = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, (UIntPtr)16);
            }
            catch { }
            return sShView != IntPtr.Zero;
        }

        // Publish the current managed-heap size for the native heartbeat to read.
        static void PublishHeap(long bytes)
        {
            if (!OpenShared()) return;
            try
            {
                Marshal.WriteInt64(sShView, 0, bytes);
                Marshal.WriteInt64(sShView, 8, (long)Environment.TickCount);
            }
            catch { }
        }

        // Invariant 1-decimal MB so the log parses the same on any locale.
        static string Mb(long bytes)
        {
            return (bytes / (1024.0 * 1024.0)).ToString("0.0", CultureInfo.InvariantCulture);
        }

        // Cumulative gen0/1/2 collection counts.
        static string GenCounts()
        {
            try
            {
                string s = "";
                for (int g = 0; g <= GC.MaxGeneration; g++)
                    s += (g == 0 ? "gc" : " gc") + g + "=" + GC.CollectionCount(g);
                return s;
            }
            catch { return ""; }
        }

        // Append one timestamped line to the script-heap log.  Never throws.
        static void Log(string line)
        {
            try
            {
                lock (sLogLock)
                {
                    if (!Directory.Exists(kLogDir)) Directory.CreateDirectory(kLogDir);
                    File.AppendAllText(kLogPath,
                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture)
                        + "  " + line + "\r\n");
                }
            }
            catch { }
        }

        static bool Init()
        {
            try
            {
                sWaiter = new Thread(WaiterLoop);
                sWaiter.IsBackground = true;   // never block game shutdown
                sWaiter.Name = "TS3VAS-MonoGc";
                sWaiter.Start();
            }
            catch
            {
                // If threading is unavailable this early, fail silent — the native
                // side still functions; it just won't get its assisted collects.
            }
            return true;
        }

        static void WaiterLoop()
        {
            EventWaitHandle ev = null;
            // Open-or-create the SAME named event the native DLL uses.  Either side
            // may win the race to create it; named kernel objects are shared.
            try
            {
                ev = new EventWaitHandle(false, EventResetMode.AutoReset, kEventName);
            }
            catch
            {
                return;
            }

            Log("companion started — logging managed heap (GC.GetTotalMemory) every 30 s "
                + "and before/after each requested collect.  " + GenCounts());

            while (!sStop)
            {
                try
                {
                    // Wake on the native signal; the 30 s timeout doubles as the sample
                    // cadence so we get a continuous heap trajectory even between prods.
                    bool signaled = ev.WaitOne(30000);
                    if (sStop)
                        break;

                    if (!signaled)
                    {
                        // No collect requested — just sample the managed heap (cheap,
                        // does not force a collect) so the trajectory is unbroken.
                        long h = GC.GetTotalMemory(false);
                        PublishHeap(h);
                        Log("heap=" + Mb(h) + " MB  [sample]  " + GenCounts());
                        continue;
                    }

                    // The collect Mono wouldn't have run, plus finalizer drain so the
                    // native-backed wrappers actually release their native memory.
                    // Measure before/after: a big heap that barely shrinks is the
                    // dangling-ref leak signature — i.e. approaching the managed wall.
                    long before = GC.GetTotalMemory(false);
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    GC.Collect();   // second pass reclaims objects freed by finalizers
                    long after = GC.GetTotalMemory(false);
                    PublishHeap(after);
                    Log("heap=" + Mb(after) + " MB  [collect] before=" + Mb(before)
                        + " after=" + Mb(after) + " reclaimed=" + Mb(before - after)
                        + " MB  " + GenCounts());
                }
                catch
                {
                    // Never let a collect hiccup kill the waiter.
                }
            }
        }
    }
}
