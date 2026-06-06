#pragma once
#include <cstdint>

// Shared "already reported this package's script" set, consulted by BOTH S3SA
// detection sites so each package's script resources are counted exactly once
// regardless of which load path sees it first:
//   • the map-view path  — ProbeScriptAssembly  (WorkingHooks, primary)
//   • the ReadFile path  — ScanPackageForScript  (ObserverHooks, secondary)
//
// Keyed on the package's BASE FILENAME (case-insensitive): the map-view path only
// has the device path (\Device\HarddiskVolumeN\...) while the ReadFile path has the
// drive path (C:\...), so the full paths differ — only the base name matches.
//
// Always compiled (WorkingHooks links it unconditionally); the ReadFile site that
// also uses it is itself gated by TS3VAS_TELEMETRY.
namespace ScriptScanDedup {
    uint64_t KeyFromBaseNameA(const char* baseName);
    uint64_t KeyFromBaseNameW(const wchar_t* baseName);

    // True if this package was already marked (caller should skip reporting);
    // otherwise records it and returns false.  Lock-free and thread-safe.
    bool MarkOnce(uint64_t key);
}
