#pragma once
// ContainmentLane.h
//
// Classifies each proxy allocation into one of two containment lanes, sharded
// 4 ways (A–D) to spread contention:
//
//   LANE_CONTAINED_* — allocations the tool pulls into the managed proxy arena.
//     • Caller: game exe, runtime DLLs, mods.
//     • Content: tuning XML, behaviour scripts, catalog metadata, string tables.
//
//   LANE_EXCLUDED_* — allocations classified as graphics-driver owned, which the
//     tool deliberately keeps OUT of the arena/sardine packing (their pointers
//     are handed to the GPU/kernel command path and must not live in our VAS).
//     • Caller: graphics driver modules (d3d9, nvd3dum, atidxx, …).
//
// The lane is telemetry/observability today — it labels per-lane counters and the
// ETW lane field so the contained-vs-excluded split is visible; it does not change
// where an allocation is placed.
//
// Note: the numeric values are stable (emitted in ETW); do not renumber.

#include <windows.h>
#include <cstdint>

// ── Lane type ────────────────────────────────────────────────────────────────
enum class ContainmentLane : uint32_t {
    LANE_CONTAINED_A = 0,
    LANE_EXCLUDED_A  = 1,
    LANE_EXCLUDED_B  = 2,
    LANE_EXCLUDED_C  = 3,
    LANE_CONTAINED_B = 4,
    LANE_CONTAINED_C = 5,
    LANE_EXCLUDED_D  = 6,
    LANE_CONTAINED_D = 7,
};

// ── Caller-module classification (from WorkingHooks AllocCallerKind) ─────────────
// kind values match AllocCallerKind in WorkingHooks.cpp (0=GameExe,1=Graphics,…).
// Graphics-driver allocations go to an EXCLUDED lane; everything else CONTAINED.
// Sharded by thread id (A–D) to spread contention.
ContainmentLane ContainmentLane_FromCallerKind(int callerKind);
