// ContainmentLane.cpp
// ─────────────────────────────────────────────────────────────────────────────
// Implements ContainmentLane_FromCallerKind.
//
// AllocCallerKind integer mapping (must stay in sync with WorkingHooks.cpp):
//   0 = GameExe
//   1 = Graphics
//   2 = RuntimeDll
//   3 = SystemDll
//   4 = ModDll
//   5 = Unknown
// ─────────────────────────────────────────────────────────────────────────────

#include "ContainmentLane.h"

// Graphics-driver allocations are EXCLUDED from the arena; everything else is
// CONTAINED.  Sharded 4 ways by thread id (A–D) to spread contention.
static inline uint32_t LaneShard4() {
    return (GetCurrentThreadId() & 3u);
}

ContainmentLane ContainmentLane_FromCallerKind(int callerKind) {
    const uint32_t shard = LaneShard4();
    if (callerKind == 1) {   // Graphics
        return (shard == 0u) ? ContainmentLane::LANE_EXCLUDED_A
             : (shard == 1u) ? ContainmentLane::LANE_EXCLUDED_B
             : (shard == 2u) ? ContainmentLane::LANE_EXCLUDED_C
                             : ContainmentLane::LANE_EXCLUDED_D;
    }
    return (shard == 0u) ? ContainmentLane::LANE_CONTAINED_A
         : (shard == 1u) ? ContainmentLane::LANE_CONTAINED_B
         : (shard == 2u) ? ContainmentLane::LANE_CONTAINED_C
                         : ContainmentLane::LANE_CONTAINED_D;
}
