// ScriptScanDedup.cpp — shared, lock-free single-report set for S3SA detection.
// See ScriptScanDedup.h.

#include "ScriptScanDedup.h"
#include <windows.h>
#include <cctype>
#include <cwctype>

namespace {
    // Open-addressing table, zero-initialised (0 == empty slot).  Lock-free via
    // InterlockedCompareExchange64.  16384 slots comfortably exceeds the package
    // count of a fully-modded session; on table pressure we treat a key as new
    // (worst case: a rare double-count, never a crash).
    static const size_t   kSlots = 16384;
    static volatile LONG64 s_slots[kSlots];

    inline uint64_t fnv1a64_byte(uint64_t h, unsigned char c) {
        h ^= c; h *= 0x100000001b3ULL; return h;
    }
}

namespace ScriptScanDedup {

uint64_t KeyFromBaseNameA(const char* b) {
    if (!b || !*b) return 0;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; *b; ++b) h = fnv1a64_byte(h, (unsigned char)std::tolower((unsigned char)*b));
    return h;
}

uint64_t KeyFromBaseNameW(const wchar_t* b) {
    if (!b || !*b) return 0;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; *b; ++b) {
        // Hash the lowercased UTF-16 code unit byte-wise so A/W base names of the
        // same ASCII package filename produce the same key.
        const wchar_t lc = (wchar_t)std::towlower(*b);
        h = fnv1a64_byte(h, (unsigned char)(lc & 0xFF));
    }
    return h;
}

bool MarkOnce(uint64_t key) {
    if (key == 0) key = 0x1ULL;   // 0 is the empty sentinel; remap
    const size_t base = (size_t)(key % kSlots);
    for (size_t probe = 0; probe < 64; ++probe) {
        const size_t idx = (base + probe) % kSlots;
        const LONG64 cur = InterlockedCompareExchange64(&s_slots[idx], 0, 0);
        if ((uint64_t)cur == key) return true;            // already recorded
        if (cur == 0) {
            const LONG64 prev = InterlockedCompareExchange64(&s_slots[idx], (LONG64)key, 0);
            if (prev == 0) return false;                  // we claimed it (newly seen)
            if ((uint64_t)prev == key) return true;       // lost race to same key
            // slot taken by a different key — keep probing
        }
    }
    return false;   // table pressure — treat as new
}

} // namespace ScriptScanDedup
