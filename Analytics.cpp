#include "Analytics.h"
#include "AnalyticsTimers.h"
#include "AnalyticsCounters.h"
#include "Logger.h"

namespace {
constexpr int kNameIdCacheSlots = 64;
constexpr size_t kMaxNameLen = 63;

struct NameIdCacheEntry {
    char name[64];
    uint32_t hash;
    int id;
    bool valid;
};

thread_local NameIdCacheEntry g_counterCache[kNameIdCacheSlots] = {};
thread_local NameIdCacheEntry g_timingCache[kNameIdCacheSlots] = {};
thread_local int g_counterCacheCursor = 0;
thread_local int g_timingCacheCursor = 0;

static uint32_t FastNameHash(const char* s) {
    // FNV-1a 32-bit
    uint32_t h = 2166136261u;
    if (!s) return h;
    for (size_t i = 0; s[i] != '\0' && i < kMaxNameLen; ++i) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

int LookupThreadLocalId(NameIdCacheEntry* cache, const char* name) {
    if (!name || !name[0]) return -1;
    const uint32_t hash = FastNameHash(name);
    for (int i = 0; i < kNameIdCacheSlots; ++i) {
        if (!cache[i].valid) continue;
        if (cache[i].hash == hash && strcmp(cache[i].name, name) == 0) return cache[i].id;
    }
    return -1;
}

void StoreThreadLocalId(NameIdCacheEntry* cache, int& cursor, const char* name, int id) {
    if (!name || !name[0] || id < 0) return;
    strncpy_s(cache[cursor].name, sizeof(cache[cursor].name), name, _TRUNCATE);
    cache[cursor].hash = FastNameHash(cache[cursor].name);
    cache[cursor].id = id;
    cache[cursor].valid = true;
    cursor = (cursor + 1) % kNameIdCacheSlots;
}

// True only when this thread has a TLS array (TEB.ThreadLocalStoragePointer != null).
// Foreign/system threads our injected DLL never set up have it null — touching a C++
// thread_local there faults (the GetCounterId crash), so we must skip the per-thread
// cache and use the lock-free global lookup instead.  Matches WorkingHooks' bootstrap check.
static inline bool ThreadHasTls() {
    return *(LPVOID*)((BYTE*)NtCurrentTeb() + 0x2C) != nullptr;
}
}

Analytics::Analytics() : m_timingCount(0), m_counterCount(0) {
    InitializeCriticalSection(&m_cs);
    memset(m_timingNames, 0, sizeof(m_timingNames));
    memset(m_counterNames, 0, sizeof(m_counterNames));
    for (int i = 0; i < MAX_ANALYTICS_ITEMS; ++i) {
        m_timings[i].start.QuadPart = 0;
        m_timings[i].total_time.store(0, std::memory_order_relaxed);
        m_timings[i].count.store(0, std::memory_order_relaxed);
        m_counters[i].value.store(0, std::memory_order_relaxed);
    }
}

Analytics::~Analytics() {
    DeleteCriticalSection(&m_cs);
}

int Analytics::FindTimingIdNoLock(const char* name) const {
    const int count = m_timingCount.load(std::memory_order_acquire);
    for (int i = 0; i < count; ++i) {
        if (strcmp(m_timingNames[i], name) == 0) {
            return i;
        }
    }
    return -1;
}

int Analytics::FindCounterIdNoLock(const char* name) const {
    const int count = m_counterCount.load(std::memory_order_acquire);
    for (int i = 0; i < count; ++i) {
        if (strcmp(m_counterNames[i], name) == 0) {
            return i;
        }
    }
    return -1;
}

int Analytics::GetTimingId(const char* name) {
    if (!name || !name[0]) return -1;
    const bool tlsOk = ThreadHasTls();   // skip thread_local cache on no-TLS threads
    int id = tlsOk ? LookupThreadLocalId(g_timingCache, name) : -1;
    if (id >= 0) return id;

    id = FindTimingIdNoLock(name);
    if (id >= 0) {
        if (tlsOk) StoreThreadLocalId(g_timingCache, g_timingCacheCursor, name, id);
        return id;
    }

    EnterCriticalSection(&m_cs);
    id = FindTimingIdNoLock(name);
    if (id >= 0) {
        LeaveCriticalSection(&m_cs);
        if (tlsOk) StoreThreadLocalId(g_timingCache, g_timingCacheCursor, name, id);
        return id;
    }
    const int count = m_timingCount.load(std::memory_order_relaxed);
    if (count >= MAX_ANALYTICS_ITEMS) {
        static LONG warned = 0;
        if (InterlockedCompareExchange(&warned, 1, 0) == 0)
            OutputDebugStringA("[TS3VAS][Analytics] TIMING TABLE FULL — new timers read 0; raise MAX_ANALYTICS_ITEMS\n");
        LeaveCriticalSection(&m_cs);
        return -1;
    }
    strcpy_s(m_timingNames[count], name);
    m_timingCount.store(count + 1, std::memory_order_release);
    LeaveCriticalSection(&m_cs);
    if (tlsOk) StoreThreadLocalId(g_timingCache, g_timingCacheCursor, name, count);
    return count;
}

int Analytics::GetCounterId(const char* name) {
    if (!name || !name[0]) return -1;
    const bool tlsOk = ThreadHasTls();   // skip thread_local cache on no-TLS threads
    int id = tlsOk ? LookupThreadLocalId(g_counterCache, name) : -1;
    if (id >= 0) return id;

    id = FindCounterIdNoLock(name);
    if (id >= 0) {
        if (tlsOk) StoreThreadLocalId(g_counterCache, g_counterCacheCursor, name, id);
        return id;
    }

    EnterCriticalSection(&m_cs);
    id = FindCounterIdNoLock(name);
    if (id >= 0) {
        LeaveCriticalSection(&m_cs);
        if (tlsOk) StoreThreadLocalId(g_counterCache, g_counterCacheCursor, name, id);
        return id;
    }
    const int count = m_counterCount.load(std::memory_order_relaxed);
    if (count >= MAX_ANALYTICS_ITEMS) {
        // Table full: this and every later new counter silently reads 0, which masquerades
        // as a reporting/"math" bug.  Warn once (alloc-free, no logger re-entrancy).
        static LONG warned = 0;
        if (InterlockedCompareExchange(&warned, 1, 0) == 0)
            OutputDebugStringA("[TS3VAS][Analytics] COUNTER TABLE FULL — new counters read 0; raise MAX_ANALYTICS_ITEMS\n");
        LeaveCriticalSection(&m_cs);
        return -1;
    }
    strcpy_s(m_counterNames[count], name);
    m_counters[count].value.store(0, std::memory_order_relaxed);
    m_counterCount.store(count + 1, std::memory_order_release);
    LeaveCriticalSection(&m_cs);
    if (tlsOk) StoreThreadLocalId(g_counterCache, g_counterCacheCursor, name, count);
    return count;
}

void Analytics::BeginTiming(const char* name) {
    int id = GetTimingId(name);
    if (id != -1) {
        QueryPerformanceCounter(&m_timings[id].start);
    }
}

void Analytics::EndTiming(const char* name) {
    int id = GetTimingId(name);
    if (id != -1) {
        LARGE_INTEGER end;
        QueryPerformanceCounter(&end);
        m_timings[id].total_time.fetch_add((end.QuadPart - m_timings[id].start.QuadPart),
                                           std::memory_order_relaxed);
        m_timings[id].count.fetch_add(1, std::memory_order_relaxed);
    }
}

void Analytics::IncrementCounter(const char* name, uint64_t value) {
    int id = GetCounterId(name);
    if (id != -1) {
        m_counters[id].value.fetch_add((long long)value, std::memory_order_relaxed);
    }
}

uint64_t Analytics::GetCounterValue(const char* name) {
    const int id = FindCounterIdNoLock(name);
    if (id < 0) return 0;
    return (uint64_t)m_counters[id].value.load(std::memory_order_relaxed);
}

void Analytics::Report() {
    AnalyticsReporter reporter;
    reporter.GenerateTimingReport(m_timings, m_timingNames, m_timingCount.load(std::memory_order_acquire));
    reporter.GenerateCounterReport(m_counters, m_counterNames, m_counterCount.load(std::memory_order_acquire));
}
