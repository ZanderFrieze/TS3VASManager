#pragma once
#include <windows.h>
#include <atomic>
#include "AnalyticsTimers.h"
#include "AnalyticsCounters.h"

// Headroom for the counter/timing tables.  We were ~230-250 distinct counters before
// the heap-disposition bands (+18) — close enough that the sprintf'd PROXY_Alloc_Fail_*
// failure families could push past 256 mid-session, at which point GetCounterId returns
// -1 and the new counter silently reads 0 (looks like a reporting/"math" bug).  512 keeps
// comfortable slack.  Cost is trivial: ~(64+sizeof(CounterData)+sizeof(TimingData)) per
// slot of static storage.
constexpr int MAX_ANALYTICS_ITEMS = 512;

class Analytics {
public:
    static void Initialize();
    static void Shutdown();
    static Analytics* GetInstance();

    void Report();
    void BeginTiming(const char* name);
    void EndTiming(const char* name);
    void IncrementCounter(const char* name, uint64_t value = 1);
    uint64_t GetCounterValue(const char* name);

private:
    Analytics();
    ~Analytics();
    Analytics(const Analytics&) = delete;
    Analytics& operator=(const Analytics&) = delete;

    CRITICAL_SECTION m_cs;
    TimingData  m_timings[MAX_ANALYTICS_ITEMS];
    CounterData m_counters[MAX_ANALYTICS_ITEMS];
    char m_timingNames[MAX_ANALYTICS_ITEMS][64];
    char m_counterNames[MAX_ANALYTICS_ITEMS][64];
    std::atomic<int> m_timingCount;
    std::atomic<int> m_counterCount;
    
    int GetTimingId(const char* name);
    int GetCounterId(const char* name);
    int FindTimingIdNoLock(const char* name) const;
    int FindCounterIdNoLock(const char* name) const;

    static Analytics* s_instance;
};

class ScopedTimer {
public:
    ScopedTimer(const char* name) : m_name(name) {
        if (Analytics::GetInstance()) {
            Analytics::GetInstance()->BeginTiming(m_name);
        }
    }
    ~ScopedTimer() {
        if (Analytics::GetInstance()) {
            Analytics::GetInstance()->EndTiming(m_name);
        }
    }
private:
    const char* m_name;
};
