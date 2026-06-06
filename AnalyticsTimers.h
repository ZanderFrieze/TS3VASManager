#pragma once
#include <windows.h>
#include <atomic>

struct TimingData {
    LARGE_INTEGER start;
    std::atomic<long long> total_time;
    std::atomic<long long> count;
};

class AnalyticsReporter {
public:
    void GenerateTimingReport(const TimingData* timings, 
                             const char timingNames[][64], 
                             int timingCount);
    void GenerateCounterReport(const struct CounterData* counters, 
                              const char counterNames[][64], 
                              int counterCount);
};