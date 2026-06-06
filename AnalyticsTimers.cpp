#include "AnalyticsTimers.h"
#include "AnalyticsCounters.h"
#include "Logger.h"

void AnalyticsReporter::GenerateTimingReport(const TimingData* timings, 
                                             const char timingNames[][64], 
                                             int timingCount) {
    Logger* logger = Logger::GetInstance();
    if (!logger) return;

    logger->NamedInfo("ANALYTICS_REPORT", "--- Analytics Report ---");
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);

    for (int i = 0; i < timingCount; ++i) {
        long long count = timings[i].count.load();
        if (count > 0) {
            double total_ms = (double)timings[i].total_time.load() * 1000.0 / frequency.QuadPart;
            logger->NamedInfo("ANALYTICS_REPORT", "[TIMER] %-24s: %.2f ms total, %lld calls, %.4f ms avg", 
                        timingNames[i], total_ms, count, total_ms / count);
        }
    }
}

void AnalyticsReporter::GenerateCounterReport(const CounterData* counters, 
                                              const char counterNames[][64], 
                                              int counterCount) {
    Logger* logger = Logger::GetInstance();
    if (!logger) return;

    for (int i = 0; i < counterCount; ++i) {
        long long value = counters[i].value.load();
        if (value > 0) {
            logger->NamedInfo("ANALYTICS_REPORT", "[COUNTER] %-24s: %lld", counterNames[i], value);
        }
    }
    logger->NamedInfo("ANALYTICS_REPORT", "--- End of Report ---");
}
