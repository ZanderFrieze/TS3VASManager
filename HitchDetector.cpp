#include "HitchDetector.h"
#include "Logger.h"
#include "StackWalker.h"
#include "EmergencyLogger.h"

// Raised defaults to reduce false-positive hitch spam during heavy load/streaming.
// Still overrideable via env vars:
//   TS3VAS_HITCH_INTERVAL_MS
//   TS3VAS_HITCH_READFILE_THRESHOLD
//   TS3VAS_HITCH_ALLOC_THRESHOLD
//   TS3VAS_HITCH_FREE_THRESHOLD
static int GetEnvIntOrDefault(const char* name, int defVal) {
    char buf[32] = {};
    DWORD n = GetEnvironmentVariableA(name, buf, (DWORD)sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return defVal;
    int v = atoi(buf);
    return (v > 0) ? v : defVal;
}

static int FrequencyCheckIntervalMs() {
    static int v = GetEnvIntOrDefault("TS3VAS_HITCH_INTERVAL_MS", 250);
    return v;
}
static int ReadFileFrequencyThreshold() {
    static int v = GetEnvIntOrDefault("TS3VAS_HITCH_READFILE_THRESHOLD", 2000);
    return v;
}
static int AllocFrequencyThreshold() {
    static int v = GetEnvIntOrDefault("TS3VAS_HITCH_ALLOC_THRESHOLD", 20000);
    return v;
}
static int FreeFrequencyThreshold() {
    static int v = GetEnvIntOrDefault("TS3VAS_HITCH_FREE_THRESHOLD", 20000);
    return v;
}
static bool HitchCaptureStacksEnabled() {
    static int v = GetEnvIntOrDefault("TS3VAS_HITCH_CAPTURE_STACKS", 0);
    return v > 0;
}

HitchDetector::HitchDetector() : m_stop(false) {
    m_readFileCount.store(0);
    m_allocCount.store(0);
    m_freeCount.store(0);
}

HitchDetector::~HitchDetector() {
    m_stop.store(true);
}

void HitchDetector::CheckApiFrequency() {
    static DWORD lastCheckTime = 0;
    if (lastCheckTime == 0) {
        lastCheckTime = GetTickCount();
        return;  // Skip first check to establish baseline
    }
    
    static long long lastReadFileCount = 0;
    static long long lastAllocCount = 0;
    static long long lastFreeCount = 0;
    
    DWORD currentTime = GetTickCount();
    DWORD delta_t = currentTime - lastCheckTime;

    // Only check at the specified interval
    if (delta_t < (DWORD)FrequencyCheckIntervalMs()) {
        return;
    }

    // Load current counts
    long long currentReadFileCount = m_readFileCount.load(std::memory_order_relaxed);
    long long currentAllocCount = m_allocCount.load(std::memory_order_relaxed);
    long long currentFreeCount = m_freeCount.load(std::memory_order_relaxed);
    
    // Calculate deltas
    long long deltaReads = currentReadFileCount - lastReadFileCount;
    long long deltaAllocs = currentAllocCount - lastAllocCount;
    long long deltaFrees = currentFreeCount - lastFreeCount;
    
    bool hitchDetected = false;
    Logger* logger = Logger::GetInstance();

    // Check for high ReadFile traffic
    if (deltaReads > ReadFileFrequencyThreshold()) {
        if (logger) {
            logger->Warn("[HITCH] High ReadFile traffic: %lld calls in %lu ms (threshold: %d)", 
                        deltaReads, delta_t, ReadFileFrequencyThreshold());
        }
        hitchDetected = true;
    }
    
    // Check for high VirtualAlloc traffic
    if (deltaAllocs > AllocFrequencyThreshold()) {
        if (logger) {
            logger->Warn("[HITCH] High VirtualAlloc traffic: %lld calls in %lu ms (threshold: %d)", 
                        deltaAllocs, delta_t, AllocFrequencyThreshold());
        }
        hitchDetected = true;
    }
    
    // Check for high VirtualFree traffic
    if (deltaFrees > FreeFrequencyThreshold()) {
        if (logger) {
            logger->Warn("[HITCH] High VirtualFree traffic: %lld calls in %lu ms (threshold: %d)", 
                        deltaFrees, delta_t, FreeFrequencyThreshold());
        }
        hitchDetected = true;
    }

    // If we detected a hitch, try to capture a stack trace
    // But don't let it crash if it fails
    if (hitchDetected && HitchCaptureStacksEnabled()) {
        StackWalker* walker = StackWalker::GetInstance();
        if (walker) {
            bool captured = walker->CaptureAndLogStackAsync("High API Frequency");
            if (!captured && logger) {
                logger->Warn("[HITCH] Stack capture failed or skipped");
            }
        }
    }

    // Update baseline counters
    lastReadFileCount = currentReadFileCount;
    lastAllocCount = currentAllocCount;
    lastFreeCount = currentFreeCount;
    lastCheckTime = currentTime;
}
