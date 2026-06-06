#pragma once
#include <windows.h>
#include <atomic>

#define HITCH_THRESHOLD_MS 50

class HitchDetector {
public:
    static void Initialize();
    static void Shutdown();
    static HitchDetector* GetInstance();

    void CheckApiFrequency();
    
    // Use relaxed memory order for performance counters
    void IncrementReadFile() { 
        m_readFileCount.fetch_add(1, std::memory_order_relaxed); 
    }
    void IncrementAlloc() { 
        m_allocCount.fetch_add(1, std::memory_order_relaxed); 
    }
    void IncrementFree() { 
        m_freeCount.fetch_add(1, std::memory_order_relaxed); 
    }

private:
    HitchDetector();
    ~HitchDetector();
    HitchDetector(const HitchDetector&) = delete;
    HitchDetector& operator=(const HitchDetector&) = delete;

    std::atomic<bool> m_stop;
    std::atomic<long long> m_readFileCount;
    std::atomic<long long> m_allocCount;
    std::atomic<long long> m_freeCount;

    static HitchDetector* s_instance;
};