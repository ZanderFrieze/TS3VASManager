#pragma once
#include <atomic>
#include <windows.h>

enum class VASPressureLevel {
    Normal,
    Warning,
    Critical
};

class VASPressureMonitor {
public:
    static void Initialize();
    static void Shutdown();
    static VASPressureMonitor* GetInstance();

    void Update(SIZE_T availableVAS);
    VASPressureLevel GetPressureLevel() const;
    SIZE_T GetAvailableVAS() const;
    bool ShouldThrottle() const;
    bool ShouldPause() const;

    // Keyed on largest_free (contiguous span), not total free VAS.
    // Fragmentation makes total free misleading; a 64 MB largest span means
    // no world-load allocation can succeed regardless of total headroom.
    static const SIZE_T WARNING_THRESHOLD  = 128 * 1024 * 1024;  // 128 MB largest_free
    static const SIZE_T CRITICAL_THRESHOLD =  64 * 1024 * 1024;  //  64 MB largest_free

private:
    VASPressureMonitor();
    ~VASPressureMonitor();
    std::atomic<SIZE_T> m_availableVAS;
    std::atomic<int> m_pressureLevel;

    static VASPressureMonitor* s_instance;
};