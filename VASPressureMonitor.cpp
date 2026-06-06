#include "VASPressureMonitor.h"
#include "Logger.h"
#include <new>

alignas(VASPressureMonitor) static char s_vasPressureMonitorStorage[sizeof(VASPressureMonitor)];

VASPressureMonitor* VASPressureMonitor::s_instance = nullptr;

void VASPressureMonitor::Initialize() {
    if (s_instance == nullptr) {
        s_instance = new (s_vasPressureMonitorStorage) VASPressureMonitor();
    }
}

void VASPressureMonitor::Shutdown() {
    if (s_instance) {
        s_instance->~VASPressureMonitor();
        s_instance = nullptr;
    }
}

VASPressureMonitor* VASPressureMonitor::GetInstance() {
    return s_instance;
}

VASPressureMonitor::VASPressureMonitor() {
    m_availableVAS.store(2000ULL * 1024 * 1024);
    m_pressureLevel.store(static_cast<int>(VASPressureLevel::Normal));
}

VASPressureMonitor::~VASPressureMonitor() {}

void VASPressureMonitor::Update(SIZE_T availableVAS) {
    m_availableVAS.store(availableVAS);
    
    VASPressureLevel newLevel;
    if (availableVAS < CRITICAL_THRESHOLD) {
        newLevel = VASPressureLevel::Critical;
    } else if (availableVAS < WARNING_THRESHOLD) {
        newLevel = VASPressureLevel::Warning;
    } else {
        newLevel = VASPressureLevel::Normal;
    }
    
    int oldLevel = m_pressureLevel.exchange(static_cast<int>(newLevel));
    
    if (oldLevel != static_cast<int>(newLevel)) {
        Logger* log = Logger::GetInstance();
        if (log) {
            const char* levelName = "UNKNOWN";
            switch (newLevel) {
                case VASPressureLevel::Normal: levelName = "NORMAL"; break;
                case VASPressureLevel::Warning: levelName = "WARNING"; break;
                case VASPressureLevel::Critical: levelName = "CRITICAL"; break;
            }
            log->Warn("[VAS_PRESSURE] State changed to %s (%zu MB available)", 
                     levelName, availableVAS / (1024 * 1024));
        }
    }
}

VASPressureLevel VASPressureMonitor::GetPressureLevel() const {
    return static_cast<VASPressureLevel>(m_pressureLevel.load());
}

SIZE_T VASPressureMonitor::GetAvailableVAS() const {
    return m_availableVAS.load();
}

bool VASPressureMonitor::ShouldThrottle() const {
    return GetPressureLevel() >= VASPressureLevel::Warning;
}

bool VASPressureMonitor::ShouldPause() const {
    return GetPressureLevel() == VASPressureLevel::Critical;
}