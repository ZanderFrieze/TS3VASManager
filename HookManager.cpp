#include "HookManager.h"
#include "MemoryManager.h"
#include "WorkingHooks.h"
#include "Logger.h"
#include "Analytics.h"
#include "VASPressureMonitor.h"
#include <Psapi.h>
#include <detours.h>
#include "EmergencyLogger.h"

MemoryManager* HookManager::s_memManager = nullptr;
HitchDetector* HookManager::s_hitchDetector = nullptr;

HookManager::HookManager(MemoryManager* memManager)
    : m_hooksInstalled(false) {
    s_memManager = memManager;
    s_hitchDetector = HitchDetector::GetInstance();
}

HookManager::~HookManager() {
    EmergencyLog("HookManager_Dtor", "Enter.");
    Uninstall();
    EmergencyLog("HookManager_Dtor", "Exit.");
}

bool HookManager::InstallAndEnableHooks() {
    if (m_hooksInstalled) return true;

    Logger* log = Logger::GetInstance();

    // ── Rtl heap + NtAllocateVirtualMemory hooks ─────────────────────────────
    if (!WorkingHooks::Install(s_memManager)) {
        if (log) log->Error("[HOOKS] Failed to install Rtl heap hooks.");
        return false;
    }

    // Detours hooks are live immediately on DetourTransactionCommit — no-op here
    WorkingHooks::EnableHooks();

    m_hooksInstalled = true;
    if (log) log->Info("[HOOKS] All hooks installed and live — "
        "RtlAllocateHeap + NtAllocateVirtualMemory active.");
    return true;
}

void HookManager::Uninstall() {
    EmergencyLogF("HookManager_Uninstall", "Enter. installed=%d", m_hooksInstalled ? 1 : 0);
    if (!m_hooksInstalled) {
        EmergencyLog("HookManager_Uninstall", "No hooks installed, exit.");
        return;
    }

    if (Logger::GetInstance())
        Logger::GetInstance()->Info("[HOOKS] Uninstalling API hooks...");

    EmergencyLog("HookManager_Uninstall", "Begin RTL shutdown/pass-through.");
    WorkingHooks::BeginShutdown();

    EmergencyLog("HookManager_Uninstall", "Calling WorkingHooks::Uninstall.");
    WorkingHooks::Uninstall();

    m_hooksInstalled = false;
    EmergencyLog("HookManager_Uninstall", "Exit.");
}
