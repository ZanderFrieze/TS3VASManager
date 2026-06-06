#pragma once
#include <windows.h>
#include "HitchDetector.h"
#include "WorkingHooks.h"

class MemoryManager;

class HookManager {
public:
    HookManager(MemoryManager* memManager);
    ~HookManager();

    bool InstallAndEnableHooks(); // replaces InstallStagedHooks + EnableCoreHooks
    void Uninstall();

private:
    static MemoryManager* s_memManager;
    static HitchDetector*       s_hitchDetector;
    bool m_hooksInstalled;
};
