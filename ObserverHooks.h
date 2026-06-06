#pragma once
#include <windows.h>

// ObserverHooks no longer serves as an activation trigger.
// It is kept as an optional frame-hitch detector only.
// Install() is not called from HookManager — call it manually
// only if per-frame hitch logging is desired.
namespace ObserverHooks {
    bool Install();   // optional hitch detector
    void Uninstall();
    bool IsInstalled();
}
