# ============================================================================
#  CMakeLists.txt — TS3VASManager.dll  (32-bit injected hook DLL)
#
#  Location: <project root>\CMakeLists.txt
#  Build:    run TS3VASManager_build.bat from project root
#  Output:   build\bin\Release\TS3VASManager.dll
#
#  Requires Detours source (9 files) in:
#      <project root>\extern\detours\src\
#  See BEFORE_YOU_BUILD.txt — Step 1.
#
#  Optional auto-deploy to Game\Bin:
#      cmake -DGAME_BIN_DIR="E:\The Sims 3\Game\Bin" ...
# ============================================================================

cmake_minimum_required(VERSION 3.20)
project(TS3VASManager CXX)

# ── Architecture guard (must be x86 — game is 32-bit) ────────────────────────
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR
        "TS3VASManager.dll must be built as x86 (32-bit).\n"
        "Re-run CMake with: cmake -A Win32 ..")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Output directories ────────────────────────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "C:/ts3_tool")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/bin/Debug")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "C:/ts3_tool")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/bin/Debug")

# Keep the linker PDB in the build tree instead of next to the deployed DLL.
# /Zi + /DEBUG below still emit full symbols — they just land here, not in
# C:/ts3_tool. Re-point these to C:/ts3_tool when we need symbols deployed again.
set(CMAKE_PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/pdb")
set(CMAKE_PDB_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/pdb")

# ── Detours — compiled from source ───────────────────────────────────────────
# Copy these 9 files from https://github.com/microsoft/detours into the path below:
#   detours.h  detver.h  detours.cpp  creatwth.cpp  disasm.cpp
#   disolx86.cpp  disolx64.cpp  image.cpp  modules.cpp
set(DETOURS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/extern/detours/src")

if(NOT EXISTS "${DETOURS_SRC}/detours.h")
    message(FATAL_ERROR
        "Detours source not found at: ${DETOURS_SRC}\n"
        "See BEFORE_YOU_BUILD.txt Step 1.")
endif()

# x86 build only needs disolx86.cpp — do NOT include disolx64.cpp here.
set(DETOURS_SOURCES
    "${DETOURS_SRC}/detours.cpp"
    "${DETOURS_SRC}/creatwth.cpp"
    "${DETOURS_SRC}/disasm.cpp"
    "${DETOURS_SRC}/disolx86.cpp"
    "${DETOURS_SRC}/image.cpp"
    "${DETOURS_SRC}/modules.cpp"
)

# ── Manager sources ───────────────────────────────────────────────────────────
set(MANAGER_SOURCES
    # Core DLL entry + hook orchestration
    Main.cpp
    HookManager.cpp
    WorkingHooks.cpp
    ExceptionHandler.cpp

    # Proxy memory management (client-side lightweight agent)
    MemoryManager.cpp
    ProxyGc.cpp
    ProxyAllocator.cpp
    ProxyAllocatorTrace.cpp

    # Allocation classification (containment lanes + map-view inventory)
    ContainmentLane.cpp
    MapViewTypeTracker.cpp

    # Shared single-report set for S3SA detection (both load paths consult it)
    ScriptScanDedup.cpp

    # Monitoring / analytics / diagnostics
    Analytics.cpp
    AnalyticsTimers.cpp
    HeartbeatMonitor.cpp
    HitchDetector.cpp
    VASPressureMonitor.cpp
    StackWalker.cpp

    # Logging
    Logger.cpp
    EmergencyLogger.cpp

    # ETW instrumentation
    ETWProvider.cpp

    # Observe-only hooks (D3D9 resource/Present telemetry; observe-only memory
    # hooks will move here in a later stage).  Toggled via TS3VAS_ENABLE_D3D9_HOOK.
    ObserverHooks.cpp
)

# ── Telemetry / observer build toggle ────────────────────────────────────────
# ON  = "debug build": ObserverHooks + console + reporting compiled in (for users
#        who hit crashes and send logs).
# OFF = "play build":  all observe-only telemetry compiled out; only the working
#        proxy hooks remain.  Configure the play build with -DTS3VAS_TELEMETRY=OFF.
option(TS3VAS_TELEMETRY "Compile in observe-only hooks, console, and reporting" ON)

# ── DLL target ───────────────────────────────────────────────────────────────
add_library(TS3VASManager SHARED ${MANAGER_SOURCES} ${DETOURS_SOURCES})

target_include_directories(TS3VASManager PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"   # project headers
    "${DETOURS_SRC}"                # detours.h / detver.h
)

target_compile_definitions(TS3VASManager PRIVATE
    WIN32
    _WINDOWS
    _USRDLL
    TS3VASMANAGER_EXPORTS
    NOMINMAX                    # suppress min/max macros; use std::min/max
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
    $<$<BOOL:${TS3VAS_TELEMETRY}>:TS3VAS_TELEMETRY>
)

if(MSVC)
    # Suppress Detours' own internal warnings — they are not our code
    foreach(src ${DETOURS_SOURCES})
        set_source_files_properties("${src}" PROPERTIES COMPILE_FLAGS "/W0")
    endforeach()

    target_compile_options(TS3VASManager PRIVATE
        /W3             # warning level 3 for our code
        /WX-            # warnings are not errors (legacy compat)
        /MP             # multi-processor compilation
        /Zi             # full PDB for crash diagnosis
        /GS             # security cookie
        /sdl            # additional security checks
        /EHsc           # C++ exception handling
        "$<$<CONFIG:Debug>:/Od>"
        "$<$<CONFIG:Release>:/O2>"
    )

    target_link_options(TS3VASManager PRIVATE
        /DEBUG
        # /DEBUG defaults the linker to /OPT:NOREF; re-enable /OPT:REF so the play
        # build (TS3VAS_TELEMETRY OFF) actually strips the now-unreferenced observe
        # hooks + their exclusive helpers.  Only removes unreferenced code, so the
        # debug build (where those hooks are attached/referenced) is unaffected.
        # ICF left off so identical functions keep distinct addresses for crash PDBs.
        /OPT:REF
        /OPT:NOICF
    )
endif()

target_link_libraries(TS3VASManager PRIVATE
    dbghelp.lib
    psapi.lib
    d3d9.lib
    shlwapi.lib
    version.lib
    kernel32.lib
    user32.lib
    advapi32.lib
)

# ── Optional: post-build deploy to Game\Bin ───────────────────────────────────
# cmake -DGAME_BIN_DIR="E:\The Sims 3\Game\Bin" ...
if(DEFINED GAME_BIN_DIR)
    add_custom_command(TARGET TS3VASManager POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:TS3VASManager>"
            "${GAME_BIN_DIR}/TS3VASManager.dll"
        COMMENT "Deploying TS3VASManager.dll → ${GAME_BIN_DIR}"
    )
endif()
