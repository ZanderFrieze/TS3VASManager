# ============================================================================
#  CMakeLists.txt — TS3Launcher.exe  (32-bit launcher / injector)
#
#  Location: <project root>\exe\CMakeLists.txt
#  Build:    run TS3Launcher_build.bat from the exe\ folder
#  Output:   build\bin\Release\TS3Launcher.exe
#
#  Deploy:   copy TS3Launcher.exe into Game\Bin alongside
#            TS3VASServer.exe, TS3VASManager.dll, and the game exe.
#
#  Detours source must be present at:
#      <project root>\extern\detours\src\
#  (Same set used by the Manager build — no separate copy needed.)
#
#  Optional auto-deploy to Game\Bin:
#      cmake -DGAME_BIN_DIR="E:\The Sims 3\Game\Bin" ...
# ============================================================================

cmake_minimum_required(VERSION 3.20)
project(TS3Launcher CXX)

# ── Architecture guard (must be x86 — injects into 32-bit game) ──────────────
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR
        "TS3Launcher.exe must be built as x86 (32-bit).\n"
        "Re-run CMake with: cmake -A Win32 ..")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Output directories ────────────────────────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "C:/ts3_tool")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/bin/Debug")

# Keep the linker PDB in the build tree instead of next to the deployed EXE.
# /Zi + /DEBUG below still emit full symbols — they just land here, not in
# C:/ts3_tool. Re-point these to C:/ts3_tool when we need symbols deployed again.
set(CMAKE_PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/pdb")
set(CMAKE_PDB_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/pdb")

# ── Detours — compiled from source ───────────────────────────────────────────
# Relative to exe\ subdir: ../extern/detours/src
# Only creatwth.cpp is strictly required for DetourCreateProcessWithDllExA,
# but the full x86 set is compiled for consistency and future use.
# x86 build: do NOT include disolx64.cpp.
set(DETOURS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../extern/detours/src")

if(NOT EXISTS "${DETOURS_SRC}/detours.h")
    message(FATAL_ERROR
        "Detours source not found at: ${DETOURS_SRC}\n"
        "Copy 9 Detours files into <project root>\\extern\\detours\\src\\")
endif()

set(DETOURS_SOURCES
    "${DETOURS_SRC}/detours.cpp"
    "${DETOURS_SRC}/creatwth.cpp"
    "${DETOURS_SRC}/disasm.cpp"
    "${DETOURS_SRC}/disolx86.cpp"
    "${DETOURS_SRC}/image.cpp"
    "${DETOURS_SRC}/modules.cpp"
)

# ── Launcher source ───────────────────────────────────────────────────────────
set(LAUNCHER_SOURCES
    ../TS3Launcher.cpp
)

# ── Executable target ─────────────────────────────────────────────────────────
# Console subsystem — launcher uses printf for status output
add_executable(TS3Launcher ${LAUNCHER_SOURCES} ${DETOURS_SOURCES})

target_include_directories(TS3Launcher PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/.."    # TS3MemoryProtocol.h (SERVER_READY_EVENT)
    "${DETOURS_SRC}"                    # detours.h / detver.h
)

target_compile_definitions(TS3Launcher PRIVATE
    WIN32
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    foreach(src ${DETOURS_SOURCES})
        set_source_files_properties("${src}" PROPERTIES COMPILE_FLAGS "/W0")
    endforeach()

    target_compile_options(TS3Launcher PRIVATE
        /W3
        /WX-
        /MP
        /Zi
        /GS
        /sdl
        /EHsc
        "$<$<CONFIG:Debug>:/Od>"
        "$<$<CONFIG:Release>:/O2>"
    )

    target_link_options(TS3Launcher PRIVATE
        /SUBSYSTEM:CONSOLE
        /DEBUG
    )
endif()

target_link_libraries(TS3Launcher PRIVATE
    shlwapi.lib
    kernel32.lib
    user32.lib
    advapi32.lib
)

# ── Optional: post-build deploy to Game\Bin ───────────────────────────────────
if(DEFINED GAME_BIN_DIR)
    add_custom_command(TARGET TS3Launcher POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:TS3Launcher>"
            "${GAME_BIN_DIR}/TS3Launcher.exe"
        COMMENT "Deploying TS3Launcher.exe → ${GAME_BIN_DIR}"
    )
endif()
