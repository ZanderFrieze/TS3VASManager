@echo off
setlocal EnableDelayedExpansion

rem ============================================================================
rem  TS3VASManager — full build (both DLL variants + launcher)
rem  Run from: project root  (K:\TS3VASManager\)
rem
rem  Produces TWO injected-DLL variants from one source via -DTS3VAS_TELEMETRY:
rem    • C:\ts3_tool\TS3VASManager.dll       — DEBUG build  (telemetry ON):
rem        observe-only hooks + console + reporting compiled in.  Hand this to
rem        users who hit crashes so they can send logs.
rem    • C:\ts3_tool\TS3VASManager_play.dll  — PLAY build   (telemetry OFF):
rem        observe-only hooks not installed, reporting compiled out — the lean
rem        "just play" build for a public release.
rem  Plus C:\ts3_tool\TS3Launcher.exe (the injector).
rem
rem  Deploy: copy the variant you want into the game Bin folder AS
rem          TS3VASManager.dll (the launcher injects that exact name).
rem ============================================================================

set "SRC_DIR=%~dp0"
if "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR:~0,-1%"
set "GENERATOR=Visual Studio 17 2022"
set "PLAY_BUILD=%SRC_DIR%\build_play"
set "DLL_BUILD=%SRC_DIR%\build"
set "EXE_BUILD=%SRC_DIR%\exe\build"
set "OUT=C:\ts3_tool"
set "DLL_DEBUG=%OUT%\TS3VASManager.dll"
set "DLL_PLAY=%OUT%\TS3VASManager_play.dll"
set "EXE_PATH=%OUT%\TS3Launcher.exe"

echo ============================================================================
echo  TS3VASManager full build (32-bit)  —  %DATE% %TIME%
echo  Source : %SRC_DIR%
echo  Output : %OUT%\  (debug DLL + play DLL + launcher)
echo ============================================================================

rem ── PHASE 0 : Clean ─────────────────────────────────────────────────────────
echo.
echo [CLEAN] Removing previous build trees...
for %%D in ("%PLAY_BUILD%" "%DLL_BUILD%" "%EXE_BUILD%") do if exist "%%~D" rmdir /s /q "%%~D"
for %%D in ("%PLAY_BUILD%" "%DLL_BUILD%" "%EXE_BUILD%") do if exist "%%~D" ( echo [ERROR] Cannot delete %%~D — close VS or the game first. & exit /b 1 )
echo [CLEAN] Done.

rem ── PHASE 1 : PLAY DLL (telemetry OFF) ──────────────────────────────────────
rem  Built first because CMake writes TS3VASManager.dll; we rename it immediately
rem  so the DEBUG build below can take that canonical name.
echo.
echo [PLAY] Configuring (x86, TS3VAS_TELEMETRY=OFF)...
cmake -G "%GENERATOR%" -A Win32 -DTS3VAS_TELEMETRY=OFF -S "%SRC_DIR%" -B "%PLAY_BUILD%"
if %errorlevel% neq 0 ( echo [ERROR] PLAY CMake configure failed. & exit /b 1 )
echo [PLAY] Building Release...
cmake --build "%PLAY_BUILD%" --config Release --clean-first
if %errorlevel% neq 0 ( echo [ERROR] PLAY build failed. & exit /b 1 )
if not exist "%DLL_DEBUG%" ( echo [FATAL] play DLL not produced at %DLL_DEBUG%. & exit /b 1 )
move /y "%DLL_DEBUG%" "%DLL_PLAY%" >nul
if not exist "%DLL_PLAY%" ( echo [FATAL] could not rename play DLL to %DLL_PLAY%. & exit /b 1 )
for %%f in ("%DLL_PLAY%") do echo [OK] TS3VASManager_play.dll  %%~zf bytes  %%~tf

rem ── PHASE 2 : DEBUG DLL (telemetry ON, the default name) ────────────────────
echo.
echo [DEBUG] Configuring (x86, TS3VAS_TELEMETRY=ON)...
cmake -G "%GENERATOR%" -A Win32 -DTS3VAS_TELEMETRY=ON -S "%SRC_DIR%" -B "%DLL_BUILD%"
if %errorlevel% neq 0 ( echo [ERROR] DEBUG CMake configure failed. & exit /b 1 )
echo [DEBUG] Building Release...
cmake --build "%DLL_BUILD%" --config Release --clean-first
if %errorlevel% neq 0 ( echo [ERROR] DEBUG build failed. & exit /b 1 )
if not exist "%DLL_DEBUG%" ( echo [FATAL] %DLL_DEBUG% not produced. & exit /b 1 )
for %%f in ("%DLL_DEBUG%") do echo [OK] TS3VASManager.dll  %%~zf bytes  %%~tf

rem ── PHASE 3 : Launcher (TS3Launcher.exe) ────────────────────────────────────
echo.
echo [EXE] Configuring (x86)...
cmake -G "%GENERATOR%" -A Win32 -S "%SRC_DIR%\exe" -B "%EXE_BUILD%"
if %errorlevel% neq 0 ( echo [ERROR] Launcher CMake configure failed. & exit /b 1 )
echo [EXE] Building Release...
cmake --build "%EXE_BUILD%" --config Release --clean-first
if %errorlevel% neq 0 ( echo [ERROR] Launcher build failed. & exit /b 1 )
if not exist "%EXE_PATH%" ( echo [FATAL] %EXE_PATH% not produced. & exit /b 1 )
for %%f in ("%EXE_PATH%") do echo [OK] TS3Launcher.exe  %%~zf bytes  %%~tf

echo.
echo ============================================================================
echo  BUILD COMPLETE
echo    %DLL_DEBUG%   (debug: telemetry ON)
echo    %DLL_PLAY%    (play:  telemetry OFF)
echo    %EXE_PATH%
echo.
echo  Deploy: copy the variant you want into the game Bin folder, renamed to
echo          TS3VASManager.dll (the launcher injects that exact name).
echo    debug -> crash testing / log collection
echo    play  -> lean public "just play" build
echo.
echo  If TS3VASManager.asi exists in the game Bin folder, DELETE IT.
echo  Logs: %OUT%\
echo ============================================================================

endlocal
