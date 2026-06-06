@echo off
setlocal

rem ============================================================================
rem  TS3VASManager DLL Build
rem  Run from: K:\TS3VASManager\
rem  Output:   build\bin\Release\TS3VASManager.dll
rem
rem  Builds the 32-bit injected hook DLL.
rem  The 64-bit RAM server is built separately — see TS3VASManagerServer\TS3VASServer_build.bat
rem  The launcher exe is built separately — see exe_build\ (run TS3Launcher_build.bat)
rem
rem  Deploy order:
rem    1. Build + deploy TS3VASServer.exe  → C:\ts3_tool\TS3VASServer.exe
rem    2. Build + deploy TS3VASManager.dll → E:\The Sims 3\Game\Bin\TS3VASManager.dll
rem    3. Build + deploy TS3Launcher.exe   → C:\ts3_tool\TS3Launcher.exe
rem    4. Run TS3Launcher.exe — it starts the server then injects the DLL.
rem ============================================================================

set "BUILD_TIMESTAMP=%DATE% %TIME%"
set "SRC_DIR=%~dp0"
if "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR:~0,-1%"
set "BUILD_DIR=%SRC_DIR%\build"
set "GENERATOR=Visual Studio 17 2022"
set "DLL_PATH=C:\ts3_tool\TS3VASManager.dll"

echo ============================================================================
echo  TS3VASManager DLL Build (32-bit) — %BUILD_TIMESTAMP%
echo  Source : %SRC_DIR%
echo  Output : C:\ts3_tool\
echo ============================================================================

rem ── PHASE 0 : Clean ─────────────────────────────────────────────────────────
echo.
echo [CLEAN] Removing previous DLL build...
if exist "%BUILD_DIR%" (
    rmdir /s /q "%BUILD_DIR%"
    if exist "%BUILD_DIR%" (
        echo [ERROR] Cannot delete build dir. Close Visual Studio or the game first.
        exit /b 1
    )
)
echo [CLEAN] Done.

rem ── PHASE 1 : Configure ─────────────────────────────────────────────────────
echo.
echo [CONFIG] Running CMake (x86)...
cmake -G "%GENERATOR%" -A Win32 -S "%SRC_DIR%" -B "%BUILD_DIR%"
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    exit /b 1
)

rem ── PHASE 2 : Build ──────────────────────────────────────────────────────────
echo.
echo [BUILD] Compiling TS3VASManager.dll...
cmake --build "%BUILD_DIR%" --config Release --clean-first
if %errorlevel% neq 0 (
    echo [ERROR] Build failed. Check errors above.
    exit /b 1
)

rem ── PHASE 3 : Verify ─────────────────────────────────────────────────────────
echo.
echo [VERIFY] Checking output...
if not exist "%DLL_PATH%" (
    echo [FATAL] TS3VASManager.dll not found at expected path:
    echo         %DLL_PATH%
    exit /b 1
)
for %%f in ("%DLL_PATH%") do (
    echo [OK] Built: TS3VASManager.dll  %%~zf bytes  %%~tf
)

echo.
echo ============================================================================
echo  DLL BUILD COMPLETE
echo.
echo  Deploy:
echo    Copy: %DLL_PATH%
echo    To:   E:\The Sims 3\Game\Bin\TS3VASManager.dll
echo.
echo  IMPORTANT — build the 64-bit server before testing:
echo    cd TS3VASManagerServer
echo    TS3VASServer_build.bat
echo.
echo  If TS3VASManager.asi exists in the game Bin folder, DELETE IT.
echo  The ASI Loader (wininet.dll) must not load the DLL a second time.
echo.
echo  Logs: C:\ts3_tool\
echo ============================================================================

endlocal
