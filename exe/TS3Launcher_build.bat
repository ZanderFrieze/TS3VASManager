@echo off
setlocal

rem ============================================================================
rem  TS3Launcher Build
rem  Run from: K:\TS3VASManager\exe\
rem  Output:   build\bin\Release\TS3Launcher.exe
rem
rem  Requires:
rem    ..\extern\detours\src\  — same Detours used by TS3VASManager
rem    Visual Studio 2022 with C++ x86 workload
rem ============================================================================

set "BUILD_TIMESTAMP=%DATE% %TIME%"
set "SRC_DIR=%~dp0"
if "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR:~0,-1%"
set "BUILD_DIR=%SRC_DIR%\build"
set "GENERATOR=Visual Studio 17 2022"
set "EXE_PATH=C:\ts3_tool\TS3Launcher.exe"

echo ============================================================================
echo  TS3Launcher Build — %BUILD_TIMESTAMP%
echo  Source : %SRC_DIR%
echo  Output : C:\ts3_tool\TS3Launcher.exe
echo ============================================================================

rem ── PHASE 0 : Clean ──────────────────────────────────────────────────────────
echo.
echo [CLEAN] Removing previous build...
if exist "%BUILD_DIR%" (
    rmdir /s /q "%BUILD_DIR%"
    if exist "%BUILD_DIR%" (
        echo [ERROR] Cannot delete build dir. Close Visual Studio first.
        exit /b 1
    )
)
echo [CLEAN] Done.

rem ── PHASE 1 : Configure ──────────────────────────────────────────────────────
echo.
echo [CONFIG] Running CMake (x86)...
cmake -G "%GENERATOR%" -A Win32 -S "%SRC_DIR%" -B "%BUILD_DIR%"
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    exit /b 1
)

rem ── PHASE 2 : Build ──────────────────────────────────────────────────────────
echo.
echo [BUILD] Compiling...
cmake --build "%BUILD_DIR%" --config Release --clean-first
if %errorlevel% neq 0 (
    echo [ERROR] Build failed. Check errors above.
    exit /b 1
)

rem ── PHASE 3 : Verify ─────────────────────────────────────────────────────────
echo.
echo [VERIFY] Checking output...
if not exist "%EXE_PATH%" (
    echo [FATAL] TS3Launcher.exe not found at:
    echo         %EXE_PATH%
    exit /b 1
)

for %%f in ("%EXE_PATH%") do (
    echo [OK] Built: TS3Launcher.exe  %%~zf bytes  %%~tf
)

echo.
echo ============================================================================
echo  BUILD COMPLETE
echo.
echo  Deploy:
echo    1. Built directly to:
echo       %EXE_PATH%
echo.
echo    2. Place TS3Launcher.cfg alongside TS3Launcher.exe if you need
echo       to override the default paths (see TS3Launcher.cpp for format).
echo.
echo    3. Deploy TS3VASManager.dll (NOT .asi) to:
echo       E:\The Sims 3\Game\Bin\TS3VASManager.dll
echo.
echo    4. wininet.dll (ASI Loader) stays in the game Bin — S3SS loads normally.
echo       The launcher injects TS3VASManager.dll directly pre-OEP.
echo.
echo    5. If TS3VASManager.asi still exists in the game Bin, DELETE IT.
echo       The ASI loader must not load our DLL a second time.
echo ============================================================================

endlocal
