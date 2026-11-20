@echo off
setlocal

set "BUILD_DIR=.\build"
set "EXECUTABLE=%BUILD_DIR%\belt_gcm.exe"

if not exist "%BUILD_DIR%\" (
    echo Error: build directory '%BUILD_DIR%' does not exist. 1>&2
    echo Run cmake/make first. 1>&2
    exit /b 1
)

if not exist "%EXECUTABLE%" (
    echo Error: executable '%EXECUTABLE%' not found. 1>&2
    echo Run cmake/make first. 1>&2
    exit /b 1
)

"%EXECUTABLE%"
if errorlevel 1 (
    echo Error: executable returned non-zero exit code. 1>&2
    exit /b 1
)

endlocal