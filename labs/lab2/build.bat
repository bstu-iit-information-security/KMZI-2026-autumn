@echo off
setlocal

echo Start Configuring...
cmake -S ./src -B ./build -G "MinGW Makefiles"
if errorlevel 1 (
    echo Configuring failed!
    exit /b 1
)
echo Configuring has been ended!

echo Start Building...
cmake --build ./build
if errorlevel 1 (
    echo Building failed!
    exit /b 1
)
echo Building has been ended!

endlocal