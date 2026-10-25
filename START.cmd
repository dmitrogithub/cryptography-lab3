@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist "bin\lab3.exe" (
    echo First build the program: powershell -ExecutionPolicy Bypass -File build.ps1
    pause
    exit /b 2
)
"bin\lab3.exe" --help
echo.
echo Current folder: %CD%
echo Enter the commands shown above, or run RUN_DEMO.cmd for a complete example.
cmd /d /k
