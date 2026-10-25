@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0demo.ps1"
set "demo_result=%errorlevel%"
echo.
pause
exit /b %demo_result%
