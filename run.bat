@echo off
rem Launcher for the Detection Feasibility Engine (docs/BLUEPRINT.md 8.1).
rem Deliberately thin: everything else lives in engine\web\serve.py, including
rem the port check and opening the browser.

setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo.
  echo   The virtual environment is missing.
  echo   Run this first, from PowerShell:
  echo.
  echo       scripts\setup.ps1
  echo.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" -m engine.web.serve %*
set EXITCODE=%ERRORLEVEL%

if not "%EXITCODE%"=="0" (
  echo.
  echo   The server exited with code %EXITCODE%.
  pause
)

endlocal & exit /b %EXITCODE%
