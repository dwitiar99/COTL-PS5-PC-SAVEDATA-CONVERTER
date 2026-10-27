@echo off
rem Builds a portable single-file CotL-SaveConverter.exe (run this on Windows).
setlocal
cd /d "%~dp0"

py --version >nul 2>nul
if errorlevel 1 (
  echo Python was not found.
  echo Install Python 3.9 or newer from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup.
  pause
  exit /b 1
)

py -m pip install --upgrade pyinstaller
if errorlevel 1 goto :fail

py cotl_converter.py --selftest
if errorlevel 1 goto :fail

py -m PyInstaller --onefile --clean --name CotL-SaveConverter cotl_converter.py
if errorlevel 1 goto :fail

echo.
echo Done:  dist\CotL-SaveConverter.exe
pause
exit /b 0

:fail
echo.
echo Build failed - see the messages above.
pause
exit /b 1
