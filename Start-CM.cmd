@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "cm_python="
py -3 -c "import sys,tkinter;raise SystemExit(0 if sys.version_info >= (3,9) else 1)" >nul 2>nul
if not errorlevel 1 set "cm_python=py -3"
if not defined cm_python (
  python -c "import sys,tkinter;raise SystemExit(0 if sys.version_info >= (3,9) else 1)" >nul 2>nul
  if not errorlevel 1 set "cm_python=python"
)
if not defined cm_python (
  echo Python 3.9+ with Tcl/Tk is required.
  echo Install Python for Windows from https://www.python.org/downloads/windows/
  echo Enable Tcl/Tk and IDLE, then run Start-CM.cmd again.
  pause
  exit /b 1
)
if not exist ".venv-win\Scripts\python.exe" (
  echo Preparing CM Astra...
  %cm_python% -m venv ".venv-win"
  if errorlevel 1 goto failed
)
".venv-win\Scripts\python.exe" -c "import paramiko;raise SystemExit(0 if paramiko.__version__ == '5.1.0' else 1)" >nul 2>nul
if errorlevel 1 (
  echo Installing SSH dependency. Internet is needed only for this setup.
  ".venv-win\Scripts\python.exe" -m pip install --disable-pip-version-check "paramiko==5.1.0"
  if errorlevel 1 goto failed
)
".venv-win\Scripts\python.exe" class_manager.py
if errorlevel 1 goto failed
exit /b 0
:failed
echo CM Astra could not start. Send the visible error text to your administrator.
pause
exit /b 1
