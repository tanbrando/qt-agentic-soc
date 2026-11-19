@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
for %%I in ("%SCRIPT_DIR%\..") do set "ROOT_DIR=%%~fI"

set "PYTHON_EXE="
if exist "%ROOT_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%ROOT_DIR%\.venv\Scripts\python.exe"
) else if exist "%ROOT_DIR%\.venv-client\Scripts\python.exe" (
    set "PYTHON_EXE=%ROOT_DIR%\.venv-client\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

"%PYTHON_EXE%" "%ROOT_DIR%\scripts\test_windows_attacks.py" %*
