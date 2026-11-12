@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
for %%I in ("%SCRIPT_DIR%\..") do set "PROJECT_DIR=%%~fI"

set "AGENT_ID=%~1"
set "HOSTNAME_VAL=%~2"
if "%HOSTNAME_VAL%"=="" set "HOSTNAME_VAL=lab-ubuntu"

if "%AGENT_ID%"=="" (
    set /p "AGENT_ID=Nhap Agent ID (nhan Enter de dung mac dinh 'web-01'): "
)
if "!AGENT_ID!"=="" set "AGENT_ID=web-01"

set "PYTHON_EXE=%PROJECT_DIR%\.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [-] Khong tim thay .venv. Vui long chay setup\server_setup.bat truoc!
    exit /b 1
)

:: Nạp biến từ .env để Python lấy được ASP_DB_URL
for /f "usebackq tokens=1* delims==" %%A in ("%PROJECT_DIR%\.env") do (
    set "line=%%A"
    set "firstchar=!line:~0,1!"
    if not "!firstchar!"=="#" if not "%%A"=="" (
        set "%%A=%%B"
    )
)

"%PYTHON_EXE%" "%PROJECT_DIR%\tools\asp_client_register.py" "!AGENT_ID!" "!HOSTNAME_VAL!"
