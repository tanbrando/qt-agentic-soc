@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
for %%I in ("%SCRIPT_DIR%\..") do set "ROOT_DIR=%%~fI"

set "SETUP_ONLY=0"
set "CONFIG_ARG="

:parse_args
if "%~1"=="" goto done_args
if /i "%~1"=="--setup-only" (
    set "SETUP_ONLY=1"
    shift
    goto parse_args
)
if /i "%~1"=="--config" (
    set "CONFIG_ARG=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="-h" goto show_help
if /i "%~1"=="--help" goto show_help
echo [ERROR] Unknown argument: %~1
exit /b 1

:show_help
echo Usage: setup\client_setup.bat [--setup-only] [--config PATH]
echo   --setup-only    Create venv, verify dependencies, generate config, then exit.
echo   --config PATH   Use custom collector YAML configuration file.
exit /b 0

:done_args
echo ==============================================================================
echo [ASP SIEM] KHOI TAO CLIENT AGENT THU THAP LOG TREN WINDOWS
echo ==============================================================================

:: 1. Kiem tra Python
set "CLIENT_PYTHON="
if exist "%ROOT_DIR%\.venv\Scripts\python.exe" (
    set "CLIENT_PYTHON=%ROOT_DIR%\.venv\Scripts\python.exe"
    echo [1/4] Su dung Python virtualenv hien co tai .venv
) else if exist "%ROOT_DIR%\.venv-client\Scripts\python.exe" (
    set "CLIENT_PYTHON=%ROOT_DIR%\.venv-client\Scripts\python.exe"
    echo [1/4] Su dung Python virtualenv tai .venv-client
) else (
    where python >nul 2>nul
    if %errorlevel% equ 0 (
        echo [1/4] Dang tao virtualenv .venv-client tai %ROOT_DIR%\.venv-client...
        python -m venv "%ROOT_DIR%\.venv-client"
        set "CLIENT_PYTHON=%ROOT_DIR%\.venv-client\Scripts\python.exe"
    ) else (
        echo [-] Khong tim thay Python. Vui long cai dat Python 3.10+ tren Windows!
        exit /b 1
    )
)

:: 2. Kiem tra thu vien client
echo [2/4] Kiem tra thu vien client (requests, pyyaml, pydantic)...
"%CLIENT_PYTHON%" -c "import requests, yaml, pydantic" >nul 2>nul
if %errorlevel% neq 0 (
    echo Dang cai dat thu vien client...
    "%CLIENT_PYTHON%" -m pip install "requests>=2.31.0" "pyyaml>=6.0.1" "pydantic>=2.7.0"
    if %errorlevel% neq 0 (
        echo [-] Cai dat thu vien that bai!
        exit /b 1
    )
)

:: 3. Nap bien moi truong tu .env
set "ENV_FILE=%ROOT_DIR%\.env"
if not exist "%ENV_FILE%" (
    echo [-] Khong tim thay file .env tai %ENV_FILE%!
    echo Vui long chay: setup\create_newClient.bat de tao Agent ID va API Key truoc.
    exit /b 1
)

for /f "usebackq tokens=1* delims==" %%A in ("%ENV_FILE%") do (
    set "line=%%A"
    set "firstchar=!line:~0,1!"
    if not "!firstchar!"=="#" if not "%%A"=="" (
        set "%%A=%%B"
    )
)

if "%ASP_AGENT_API_KEY%"=="" (
    echo [-] ASP_AGENT_API_KEY chua duoc thiet lap trong file .env!
    echo Vui long chay: setup\create_newClient.bat de sinh key moi.
    exit /b 1
)

:: 4. Chuan bi thu muc logs va file log rong tren Windows
set "LOGS_DIR=%ROOT_DIR%\logs"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"
if not exist "%LOGS_DIR%\spool" mkdir "%LOGS_DIR%\spool"
if not exist "%LOGS_DIR%\auth.log" type nul > "%LOGS_DIR%\auth.log"
if not exist "%LOGS_DIR%\syslog.log" type nul > "%LOGS_DIR%\syslog.log"
if not exist "%LOGS_DIR%\audit.log" type nul > "%LOGS_DIR%\audit.log"
if not exist "%LOGS_DIR%\access.log" type nul > "%LOGS_DIR%\access.log"

:: 5. Tao file cau hinh Windows da giai ma duong dan tuyet doi
set "CONFIG_PATH=%CONFIG_ARG%"
if "%CONFIG_PATH%"=="" (
    set "CONFIG_PATH=%LOGS_DIR%\asp-agent-config.windows.yaml"
    "%CLIENT_PYTHON%" -c "import os, sys, yaml; from pathlib import Path; base_cfg, out_cfg, logs_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3]).resolve().as_posix(); cfg = yaml.safe_load(Path(base_cfg).read_text(encoding='utf-8')) or {}; cfg['agent_id'] = os.environ.get('ASP_AGENT_ID') or cfg.get('agent_id', 'win-01'); cfg['server_url'] = os.environ.get('ASP_SERVER_URL', cfg.get('server_url', 'http://127.0.0.1:8000')); cfg['api_key'] = os.environ.get('ASP_AGENT_API_KEY'); v = os.environ.get('ASP_VERIFY_TLS'); cfg['verify_tls'] = (v.lower() in ('1', 'true', 'yes')) if v else False; cfg['state_file'] = f'{logs_dir}/state.json'; cfg['spool_dir'] = f'{logs_dir}/spool'; cfg['sources'] = [{'path': f'{logs_dir}/auth.log', 'log_type': 'auth'}, {'path': f'{logs_dir}/syslog.log', 'log_type': 'syslog'}, {'path': f'{logs_dir}/audit.log', 'log_type': 'audit'}, {'path': f'{logs_dir}/access.log', 'log_type': 'apache'}]; Path(out_cfg).write_text(yaml.safe_dump(cfg, sort_keys=False), encoding='utf-8')" "%ROOT_DIR%\client\config.windows.yaml" "!CONFIG_PATH!" "%LOGS_DIR%"
)

echo [3/4] Khoi tao thanh cong cau hinh Windows Agent:
echo   - Config file : !CONFIG_PATH!
echo   - Log folder  : %LOGS_DIR%
echo   - Agent ID    : %ASP_AGENT_ID%
echo   - Server URL  : %ASP_SERVER_URL%
echo.

if "%SETUP_ONLY%"=="1" (
    echo [4/4] Che do --setup-only hoan tat.
    echo De bat collector bat cu luc nao tren Windows:
    echo   "%CLIENT_PYTHON%" "%ROOT_DIR%\client\collector.py" --config "!CONFIG_PATH!"
    exit /b 0
)

echo [4/4] Bat dau chay ASP Collector tren Windows...
cd /d "%ROOT_DIR%"
"%CLIENT_PYTHON%" "%ROOT_DIR%\client\collector.py" --config "!CONFIG_PATH!"
