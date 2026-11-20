@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
for %%I in ("%SCRIPT_DIR%\..") do set "PROJECT_DIR=%%~fI"

cd /d "%PROJECT_DIR%"

echo === ASP SIEM Server Setup (Windows CMD) ===

:: 1. Kiem tra file .env
if not exist "%PROJECT_DIR%\.env" (
    echo [!] Khong tim thay file .env!
    if exist "%PROJECT_DIR%\.env.example" (
        copy "%PROJECT_DIR%\.env.example" "%PROJECT_DIR%\.env" >nul
        echo [+] Da tao file .env tu .env.example. Vui long kiem tra ASP_DB_URL truoc khi tiep tuc.
    ) else (
        echo [-] Thieu ca file .env va .env.example. Dung lai.
        exit /b 1
    )
)

:: 2. Kiem tra hoac tao moi truong ao Python .venv
set "PYTHON_EXE=%PROJECT_DIR%\.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [1/4] Dang tao moi truong ao Python tai .venv...
    python -m venv "%PROJECT_DIR%\.venv"
    if errorlevel 1 (
        echo [-] Khong the tao .venv. Kiem tra lai Python tren may.
        exit /b 1
    )
) else (
    echo [1/4] Da tim thay moi truong ao .venv.
)

:: 3. Cai dat cac goi phu thuoc tu requirements.txt
echo [2/4] Dang kiem tra va cai dat goi tu requirements.txt...
"%PYTHON_EXE%" -m pip install --upgrade pip --quiet
"%PYTHON_EXE%" -m pip install -r "%PROJECT_DIR%\requirements.txt" --quiet

echo [3/4] Dang nap cau hinh tu file .env...

:: 4. Chay migration va khoi dong server qua asp_server_runner.py
"%PYTHON_EXE%" "%PROJECT_DIR%\tools\asp_server_runner.py" %*
