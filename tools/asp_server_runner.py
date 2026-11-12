import os
import sys
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

env_path = _ROOT / ".env"
env_vars = os.environ.copy()

if env_path.exists():
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip()

setup_only = "--setup-only" in sys.argv
python_exe = sys.executable

# 1. Chạy database migrations
print("[4/4] Dang kiem tra va chay database migrations...")
mig_script = str(_ROOT / "tools" / "asp_migrate.py")
res = subprocess.run([python_exe, mig_script], env=env_vars)
if res.returncode != 0:
    print("[-] Migration that bai. Kiem tra lai ket noi PostgreSQL trong ASP_DB_URL.")
    sys.exit(1)

if setup_only:
    print("\n[v] Setup hoan tat! (--setup-only duoc kich hoat, khong khoi dong server)")
    sys.exit(0)

# 2. Khởi chạy Uvicorn Server (workers: 1)
host = env_vars.get("SOC_SERVER_HOST", "0.0.0.0")
port = env_vars.get("SOC_SERVER_PORT", "8000")

print(f"\n[v] Dang khoi dong ASP Server tai http://{host}:{port} (workers: 1)...")
print("Nhan Ctrl + C de dung server.\n")

sys.stdout.flush()
env_vars["PYTHONPATH"] = str(_ROOT)
uvicorn_cmd = [python_exe, "-m", "uvicorn", "server.main:app", "--host", host, "--port", str(port), "--workers", "1"]
subprocess.run(uvicorn_cmd, env=env_vars)

