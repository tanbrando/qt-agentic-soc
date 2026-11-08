"""
Pytest configuration and environment initialization.
Ensures correct site-packages order and module resolution.
"""

import sys
from pathlib import Path

# Purge any prematurely imported mismatched starlette/fastapi modules
for m in list(sys.modules.keys()):
    if "starlette" in m or "fastapi" in m:
        del sys.modules[m]

# Prioritize global site-packages to ensure FastAPI matches compatible Starlette version
global_site_packages = "C:\\Python312\\Lib\\site-packages"
if global_site_packages in sys.path:
    sys.path.remove(global_site_packages)
sys.path.insert(0, global_site_packages)

# Add project root and server to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

server_dir = project_root / "server"
if str(server_dir) not in sys.path:
    sys.path.insert(0, str(server_dir))
