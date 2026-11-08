import sys
from pathlib import Path

# Purge any prematurely imported mismatched starlette/fastapi modules
for m in list(sys.modules.keys()):
    if "starlette" in m or "fastapi" in m:
        del sys.modules[m]

global_site_packages = "C:\\Python312\\Lib\\site-packages"
if Path(global_site_packages).exists():
    if global_site_packages in sys.path:
        sys.path.remove(global_site_packages)
    sys.path.insert(0, global_site_packages)
