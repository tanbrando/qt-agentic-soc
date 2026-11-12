"""
Pytest configuration and environment initialization.
Ensures project root and server directories are on sys.path.
"""

import sys
from pathlib import Path

# Add project root and server to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

server_dir = project_root / "server"
if str(server_dir) not in sys.path:
    sys.path.insert(0, str(server_dir))
