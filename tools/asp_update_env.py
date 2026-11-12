import sys
import re
from pathlib import Path

env_file = sys.argv[1]
target_id = sys.argv[2]
target_key = sys.argv[3]

env_path = Path(env_file)
content = env_path.read_text(encoding="utf-8")

if re.search(r"^ASP_AGENT_ID=.*$", content, flags=re.MULTILINE):
    content = re.sub(r"^ASP_AGENT_ID=.*$", f"ASP_AGENT_ID={target_id}", content, flags=re.MULTILINE)
else:
    content += f"\nASP_AGENT_ID={target_id}\n"

if re.search(r"^ASP_AGENT_API_KEY=.*$", content, flags=re.MULTILINE):
    content = re.sub(r"^ASP_AGENT_API_KEY=.*$", f"ASP_AGENT_API_KEY={target_key}", content, flags=re.MULTILINE)
else:
    content += f"\nASP_AGENT_API_KEY={target_key}\n"

lines = [l.rstrip("\r") for l in content.split("\n")]
content_clean = "\n".join(lines).strip() + "\n"
with open(env_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(content_clean)

