import sys
from pathlib import Path

# Đảm bảo root dự án có trong sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from server.src.common.security import generate_token, hash_secret
from server.src.repositories.postgres import PostgresAuthRepository
from tools.asp_migrate import get_db_url

def main():
    agent_id = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].strip() else "web-01"
    hostname = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].strip() else "lab-ubuntu"
    
    db_url = get_db_url()
    repo = PostgresAuthRepository(db_url)
    raw_key = generate_token()
    hashed = hash_secret(raw_key)

    existing = repo.get_agent(agent_id)
    if existing:
        repo.rotate_agent_key(agent_id=agent_id, new_api_key_hash=hashed)
        with repo._connect() as conn:
            with conn.transaction():
                conn.execute("UPDATE agents SET hostname = %s WHERE id = %s", (hostname, agent_id))
        action = "ROTATED"
    else:
        repo.create_agent(agent_id=agent_id, api_key_hash=hashed, hostname=hostname)
        action = "CREATED"

    # Cập nhật trực tiếp vào file .env
    env_path = _ROOT / ".env"
    if env_path.exists():
        import re
        content = env_path.read_text(encoding="utf-8")
        if re.search(r"^ASP_AGENT_ID=.*$", content, flags=re.MULTILINE):
            content = re.sub(r"^ASP_AGENT_ID=.*$", f"ASP_AGENT_ID={agent_id}", content, flags=re.MULTILINE)
        else:
            content += f"\nASP_AGENT_ID={agent_id}\n"

        if re.search(r"^ASP_AGENT_API_KEY=.*$", content, flags=re.MULTILINE):
            content = re.sub(r"^ASP_AGENT_API_KEY=.*$", f"ASP_AGENT_API_KEY={raw_key}", content, flags=re.MULTILINE)
        else:
            content += f"\nASP_AGENT_API_KEY={raw_key}\n"

        lines = [l.rstrip("\r") for l in content.split("\n")]
        content_clean = "\n".join(lines).strip() + "\n"
        with open(env_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content_clean)

    print()
    if action == "ROTATED":
        print(f"[✓] Agent '{agent_id}' da ton tai trong DB -> Da xoay (rotate) API Key moi.")
    else:
        print(f"[✓] Da tao moi Agent '{agent_id}' thanh cong trong database.")
    print(f"  - Agent ID : {agent_id}")
    print(f"  - API Key  : {raw_key}")
    print("  - File .env da duoc tu dong cap nhat ca ID va Key.")
    print("Bay gio ban chi can copy thu muc (hoac file .env) sang may Ubuntu/Client va chay client_setup.sh!\n")

if __name__ == "__main__":
    main()
