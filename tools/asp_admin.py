"""
Admin CLI for managing ASP agent API keys and operator tokens (Section 8.6).
Generates cryptographically random tokens, stores SHA-256 hashes in PostgreSQL,
and prints raw credentials exactly once.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

# Ensure repo root is on sys.path when invoked directly as `python tools/asp_admin.py`
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from server.src.common.security import generate_token, hash_secret
from server.src.repositories.base import IAuthRepository
from server.src.repositories.postgres import PostgresAuthRepository
from tools.asp_migrate import get_db_url


def run_admin_command(
    repo: IAuthRepository,
    command: str,
    entity_id: str,
    hostname: Optional[str] = None,
    scopes: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Executes an admin action against IAuthRepository.
    Returns the newly generated plaintext secret when creating/rotating credentials, else None.
    """
    if command == "create-agent":
        raw_key = generate_token()
        repo.create_agent(agent_id=entity_id, api_key_hash=hash_secret(raw_key), hostname=hostname)
        return raw_key

    if command == "revoke-agent":
        if not repo.revoke_agent(entity_id):
            raise LookupError(f"Agent not found: {entity_id}")
        return None

    if command == "rotate-agent-key":
        new_key = generate_token()
        if not repo.rotate_agent_key(agent_id=entity_id, new_api_key_hash=hash_secret(new_key)):
            raise LookupError(f"Agent not found: {entity_id}")
        return new_key

    if command == "create-operator":
        parsed_scopes = [s.strip() for s in (scopes or ["read"]) if s.strip()]
        if not parsed_scopes:
            raise ValueError("At least one scope must be specified")
        raw_token = generate_token()
        repo.create_operator(
            operator_id=entity_id,
            token_hash=hash_secret(raw_token),
            scopes=parsed_scopes,
        )
        return raw_token

    if command == "revoke-operator":
        if not repo.revoke_operator(entity_id):
            raise LookupError(f"Operator not found: {entity_id}")
        return None

    raise ValueError(f"Unknown command: {command}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ASP admin tool for agents and operators.")
    parser.add_argument(
        "--db-url",
        default=None,
        help="PostgreSQL URI (defaults to ASP_DB_URL env var).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ca = sub.add_parser("create-agent", help="Create a new agent and print its API key once.")
    p_ca.add_argument("--id", required=True, dest="entity_id")
    p_ca.add_argument("--hostname", default=None)

    p_ra = sub.add_parser("revoke-agent", help="Revoke an agent API key.")
    p_ra.add_argument("--id", required=True, dest="entity_id")

    p_rk = sub.add_parser("rotate-agent-key", help="Rotate an agent API key and print it once.")
    p_rk.add_argument("--id", required=True, dest="entity_id")

    p_co = sub.add_parser("create-operator", help="Create an operator token and print it once.")
    p_co.add_argument("--id", required=True, dest="entity_id")
    p_co.add_argument("--scopes", default="read", help="Comma-separated scopes (e.g. read,investigate)")

    p_ro = sub.add_parser("revoke-operator", help="Revoke an operator token.")
    p_ro.add_argument("--id", required=True, dest="entity_id")

    args = parser.parse_args(argv)
    repo = PostgresAuthRepository(get_db_url(args.db_url))
    scopes = args.scopes.split(",") if hasattr(args, "scopes") else None

    secret = run_admin_command(
        repo=repo,
        command=args.command,
        entity_id=args.entity_id,
        hostname=getattr(args, "hostname", None),
        scopes=scopes,
    )
    if secret is not None:
        print(f"{args.command} succeeded for '{args.entity_id}'. Save this secret (shown once):")
        print(secret)
    else:
        print(f"{args.command} succeeded for '{args.entity_id}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

