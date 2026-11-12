"""
Idempotent PostgreSQL schema migration runner for ASP.
Applies numbered SQL files from migrations/ in order and records applied versions
in `schema_migrations`. Uses ASP_DB_URL from environment.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import psycopg

DEFAULT_MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def get_db_url(explicit_url: Optional[str] = None) -> str:
    """Returns database URL from explicit argument or ASP_DB_URL environment variable."""
    url = explicit_url or os.environ.get("ASP_DB_URL")
    if not url:
        raise ValueError("ASP_DB_URL environment variable is not set")
    return url


def list_migration_files(migrations_dir: Path) -> List[Path]:
    """Lists *.sql migration files sorted deterministically by filename."""
    if not migrations_dir.exists():
        raise FileNotFoundError(f"Migrations directory not found: {migrations_dir}")
    return sorted(p for p in migrations_dir.iterdir() if p.is_file() and p.suffix == ".sql")


def _compute_checksum(sql_text: str) -> str:
    return hashlib.sha256(sql_text.encode("utf-8")).hexdigest()


def run_migrations(
    db_url: Optional[str] = None,
    migrations_dir: Optional[Path] = None,
) -> List[str]:
    """
    Applies pending SQL migrations to PostgreSQL idempotently.
    Returns the list of newly applied migration filenames.
    """
    conn_url = get_db_url(db_url)
    target_dir = migrations_dir or DEFAULT_MIGRATIONS_DIR
    files = list_migration_files(target_dir)
    newly_applied: List[str] = []

    with psycopg.connect(conn_url) as conn:
        with conn.transaction():
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                  version text PRIMARY KEY,
                  checksum text NOT NULL,
                  applied_at timestamptz NOT NULL DEFAULT now()
                );
                """
            )

        rows = conn.execute("SELECT version, checksum FROM schema_migrations").fetchall()
        applied: Dict[str, str] = {row[0]: row[1] for row in rows}

        for sql_file in files:
            sql_text = sql_file.read_text(encoding="utf-8")
            checksum = _compute_checksum(sql_text)
            version = sql_file.name

            if version in applied:
                if applied[version] != checksum:
                    raise RuntimeError(
                        f"Checksum mismatch for already applied migration {version}"
                    )
                continue

            with conn.transaction():
                conn.execute(sql_text)
                conn.execute(
                    "INSERT INTO schema_migrations (version, checksum) VALUES (%s, %s)",
                    (version, checksum),
                )
            newly_applied.append(version)

    return newly_applied


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run ASP PostgreSQL schema migrations.")
    parser.add_argument(
        "--db-url",
        default=None,
        help="PostgreSQL connection URI (defaults to ASP_DB_URL env var).",
    )
    parser.add_argument(
        "--migrations-dir",
        type=Path,
        default=DEFAULT_MIGRATIONS_DIR,
        help="Directory containing numbered .sql migration files.",
    )
    args = parser.parse_args(argv)

    applied = run_migrations(db_url=args.db_url, migrations_dir=args.migrations_dir)
    if applied:
        print(f"Applied migrations: {', '.join(applied)}")
    else:
        print("No pending migrations. Schema is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

