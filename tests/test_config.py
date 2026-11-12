"""
Unit tests for environment-based configuration (os.environ).
"""

from server.src.common.config import ServerConfig


def test_server_config_defaults(monkeypatch):
    for key in (
        "ASP_DB_URL",
        "SOC_SERVER_HOST",
        "SOC_SERVER_PORT",
        "SOC_LOG_LEVEL",
        "ASP_DEFAULT_TIMEZONE",
        "ASP_FUTURE_TS_TOLERANCE",
        "ASP_ALLOWED_LATENESS",
        "ASP_CASE_IDLE_TIMEOUT",
        "ASP_RULES_DIR",
        "ASP_RATE_LIMIT_INGEST",
    ):
        monkeypatch.delenv(key, raising=False)

    cfg = ServerConfig.from_env()
    assert cfg.db_url is None
    assert cfg.server_host == "0.0.0.0"
    assert cfg.server_port == 8000
    assert cfg.log_level == "INFO"
    assert cfg.default_timezone == "Asia/Ho_Chi_Minh"
    assert cfg.future_ts_tolerance == "5m"
    assert cfg.allowed_lateness == "60s"
    assert cfg.case_idle_timeout == "6h"
    assert cfg.rules_dir == "rules/"
    assert cfg.rate_limit_ingest == 120


def test_server_config_from_env_overrides(monkeypatch):
    monkeypatch.setenv("ASP_DB_URL", "postgresql://postgres:placeholder@localhost:5432/asp")
    monkeypatch.setenv("SOC_SERVER_HOST", "127.0.0.1")
    monkeypatch.setenv("SOC_SERVER_PORT", "9000")
    monkeypatch.setenv("ASP_RATE_LIMIT_INGEST", "60")

    cfg = ServerConfig.from_env()
    assert cfg.db_url == "postgresql://postgres:placeholder@localhost:5432/asp"
    assert cfg.server_host == "127.0.0.1"
    assert cfg.server_port == 9000
    assert cfg.rate_limit_ingest == 60

