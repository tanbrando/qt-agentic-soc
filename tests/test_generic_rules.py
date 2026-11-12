"""
Unit tests for P5.1: YAML loader validation, all selection operators,
ReDoS regex input length cap, and the 4 generic rule classes
(MatchRule, EventCountRule, ValueCountRule, SequenceRule).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from server.src.common.schemas import (
    AlertLevel,
    AspMetaInfo,
    ECSEvent,
    EcsAgentInfo,
    EcsEndpointInfo,
    EcsEventMeta,
    EcsHostInfo,
    EcsHttpInfo,
    EcsHttpRequestInfo,
    EcsHttpResponseInfo,
    EcsProcessInfo,
    EcsUserInfo,
    EventOutcome,
    ParseStatus,
    compute_event_id,
)
from server.src.engine.generic_rules import build_rule_from_spec, compile_selection
from server.src.engine.loader import RuleYamlSpec, load_rule_specs_from_dir
from server.src.engine.state_store import InMemorySlidingWindowStore

_SEQ = 0


def _ecs(
    action: str,
    ts: datetime,
    *,
    src_ip: str | None = None,
    user: str | None = None,
    category: list[str] | None = None,
    args: str | None = None,
    sudo_target: str | None = None,
    status_code: int | None = None,
) -> ECSEvent:
    global _SEQ
    _SEQ += 1
    uid = compute_event_id("ag", 1, 1, "s1", _SEQ)
    return ECSEvent(
        timestamp=ts,
        event=EcsEventMeta(
            id=uid,
            category=category or ["authentication"],
            type=["start"],
            action=action,
            outcome=EventOutcome.FAILURE,
            dataset="linux.auth",
            original=f"{action} {args or ''}",
            created=ts,
            ingested=ts,
        ),
        host=EcsHostInfo(name="web-01"),
        agent=EcsAgentInfo(id="ag", version="0.1.0"),
        source=EcsEndpointInfo(ip=src_ip) if src_ip else None,
        user=EcsUserInfo(name=user) if user else None,
        process=EcsProcessInfo(name="proc", args=args) if args else None,
        http=(
            EcsHttpInfo(
                request=EcsHttpRequestInfo(method="GET"),
                response=EcsHttpResponseInfo(status_code=status_code),
            )
            if status_code is not None
            else None
        ),
        asp=AspMetaInfo(
            parse_status=ParseStatus.OK,
            sudo_target_user=sudo_target,
        ),
    )


def test_loader_skips_invalid_yaml_without_crashing(tmp_path: Path):
    (tmp_path / "valid.yaml").write_text(
        "\n".join(
            [
                "id: test-match",
                "title: Test Match",
                "level: medium",
                "selection:",
                "  event.action: sudo_command",
                "detection:",
                "  type: match",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "broken_missing_timespan.yaml").write_text(
        "\n".join(
            [
                "id: bad-rule",
                "title: Missing Timespan",
                "level: high",
                "selection:",
                "  event.action: ssh_login_failed",
                "detection:",
                "  type: event_count",
                "  group_by: [source.ip]",
                "  condition: {gte: 5}",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "broken_syntax.yaml").write_text("id: [unclosed", encoding="utf-8")

    specs = load_rule_specs_from_dir(tmp_path)
    assert [s.id for s in specs] == ["test-match"]


def test_selection_operators_and_redos_input_cap():
    t0 = datetime(2026, 11, 10, 8, 0, 0, tzinfo=timezone.utc)
    pred = compile_selection(
        {
            "event.category": "web",
            "event.action": ["http_request", "other"],
            "http.response.status_code|gte": 400,
            "http.response.status_code|lt": 500,
            "process.args|startswith": "/usr/",
            "process.args|endswith": "/curl",
            "process.args|contains": "bin",
            "source.ip|exists": True,
            "asp.sudo_target_user|re": r"^root$",
        }
    )
    ok_ev = _ecs(
        "http_request",
        t0,
        src_ip="1.2.3.4",
        category=["web", "network"],
        args="/usr/bin/curl",
        sudo_target="root",
        status_code=404,
    )
    assert pred(ok_ev) is True

    # Missing source.ip fails exists
    assert pred(
        _ecs(
            "http_request",
            t0,
            src_ip=None,
            category=["web"],
            args="/usr/bin/curl",
            sudo_target="root",
            status_code=404,
        )
    ) is False

    # Regex match capped at MAX_RULE_REGEX_INPUT_LEN (4096)
    re_pred = compile_selection({"process.args|re": r"TAIL_MARKER$"})
    long_ev = _ecs("sudo_command", t0, args=("A" * 4500) + "TAIL_MARKER")
    assert re_pred(long_ev) is False


def test_generic_match_rule_positive_and_negative():
    spec = RuleYamlSpec.model_validate(
        {
            "id": "test-sudo-shell",
            "title": "Sudo root shell",
            "level": "medium",
            "selection": {
                "event.action": "sudo_command",
                "asp.sudo_target_user": "root",
                "process.args|re": r"^(/usr)?/bin/((ba|da|z)?sh|su)(\s|$)",
            },
            "detection": {"type": "match"},
        }
    )
    rule = build_rule_from_spec(spec)
    t0 = datetime(2026, 11, 10, 8, 0, 0, tzinfo=timezone.utc)

    assert rule.evaluate(_ecs("sudo_command", t0, user="alice", args="/bin/bash", sudo_target="root")) is not None
    assert rule.evaluate(_ecs("sudo_command", t0, user="alice", args="/bin/shutdown", sudo_target="root")) is None


def test_generic_event_count_rule_and_missing_groupby_ignored():
    spec = RuleYamlSpec.model_validate(
        {
            "id": "test-ec",
            "title": "Test Event Count",
            "level": "high",
            "cooldown": "10m",
            "selection": {"event.action": "ssh_login_failed"},
            "detection": {
                "type": "event_count",
                "group_by": ["source.ip"],
                "timespan": "5m",
                "condition": {"gte": 3},
            },
        }
    )
    store = InMemorySlidingWindowStore()
    rule = build_rule_from_spec(spec, state_store=store)
    t0 = datetime(2026, 11, 10, 8, 0, 0, tzinfo=timezone.utc)

    # Event missing source.ip must be skipped completely
    assert rule.evaluate(_ecs("ssh_login_failed", t0, src_ip=None)) is None

    assert rule.evaluate(_ecs("ssh_login_failed", t0, src_ip="1.2.3.4")) is None
    assert rule.evaluate(_ecs("ssh_login_failed", t0 + timedelta(seconds=10), src_ip="1.2.3.4")) is None
    al = rule.evaluate(_ecs("ssh_login_failed", t0 + timedelta(seconds=20), src_ip="1.2.3.4"))
    assert al is not None
    assert al.level == AlertLevel.HIGH
    assert al.event_count == 3


def test_generic_value_count_rule_distinct_users():
    spec = RuleYamlSpec.model_validate(
        {
            "id": "test-vc",
            "title": "Spraying",
            "level": "high",
            "cooldown": "10m",
            "selection": {"event.action": ["ssh_login_failed", "ssh_invalid_user"]},
            "detection": {
                "type": "value_count",
                "group_by": ["source.ip"],
                "timespan": "5m",
                "condition": {"field": "user.name", "gte": 3},
            },
        }
    )
    rule = build_rule_from_spec(spec, state_store=InMemorySlidingWindowStore())
    t0 = datetime(2026, 11, 10, 8, 0, 0, tzinfo=timezone.utc)

    # 3 failures on the SAME user -> distinct count = 1 (< 3) -> should NOT fire
    for i in range(3):
        assert rule.evaluate(_ecs("ssh_login_failed", t0 + timedelta(seconds=i), src_ip="5.5.5.5", user="root")) is None

    # Now try 2 more distinct users -> distinct count = 3 -> fires
    assert rule.evaluate(_ecs("ssh_invalid_user", t0 + timedelta(seconds=4), src_ip="5.5.5.5", user="admin")) is None
    al = rule.evaluate(_ecs("ssh_login_failed", t0 + timedelta(seconds=5), src_ip="5.5.5.5", user="oracle"))
    assert al is not None
    assert al.group_key["distinct_count"] == 3


def test_generic_sequence_rule_enforces_order_and_total_timespan():
    spec = RuleYamlSpec.model_validate(
        {
            "id": "test-seq",
            "title": "BF then success",
            "level": "critical",
            "cooldown": "30m",
            "detection": {
                "type": "sequence",
                "group_by": ["source.ip"],
                "timespan": "10m",
                "steps": [
                    {"selection": {"event.action": "ssh_login_failed"}, "min_count": 3},
                    {"selection": {"event.action": "ssh_login_success"}, "min_count": 1},
                ],
            },
        }
    )
    t0 = datetime(2026, 11, 10, 8, 0, 0, tzinfo=timezone.utc)

    # Negative 1: success occurs BEFORE the 3 failures -> must NOT fire
    r1 = build_rule_from_spec(spec, state_store=InMemorySlidingWindowStore())
    assert r1.evaluate(_ecs("ssh_login_success", t0, src_ip="9.9.9.9")) is None
    for i in range(1, 4):
        assert r1.evaluate(_ecs("ssh_login_failed", t0 + timedelta(seconds=i), src_ip="9.9.9.9")) is None

    # Negative 2: step1 spans 0..5m, step2 arrives at 11m (> 10m from step1 start) -> must NOT fire
    r2 = build_rule_from_spec(spec, state_store=InMemorySlidingWindowStore())
    assert r2.evaluate(_ecs("ssh_login_failed", t0, src_ip="9.9.9.9")) is None
    assert r2.evaluate(_ecs("ssh_login_failed", t0 + timedelta(minutes=2), src_ip="9.9.9.9")) is None
    assert r2.evaluate(_ecs("ssh_login_failed", t0 + timedelta(minutes=5), src_ip="9.9.9.9")) is None
    assert r2.evaluate(_ecs("ssh_login_success", t0 + timedelta(minutes=11), src_ip="9.9.9.9")) is None

    # Positive: 3 failures at 0, 1m, 2m, then success at 5m (entire chain 5m <= 10m) -> FIRES
    r3 = build_rule_from_spec(spec, state_store=InMemorySlidingWindowStore())
    for m in (0, 1, 2):
        assert r3.evaluate(_ecs("ssh_login_failed", t0 + timedelta(minutes=m), src_ip="9.9.9.9")) is None
    al = r3.evaluate(_ecs("ssh_login_success", t0 + timedelta(minutes=5), src_ip="9.9.9.9"))
    assert al is not None
    assert al.level == AlertLevel.CRITICAL
    assert len(al.event_uids) == 4

