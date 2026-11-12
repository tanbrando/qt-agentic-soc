"""
Unit tests for Pydantic v2 Schemas and Data Contracts (ASP v1.1).
"""

import hashlib
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from server.src.common.schemas import (
    AgentMetadata,
    AgentReportUpdate,
    AgentVerdict,
    Alert,
    AlertLevel,
    AlertStatus,
    Artifact,
    ArtifactType,
    AspMetaInfo,
    Case,
    CaseStatus,
    ECSEvent,
    EcsAgentInfo,
    EcsEndpointInfo,
    EcsEventMeta,
    EcsHostInfo,
    EcsHttpInfo,
    EcsHttpRequestInfo,
    EcsHttpResponseInfo,
    EcsLogFileInfo,
    EcsLogInfo,
    EcsProcessInfo,
    EcsRelatedInfo,
    EcsUrlInfo,
    EcsUserAgentInfo,
    EcsUserInfo,
    EventOutcome,
    IngestBatchRequest,
    IngestBatchResponse,
    LogType,
    ParseStatus,
    RawEventFileMeta,
    RawLogEvent,
    compute_event_id,
)


def test_compute_event_id_deterministic():
    uid = compute_event_id("web-01", 2049, 131077, "7c1e9a52", 482113)
    expected = hashlib.sha1(b"web-01|2049|131077|7c1e9a52|482113").hexdigest()
    assert uid == expected
    assert len(uid) == 40

    # Changing stream_id or offset produces a distinct event.id
    assert uid != compute_event_id("web-01", 2049, 131077, "99aa11bb", 482113)
    assert uid != compute_event_id("web-01", 2049, 131077, "7c1e9a52", 482200)


def test_ingest_batch_request_v11_validation():
    payload = {
        "schema_version": "1.1",
        "batch_id": "b6f1c2e0-0000-4000-8000-000000000001",
        "sent_at": "2026-11-10T08:30:02Z",
        "agent": {
            "id": "web-01",
            "hostname": "web-01",
            "version": "0.1.0",
            "ip": ["10.0.0.5"],
            "timezone": "Asia/Ho_Chi_Minh",
        },
        "events": [
            {
                "log_type": "auth",
                "file": {
                    "path": "/var/log/auth.log",
                    "device": 2049,
                    "inode": 131077,
                    "stream_id": "7c1e9a52",
                    "offset": 482113,
                },
                "collected_at": "2026-11-10T08:30:01.250Z",
                "message": "Nov 10 08:30:00 web-01 sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 41001 ssh2",
                "message_truncated": False,
            }
        ],
    }

    batch = IngestBatchRequest.model_validate(payload)
    assert batch.schema_version == "1.1"
    assert batch.agent.id == "web-01"
    assert batch.agent.timezone == "Asia/Ho_Chi_Minh"
    assert batch.sent_at.tzinfo == timezone.utc
    assert batch.events[0].collected_at.tzinfo == timezone.utc
    assert batch.event_id_for(batch.events[0]) == compute_event_id(
        "web-01", 2049, 131077, "7c1e9a52", 482113
    )

    # Empty events list should fail validation
    with pytest.raises(ValidationError):
        IngestBatchRequest(
            batch_id="b-empty",
            sent_at=datetime.now(timezone.utc),
            agent=AgentMetadata(id="web-01", hostname="web-01", version="0.1.0"),
            events=[],
        )


def test_ingest_batch_allows_over_500_events_for_api_413_check():
    events = [
        RawLogEvent(
            log_type=LogType.AUTH,
            file=RawEventFileMeta(
                path="/var/log/auth.log",
                device=2049,
                inode=131077,
                stream_id="7c1e9a52",
                offset=i * 100,
            ),
            collected_at=datetime(2026, 11, 10, 8, 30, 1),  # naive -> UTC
            message=f"line {i}",
        )
        for i in range(501)
    ]
    batch = IngestBatchRequest(
        batch_id="b-large",
        sent_at=datetime(2026, 11, 10, 8, 30, 2),
        agent=AgentMetadata(id="web-01", hostname="web-01", version="0.1.0"),
        events=events,
    )
    assert len(batch.events) == 501
    assert batch.events[0].collected_at.tzinfo == timezone.utc
    assert batch.sent_at.tzinfo == timezone.utc
    assert batch.agent.timezone is None
    assert batch.agent.ip == []


def test_agent_metadata_invalid_timezone_rejected():
    with pytest.raises(ValidationError):
        AgentMetadata(
            id="web-01",
            hostname="web-01",
            version="0.1.0",
            timezone="Mars/Phobos",
        )


def test_ingest_batch_response_v11():
    res = IngestBatchResponse(accepted=98, duplicates=2, unparsed=1, parse_errors=0)
    assert res.accepted == 98
    assert res.duplicates == 2
    assert res.unparsed == 1
    assert res.parse_errors == 0


def test_ecs_event_nested_model_and_serialization():
    event_uid = compute_event_id("web-01", 2049, 131077, "7c1e9a52", 482113)
    ecs_ev = ECSEvent(
        timestamp=datetime(2026, 11, 10, 1, 30, 0),  # naive -> UTC
        event=EcsEventMeta(
            id=event_uid,
            category=["authentication"],
            type=["start"],
            action="ssh_login_failed",
            outcome=EventOutcome.FAILURE,
            dataset="linux.auth",
            original="Nov 10 08:30:00 web-01 sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 41001 ssh2",
            created=datetime(2026, 11, 10, 1, 30, 1, 250000, tzinfo=timezone.utc),
            ingested=datetime(2026, 11, 10, 1, 30, 2, 100000, tzinfo=timezone.utc),
        ),
        host=EcsHostInfo(name="web-01", ip=["10.0.0.5"]),
        agent=EcsAgentInfo(id="web-01", version="0.1.0"),
        log=EcsLogInfo(file=EcsLogFileInfo(path="/var/log/auth.log")),
        source=EcsEndpointInfo(ip="1.2.3.4", port=41001),
        user=EcsUserInfo(name="admin"),
        process=EcsProcessInfo(name="sshd", pid=1234),
        related=EcsRelatedInfo(ip=["1.2.3.4"], user=["admin"]),
        asp=AspMetaInfo(
            parse_status=ParseStatus.OK,
            parser="sshd_failed@1",
            auth_method="password",
        ),
    )

    dumped = ecs_ev.to_ecs_dict()
    assert dumped["@timestamp"].startswith("2026-11-10T01:30:00")
    assert dumped["ecs"] == {"version": "8.11"}
    assert dumped["event"]["id"] == event_uid
    assert dumped["event"]["kind"] == "event"
    assert dumped["event"]["category"] == ["authentication"]
    assert dumped["event"]["outcome"] == "failure"
    assert dumped["agent"]["type"] == "asp-agent"
    assert dumped["log"]["file"]["path"] == "/var/log/auth.log"
    assert dumped["asp"]["parse_status"] == "ok"
    assert "http" not in dumped

    reloaded = ECSEvent.model_validate(dumped)
    assert reloaded.timestamp.tzinfo == timezone.utc
    assert reloaded.source is not None and reloaded.source.ip == "1.2.3.4"


def test_ecs_event_web_and_unparsed_variants():
    web_ev = ECSEvent(
        timestamp=datetime(2026, 11, 10, 2, 0, 0, tzinfo=timezone.utc),
        event=EcsEventMeta(
            id="a" * 40,
            category=["web"],
            type=["access"],
            action="http_request",
            outcome=EventOutcome.FAILURE,
            dataset="apache.access",
            original='1.2.3.4 - - [10/Nov/2026:09:00:00 +0700] "GET /admin HTTP/1.1" 404 123 "-" "curl/8.0"',
            created=datetime(2026, 11, 10, 2, 0, 1, tzinfo=timezone.utc),
            ingested=datetime(2026, 11, 10, 2, 0, 2, tzinfo=timezone.utc),
        ),
        host=EcsHostInfo(name="web-01"),
        agent=EcsAgentInfo(id="web-01", version="0.1.0"),
        source=EcsEndpointInfo(ip="1.2.3.4"),
        http=EcsHttpInfo(
            request=EcsHttpRequestInfo(method="GET"),
            response=EcsHttpResponseInfo(status_code=404),
        ),
        url=EcsUrlInfo(original="/admin"),
        user_agent=EcsUserAgentInfo(original="curl/8.0"),
        asp=AspMetaInfo(parse_status=ParseStatus.OK, parser="apache_combined@1"),
    )
    assert web_ev.http is not None
    assert web_ev.http.response is not None
    assert web_ev.http.response.status_code == 404

    unparsed_ev = ECSEvent(
        timestamp=datetime(2026, 11, 10, 2, 0, 1, tzinfo=timezone.utc),
        event=EcsEventMeta(
            id="b" * 40,
            category=["host"],
            type=["info"],
            action="unparsed",
            dataset="linux.syslog",
            original="corrupted line",
            created=datetime(2026, 11, 10, 2, 0, 1, tzinfo=timezone.utc),
            ingested=datetime(2026, 11, 10, 2, 0, 2, tzinfo=timezone.utc),
        ),
        host=EcsHostInfo(name="web-01"),
        agent=EcsAgentInfo(id="web-01", version="0.1.0"),
        message="corrupted line",
        asp=AspMetaInfo(parse_status=ParseStatus.UNPARSED, ts_clamped=False),
    )
    assert unparsed_ev.asp.parse_status == ParseStatus.UNPARSED
    assert unparsed_ev.message == "corrupted line"


def test_alert_and_case_model_ddl_83():
    now = datetime(2026, 11, 10, 1, 30, 0, tzinfo=timezone.utc)
    uids = [compute_event_id("web-01", 2049, 131077, "7c1e9a52", i) for i in range(5)]

    alert = Alert(
        id=1,
        alert_key="asp-ssh-bruteforce:198.51.100.23:2989455",
        rule_id="asp-ssh-bruteforce",
        title="SSH brute force",
        level=AlertLevel.HIGH,
        window_start=now,
        window_end=now,
        group_key={"source.ip": "198.51.100.23"},
        event_count=5,
        event_uids=uids,
        case_id=10,
        tags=["attack.t1110"],
    )
    assert alert.id == 1
    assert alert.level == AlertLevel.HIGH
    assert alert.level.value == "high"
    assert alert.status == AlertStatus.NEW
    assert alert.status.value == "new"
    assert alert.case_id == 10

    case = Case(
        id=10,
        case_key="ip:198.51.100.23",
        source_ip="198.51.100.23",
        level=AlertLevel.HIGH,
        status=CaseStatus.OPEN,
        first_activity_at=now,
        last_activity_at=now,
        alerts=[alert],
    )
    assert case.id == 10
    assert case.status == CaseStatus.OPEN
    assert case.status.value == "open"
    assert case.agent_verdict is None
    assert case.agent_confidence is None
    assert case.ai_report is None

    # Serialize & Deserialize
    dumped = case.model_dump(mode="json")
    reloaded = Case.model_validate(dumped)
    assert reloaded.id == 10
    assert reloaded.case_key == "ip:198.51.100.23"
    assert reloaded.alerts[0].event_uids == uids


def test_alert_event_uids_max_200_enforced():
    too_many_uids = [f"{i:040x}" for i in range(201)]
    with pytest.raises(ValidationError):
        Alert(
            alert_key="k",
            rule_id="r",
            level=AlertLevel.LOW,
            event_count=201,
            event_uids=too_many_uids,
        )


def test_agent_report_update_validation():
    update = AgentReportUpdate(
        agent_verdict=AgentVerdict.TRUE_POSITIVE,
        agent_confidence=0.92,
        agent_report_markdown="# Report\nMalicious activity confirmed.",
        extracted_artifacts=[
            Artifact(artifact_type=ArtifactType.IP, value="1.2.3.4", reputation_score=90.0)
        ],
    )
    assert update.agent_confidence == 0.92
    assert update.agent_verdict == AgentVerdict.TRUE_POSITIVE

    with pytest.raises(ValidationError):
        AgentReportUpdate(
            agent_verdict=AgentVerdict.TRUE_POSITIVE,
            agent_confidence=1.5,
            agent_report_markdown="Invalid",
        )
