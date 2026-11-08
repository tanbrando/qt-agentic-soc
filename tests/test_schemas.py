"""
Unit tests for Pydantic v2 Schemas and Data Contracts.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from server.src.common.schemas import (
    AgentReportUpdate,
    AgentVerdict,
    Alert,
    AlertStatus,
    Artifact,
    ArtifactType,
    Case,
    EventOutcome,
    IngestBatchRequest,
    IngestBatchResponse,
    LogEventEnvelope,
    LogType,
    Severity,
)


def test_log_event_envelope_creation():
    event_id = uuid4()
    now = datetime.now(timezone.utc)
    envelope = LogEventEnvelope(
        event_id=event_id,
        timestamp=now,
        agent_id="agent-01",
        hostname="web-prod-01",
        log_type=LogType.AUTH,
        source_file="/var/log/auth.log",
        raw="Oct 11 04:02:11 web-prod-01 sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2",
        fields={"service": "sshd", "src_ip": "1.2.3.4", "event_outcome": EventOutcome.FAILURE.value},
    )

    assert envelope.event_id == event_id
    assert envelope.agent_id == "agent-01"
    assert envelope.log_type == LogType.AUTH
    assert envelope.get_field("service") == "sshd"
    assert envelope.get_field("missing", "default_val") == "default_val"
    assert envelope.timestamp.tzinfo is not None


def test_naive_timestamp_enforced_to_utc():
    naive_dt = datetime(2026, 10, 11, 4, 2, 11)
    envelope = LogEventEnvelope(
        agent_id="agent-01",
        hostname="web-prod-01",
        log_type=LogType.AUTH,
        source_file="/var/log/auth.log",
        raw="test log line",
        timestamp=naive_dt,
    )
    assert envelope.timestamp.tzinfo == timezone.utc


def test_ingest_batch_request_validation():
    envelope = LogEventEnvelope(
        agent_id="agent-01",
        hostname="web-prod-01",
        log_type=LogType.AUTH,
        source_file="/var/log/auth.log",
        raw="line 1",
    )
    batch = IngestBatchRequest(
        agent_id="agent-01",
        batch_size=1,
        events=[envelope],
    )
    assert batch.batch_size == 1
    assert len(batch.events) == 1

    # Empty events list should fail validation
    with pytest.raises(ValidationError):
        IngestBatchRequest(
            agent_id="agent-01",
            batch_size=0,
            events=[],
        )


def test_alert_and_case_model():
    alert_id = uuid4()
    evidence_id = uuid4()
    alert = Alert(
        alert_id=alert_id,
        rule_id="RULE-01",
        rule_name="SSH Brute Force",
        severity=Severity.HIGH,
        hostname="web-01",
        context={"src_ip": "198.51.100.23", "failure_count": 5},
        evidence_raw_events=[evidence_id],
        mitre_tactics=["TA0006"],
        mitre_techniques=["T1110.001"],
    )

    artifact = Artifact(
        artifact_type=ArtifactType.IP,
        value="198.51.100.23",
        reputation_score=95.0,
        reputation_vendor="AbuseIPDB",
    )

    case = Case(
        title="Incident: SSH Brute Force on web-01",
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        alerts=[alert],
        artifacts=[artifact],
    )

    assert len(case.alerts) == 1
    assert case.alerts[0].alert_id == alert_id
    assert case.artifacts[0].value == "198.51.100.23"
    assert case.status == AlertStatus.OPEN

    # Serialize & Deserialize
    dumped = case.model_dump(mode="json")
    reloaded = Case.model_validate(dumped)
    assert reloaded.case_id == case.case_id
    assert reloaded.alerts[0].evidence_raw_events[0] == evidence_id


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

    # Confidence must be between 0.0 and 1.0
    with pytest.raises(ValidationError):
        AgentReportUpdate(
            agent_verdict=AgentVerdict.TRUE_POSITIVE,
            agent_confidence=1.5,
            agent_report_markdown="Invalid",
        )

