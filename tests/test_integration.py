"""
Integration tests for IngestionService, Agent Investigation, and API endpoints.
Uses asyncio.run() for deterministic execution across standard Python environments.
"""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from server.src.api.dependencies import get_container, reset_container
from server.src.api.v1.cases import get_case, list_cases, trigger_case_investigation
from server.src.api.v1.ingest import ingest_logs
from server.src.common.schemas import (
    AgentVerdict,
    AlertStatus,
    IngestBatchRequest,
    LogEventEnvelope,
    LogType,
    Severity,
)


@pytest.fixture(autouse=True)
def clean_container():
    """Reset container before each test to ensure state isolation."""
    reset_container()
    yield


def test_end_to_end_ingestion_and_case_creation():
    async def _run():
        container = get_container()
        ingest_svc = container.ingestion_service

        # Create raw SSH brute force attempts (5 failed attempts from 198.51.100.23)
        attacker_ip = "198.51.100.23"
        events = []
        for i in range(5):
            raw_line = f"Oct 11 04:02:{10+i:02d} web-01 sshd[2849{i}]: Failed password for root from {attacker_ip} port 5234{i} ssh2"
            # Note: fields is empty, testing automatic server-side AuthLogParser normalization
            ev = LogEventEnvelope(
                event_id=uuid4(),
                timestamp=datetime.now(timezone.utc),
                agent_id="agent-01",
                hostname="web-01",
                log_type=LogType.AUTH,
                source_file="/var/log/auth.log",
                raw=raw_line,
                fields={},
            )
            events.append(ev)

        batch = IngestBatchRequest(
            agent_id="agent-01",
            batch_size=len(events),
            events=events,
        )

        # 1. Ingest batch
        response = await ingest_svc.ingest_batch(batch)
        assert response.accepted_count == 5
        assert response.alerts_generated == 1
        assert len(response.case_ids) == 1

        case_id = response.case_ids[0]

        # 2. Verify Case was created in AlertRepository
        case = await container.alert_repo.get_case(case_id)
        assert case is not None
        assert case.status == AlertStatus.OPEN
        assert case.severity == Severity.HIGH
        assert len(case.alerts) == 1
        assert case.alerts[0].rule_name == "SSH Authentication Brute Force"
        assert len(case.alerts[0].evidence_raw_events) == 5

        # 3. Trigger Agent Investigation
        report_update = await container.agent_investigator.investigate_case(case)
        assert report_update.agent_verdict == AgentVerdict.TRUE_POSITIVE
        assert report_update.agent_confidence >= 0.8
        assert len(report_update.extracted_artifacts) >= 1
        assert report_update.extracted_artifacts[0].value == attacker_ip
        assert "Executive Summary" in report_update.agent_report_markdown

        # 4. Save report update to case
        await container.alert_repo.update_case_with_agent_report(
            case_id=case_id,
            report_data=report_update.model_dump(),
        )

        updated_case = await container.alert_repo.get_case(case_id)
        assert updated_case is not None
        assert updated_case.agent_verdict == AgentVerdict.TRUE_POSITIVE.value
        assert updated_case.agent_confidence is not None

    asyncio.run(_run())


def test_api_endpoints_direct_invocation():
    async def _run():
        container = get_container()

        # 1. Ingest sudo abuse attempt via ingest_logs API handler
        batch = IngestBatchRequest(
            agent_id="test-edge-agent",
            batch_size=1,
            events=[
                LogEventEnvelope(
                    agent_id="test-edge-agent",
                    hostname="prod-db-01",
                    log_type=LogType.AUTH,
                    source_file="/var/log/auth.log",
                    raw="Oct 11 05:00:00 prod-db-01 sudo: attacker : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
                    fields={},
                )
            ],
        )

        res_ingest = await ingest_logs(batch, service=container.ingestion_service)
        assert res_ingest.accepted_count == 1
        assert res_ingest.alerts_generated == 1
        assert len(res_ingest.case_ids) == 1

        case_id = res_ingest.case_ids[0]

        # 2. Retrieve Case via get_case API handler
        case_data = await get_case(case_id=case_id, repo=container.alert_repo)
        assert case_data.case_id == case_id
        assert case_data.severity == Severity.HIGH
        assert case_data.status == AlertStatus.OPEN

        # 3. List cases via list_cases API handler
        all_cases = await list_cases(repo=container.alert_repo)
        assert len(all_cases) == 1

        # 4. Trigger Investigation via trigger_case_investigation API handler
        investigated = await trigger_case_investigation(
            case_id=case_id,
            repo=container.alert_repo,
            investigator=container.agent_investigator,
        )
        assert investigated.agent_verdict is not None
        assert investigated.agent_report_markdown is not None

    asyncio.run(_run())
