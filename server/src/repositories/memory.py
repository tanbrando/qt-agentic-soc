"""
In-Memory synchronous implementations of ILogRepository, IAlertRepository, and IAuthRepository
for testing and local development without external DB dependencies.
"""

from __future__ import annotations

import ipaddress
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from server.src.common.schemas import (
    AgentVerdict,
    Alert,
    AlertLevel,
    AlertStatus,
    Artifact,
    AspMetaInfo,
    Case,
    CaseStatus,
    ECSEvent,
    EcsAgentInfo,
    EcsEventMeta,
    EcsHostInfo,
    IngestBatchRequest,
    ParseStatus,
)
from server.src.repositories.base import (
    AgentRecord,
    BatchSaveOutcome,
    IAlertRepository,
    IAuthRepository,
    ILogRepository,
    OperatorRecord,
    ParserFn,
)


def _get_nested_value(doc: Dict[str, Any], dotted_path: str) -> Any:
    cur: Any = doc
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _build_parse_error_event(
    event_uid: str,
    raw_msg: str,
    collected_at: datetime,
    ingested_at: datetime,
    batch: IngestBatchRequest,
) -> ECSEvent:
    return ECSEvent(
        timestamp=collected_at,
        event=EcsEventMeta(
            id=event_uid,
            category=["host"],
            type=["info"],
            action="parse_error",
            dataset=f"linux.{batch.events[0].log_type.value}" if batch.events else "linux.syslog",
            original=raw_msg,
            created=collected_at,
            ingested=ingested_at,
        ),
        host=EcsHostInfo(name=batch.agent.hostname, ip=list(batch.agent.ip)),
        agent=EcsAgentInfo(id=batch.agent.id, version=batch.agent.version),
        asp=AspMetaInfo(parse_status=ParseStatus.ERROR),
    )


class InMemoryLogRepository(ILogRepository):
    """In-memory store mirroring events_raw (immutable/dedup) + normalized ECS events."""

    def __init__(self) -> None:
        self._raw: Dict[str, Dict[str, Any]] = {}
        self._events: List[ECSEvent] = []
        self._by_id: Dict[str, ECSEvent] = {}

    def save_batch_with_parser(
        self,
        batch: IngestBatchRequest,
        parser_fn: ParserFn,
        ingested_at: datetime,
    ) -> BatchSaveOutcome:
        new_events: List[ECSEvent] = []
        duplicate_count = 0
        unparsed_count = 0
        parse_error_count = 0

        for raw_ev in batch.events:
            event_uid = batch.event_id_for(raw_ev)
            if event_uid in self._raw:
                duplicate_count += 1
                continue

            self._raw[event_uid] = {
                "event_uid": event_uid,
                "agent_id": batch.agent.id,
                "batch_id": batch.batch_id,
                "log_type": raw_ev.log_type.value,
                "message": raw_ev.message,
                "message_truncated": raw_ev.message_truncated,
                "file_meta": raw_ev.file.model_dump(mode="json"),
                "agent_meta": batch.agent.model_dump(mode="json"),
                "collected_at": raw_ev.collected_at,
                "received_at": ingested_at,
            }

            try:
                ecs_event = parser_fn(raw_ev, batch.agent, event_uid, ingested_at)
            except Exception:
                ecs_event = _build_parse_error_event(
                    event_uid, raw_ev.message, raw_ev.collected_at, ingested_at, batch
                )
                ecs_event.event.dataset = (
                    "apache.access"
                    if raw_ev.log_type.value == "apache"
                    else f"linux.{raw_ev.log_type.value}"
                )

            if ecs_event.asp.parse_status == ParseStatus.UNPARSED:
                unparsed_count += 1
            elif ecs_event.asp.parse_status == ParseStatus.ERROR:
                parse_error_count += 1

            self._events.append(ecs_event)
            self._by_id[event_uid] = ecs_event
            new_events.append(ecs_event)

        return BatchSaveOutcome(
            new_events=new_events,
            duplicate_count=duplicate_count,
            unparsed_count=unparsed_count,
            parse_error_count=parse_error_count,
        )

    def save_events(self, events: List[ECSEvent]) -> None:
        for ev in events:
            uid = ev.event.id
            if uid in self._by_id:
                continue
            if uid not in self._raw:
                self._raw[uid] = {
                    "event_uid": uid,
                    "agent_id": ev.agent.id,
                    "batch_id": None,
                    "log_type": ev.event.dataset.split(".")[-1],
                    "message": ev.event.original,
                    "message_truncated": bool(ev.asp.message_truncated),
                    "file_meta": {"path": ev.log.file.path if ev.log else ""},
                    "agent_meta": {"hostname": ev.host.name, "version": ev.agent.version},
                    "collected_at": ev.event.created,
                    "received_at": ev.event.ingested,
                }
            self._events.append(ev)
            self._by_id[uid] = ev

    def find_events(self, query: Dict[str, Any], limit: int = 50) -> List[ECSEvent]:
        results: List[ECSEvent] = []
        ordered = sorted(self._events, key=lambda e: e.timestamp, reverse=True)
        for ev in ordered:
            doc = ev.to_ecs_dict()
            matches = True
            for k, v in query.items():
                if k in ("event_id", "event.id"):
                    if isinstance(v, list):
                        if ev.event.id not in v:
                            matches = False
                            break
                    elif ev.event.id != v:
                        matches = False
                        break
                elif k == "hostname":
                    if ev.host.name != v:
                        matches = False
                        break
                elif k == "src_ip":
                    if (ev.source.ip if ev.source else None) != v:
                        matches = False
                        break
                elif k == "user":
                    if (ev.user.name if ev.user else None) != v:
                        matches = False
                        break
                elif k == "service":
                    if (ev.process.name if ev.process else None) != v:
                        matches = False
                        break
                elif _get_nested_value(doc, k) != v:
                    matches = False
                    break
            if matches:
                results.append(ev)
                if len(results) >= limit:
                    break
        return results

    def get_by_ids(self, event_ids: List[str]) -> List[ECSEvent]:
        return [self._by_id[eid] for eid in event_ids if eid in self._by_id]

    def get_raw_event(self, event_uid: str) -> Optional[Dict[str, Any]]:
        raw = self._raw.get(event_uid)
        return dict(raw) if raw is not None else None

    def get_max_event_ts(self) -> Optional[datetime]:
        if not self._events:
            return None
        return max(ev.timestamp for ev in self._events)

    def find_events_since(self, since: datetime) -> List[ECSEvent]:
        since_utc = since.replace(tzinfo=timezone.utc) if since.tzinfo is None else since.astimezone(timezone.utc)
        matched = [
            ev
            for ev in self._events
            if (ev.timestamp.replace(tzinfo=timezone.utc) if ev.timestamp.tzinfo is None else ev.timestamp.astimezone(timezone.utc)) >= since_utc
        ]
        return sorted(matched, key=lambda e: (e.timestamp, e.event.id))

    def list_events(
        self,
        source_ip: Optional[str] = None,
        user_name: Optional[str] = None,
        action: Optional[str] = None,
        dataset: Optional[str] = None,
        parse_status: Optional[ParseStatus] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ECSEvent]:
        norm_ip = str(ipaddress.ip_address(source_ip)) if source_ip else None
        since_utc = (since.replace(tzinfo=timezone.utc) if since.tzinfo is None else since.astimezone(timezone.utc)) if since else None
        until_utc = (until.replace(tzinfo=timezone.utc) if until.tzinfo is None else until.astimezone(timezone.utc)) if until else None

        filtered: List[ECSEvent] = []
        for ev in self._events:
            if norm_ip is not None:
                ev_ip = ev.source.ip if ev.source else None
                if not ev_ip or str(ipaddress.ip_address(ev_ip)) != norm_ip:
                    continue
            if user_name is not None and (ev.user.name if ev.user else None) != user_name:
                continue
            if action is not None and ev.event.action != action:
                continue
            if dataset is not None and ev.event.dataset != dataset:
                continue
            if parse_status is not None and ev.asp.parse_status != parse_status:
                continue
            ev_ts = ev.timestamp.replace(tzinfo=timezone.utc) if ev.timestamp.tzinfo is None else ev.timestamp.astimezone(timezone.utc)
            if since_utc is not None and ev_ts < since_utc:
                continue
            if until_utc is not None and ev_ts > until_utc:
                continue
            filtered.append(ev)

        ordered = sorted(filtered, key=lambda e: (e.timestamp, e.event.id), reverse=True)
        return [ev.model_copy(deep=True) for ev in ordered[offset : offset + limit]]


class InMemoryAlertRepository(IAlertRepository):
    """In-memory store for alerts and cases with auto-increment integer IDs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._alerts: Dict[int, Alert] = {}
        self._alert_keys: set[str] = set()
        self._cases: Dict[int, Case] = {}
        self._open_case_by_key: Dict[str, int] = {}
        self._next_alert_id: int = 1
        self._next_case_id: int = 1

    def correlate_alert_to_case(
        self,
        alert: Alert,
        case_key: str,
        source_ip: Optional[str],
        idle_timeout_seconds: int = 21_600,
    ) -> Optional[Case]:
        with self._lock:
            return super().correlate_alert_to_case(
                alert=alert,
                case_key=case_key,
                source_ip=source_ip,
                idle_timeout_seconds=idle_timeout_seconds,
            )

    def save_alert(self, alert: Alert) -> Optional[Alert]:
        if alert.alert_key in self._alert_keys:
            return None
        if alert.id is None:
            alert.id = self._next_alert_id
            self._next_alert_id += 1
        stored = alert.model_copy(deep=True)
        self._alert_keys.add(stored.alert_key)
        self._alerts[stored.id] = stored
        return stored

    def assign_alert_case(self, alert_id: int, case_id: int) -> None:
        alert = self._alerts.get(alert_id)
        if alert is not None:
            alert.case_id = case_id
        case = self._cases.get(case_id)
        if case is not None and alert is not None:
            if not any(a.id == alert_id for a in case.alerts):
                case.alerts.append(alert)

    def save_case(self, case: Case) -> Case:
        if case.id is None:
            if case.status == CaseStatus.OPEN and case.case_key in self._open_case_by_key:
                raise ValueError(f"Open case already exists for key {case.case_key}")
            case.id = self._next_case_id
            self._next_case_id += 1
        stored = case.model_copy(deep=True)
        for a in stored.alerts:
            a.case_id = stored.id
            if a.id is not None and a.id in self._alerts:
                self._alerts[a.id].case_id = stored.id
        self._cases[stored.id] = stored
        if stored.status == CaseStatus.OPEN:
            self._open_case_by_key[stored.case_key] = stored.id
        elif self._open_case_by_key.get(stored.case_key) == stored.id:
            del self._open_case_by_key[stored.case_key]
        return stored

    def get_case(self, case_id: int) -> Optional[Case]:
        case = self._cases.get(case_id)
        if case is None:
            return None
        copy_case = case.model_copy(deep=True)
        copy_case.alerts = sorted(
            [a.model_copy(deep=True) for a in self._alerts.values() if a.case_id == case_id],
            key=lambda a: (a.created_at, a.id or 0),
        )
        return copy_case

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        level: Optional[AlertLevel] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Case]:
        norm_ip = str(ipaddress.ip_address(source_ip)) if source_ip else None
        cases = list(self._cases.values())
        if status is not None:
            cases = [c for c in cases if c.status == status]
        if level is not None:
            cases = [c for c in cases if c.level == level]
        if norm_ip is not None:
            cases = [
                c
                for c in cases
                if c.source_ip and str(ipaddress.ip_address(c.source_ip)) == norm_ip
            ]
        ordered = sorted(cases, key=lambda c: (c.created_at, c.id or 0), reverse=True)
        sliced = ordered[offset : offset + limit]
        return [self.get_case(c.id) for c in sliced if c.id is not None]  # type: ignore[misc]

    def list_alerts(
        self,
        rule_id: Optional[str] = None,
        level: Optional[AlertLevel] = None,
        status: Optional[AlertStatus] = None,
        case_id: Optional[int] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Alert]:
        since_utc = (since.replace(tzinfo=timezone.utc) if since.tzinfo is None else since.astimezone(timezone.utc)) if since else None
        until_utc = (until.replace(tzinfo=timezone.utc) if until.tzinfo is None else until.astimezone(timezone.utc)) if until else None

        filtered: List[Alert] = []
        for al in self._alerts.values():
            if rule_id is not None and al.rule_id != rule_id:
                continue
            if level is not None and al.level != level:
                continue
            if status is not None and al.status != status:
                continue
            if case_id is not None and al.case_id != case_id:
                continue
            al_ts = al.created_at.replace(tzinfo=timezone.utc) if al.created_at.tzinfo is None else al.created_at.astimezone(timezone.utc)
            if since_utc is not None and al_ts < since_utc:
                continue
            if until_utc is not None and al_ts > until_utc:
                continue
            filtered.append(al)

        ordered = sorted(filtered, key=lambda a: (a.created_at, a.id or 0), reverse=True)
        return [al.model_copy(deep=True) for al in ordered[offset : offset + limit]]

    def find_open_case_by_key(self, case_key: str) -> Optional[Case]:
        case_id = self._open_case_by_key.get(case_key)
        if case_id is not None:
            case = self.get_case(case_id)
            if case is not None and case.status == CaseStatus.OPEN:
                return case
        return None

    def list_alerts_since(self, window_end_since: datetime) -> List[Alert]:
        cutoff = (
            window_end_since.replace(tzinfo=timezone.utc)
            if window_end_since.tzinfo is None
            else window_end_since.astimezone(timezone.utc)
        )
        matched = []
        for al in self._alerts.values():
            ref = al.window_end or al.created_at
            ref_utc = ref.replace(tzinfo=timezone.utc) if ref.tzinfo is None else ref.astimezone(timezone.utc)
            if ref_utc >= cutoff:
                matched.append(al.model_copy(deep=True))
        return sorted(matched, key=lambda a: (a.window_end or a.created_at, a.id or 0))

    def update_case_with_agent_report(self, case_id: int, report_data: Dict[str, Any]) -> None:
        case = self._cases.get(case_id)
        if not case:
            raise ValueError(f"Case with ID {case_id} not found")

        if "agent_verdict" in report_data and report_data["agent_verdict"] is not None:
            verdict = report_data["agent_verdict"]
            case.agent_verdict = verdict.value if isinstance(verdict, AgentVerdict) else str(verdict)
        if "agent_confidence" in report_data and report_data["agent_confidence"] is not None:
            case.agent_confidence = float(report_data["agent_confidence"])
        if "agent_report_markdown" in report_data and report_data["agent_report_markdown"] is not None:
            case.agent_report_markdown = str(report_data["agent_report_markdown"])
        if "ai_report" in report_data and report_data["ai_report"] is not None:
            case.ai_report = dict(report_data["ai_report"])
            case.ai_investigated_at = datetime.now(timezone.utc)

        artifact_list = report_data.get("artifacts") or report_data.get("extracted_artifacts") or []
        for item in artifact_list:
            art = item if isinstance(item, Artifact) else Artifact(**item)
            if not any(a.value == art.value and a.artifact_type == art.artifact_type for a in case.artifacts):
                case.artifacts.append(art)

        case.updated_at = datetime.now(timezone.utc)


class InMemoryAuthRepository(IAuthRepository):
    """In-memory credential store for agents and operators."""

    def __init__(self) -> None:
        self._agents: Dict[str, AgentRecord] = {}
        self._agents_by_hash: Dict[str, str] = {}
        self._operators: Dict[str, OperatorRecord] = {}
        self._operators_by_hash: Dict[str, str] = {}

    def create_agent(
        self,
        agent_id: str,
        api_key_hash: str,
        hostname: Optional[str] = None,
    ) -> AgentRecord:
        if agent_id in self._agents:
            raise ValueError(f"Agent {agent_id} already exists")
        if api_key_hash in self._agents_by_hash:
            raise ValueError("API key hash already registered")
        rec = AgentRecord(
            id=agent_id,
            api_key_hash=api_key_hash,
            hostname=hostname,
            created_at=datetime.now(timezone.utc),
        )
        self._agents[agent_id] = rec
        self._agents_by_hash[api_key_hash] = agent_id
        return rec

    def get_agent_by_key_hash(self, api_key_hash: str) -> Optional[AgentRecord]:
        agent_id = self._agents_by_hash.get(api_key_hash)
        if agent_id is None:
            return None
        rec = self._agents.get(agent_id)
        if rec is not None and rec.revoked_at is None:
            return rec
        return None

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        return self._agents.get(agent_id)

    def touch_agent_last_seen(self, agent_id: str, seen_at: datetime) -> None:
        rec = self._agents.get(agent_id)
        if rec is not None:
            rec.last_seen = seen_at

    def revoke_agent(self, agent_id: str) -> bool:
        rec = self._agents.get(agent_id)
        if rec is None:
            return False
        rec.revoked_at = datetime.now(timezone.utc)
        return True

    def rotate_agent_key(self, agent_id: str, new_api_key_hash: str) -> bool:
        rec = self._agents.get(agent_id)
        if rec is None:
            return False
        self._agents_by_hash.pop(rec.api_key_hash, None)
        rec.api_key_hash = new_api_key_hash
        rec.revoked_at = None
        self._agents_by_hash[new_api_key_hash] = agent_id
        return True

    def create_operator(
        self,
        operator_id: str,
        token_hash: str,
        scopes: List[str],
    ) -> OperatorRecord:
        if operator_id in self._operators:
            raise ValueError(f"Operator {operator_id} already exists")
        if token_hash in self._operators_by_hash:
            raise ValueError("Operator token hash already registered")
        rec = OperatorRecord(
            id=operator_id,
            token_hash=token_hash,
            scopes=list(scopes),
            created_at=datetime.now(timezone.utc),
        )
        self._operators[operator_id] = rec
        self._operators_by_hash[token_hash] = operator_id
        return rec

    def get_operator_by_token_hash(self, token_hash: str) -> Optional[OperatorRecord]:
        op_id = self._operators_by_hash.get(token_hash)
        if op_id is None:
            return None
        rec = self._operators.get(op_id)
        if rec is not None and rec.revoked_at is None:
            return rec
        return None

    def revoke_operator(self, operator_id: str) -> bool:
        rec = self._operators.get(operator_id)
        if rec is None:
            return False
        rec.revoked_at = datetime.now(timezone.utc)
        return True
