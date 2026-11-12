"""
Data Contracts and Pydantic v2 Models for the ASP (Agentic SOC Platform).
Follows the v1.1 Ingestion Envelope (Section 5), ECS Subset Event Schema (Section 6),
and PostgreSQL DDL Contracts (Section 8.3).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Helpers
# ============================================================================

def _ensure_utc(v: Optional[datetime]) -> Optional[datetime]:
    """Enforces UTC timezone on aware or naive datetimes."""
    if v is None:
        return None
    if v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc)
    return v.astimezone(timezone.utc)


def compute_event_id(
    agent_id: str,
    device: int,
    inode: int,
    stream_id: str,
    offset: int,
) -> str:
    """
    Computes deterministic SHA-1 hex identifier (event.id / event_uid):
    sha1(agent_id|device|inode|stream_id|offset).
    """
    raw_key = f"{agent_id}|{device}|{inode}|{stream_id}|{offset}".encode("utf-8")
    return hashlib.sha1(raw_key).hexdigest()


# ============================================================================
# Enums
# ============================================================================

class LogType(str, Enum):
    """Supported log source categories."""
    AUTH = "auth"
    SYSLOG = "syslog"
    APACHE = "apache"
    AUDIT = "audit"
    KERNEL = "kernel"
    PACKAGE = "package"


class EventOutcome(str, Enum):
    """ECS-standardized event outcome."""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class ParseStatus(str, Enum):
    """Server-side parser outcome stored in asp.parse_status."""
    OK = "ok"
    UNPARSED = "unparsed"
    ERROR = "error"


class AlertLevel(str, Enum):
    """SOC alert and case severity tiers (lowercase per DDL Section 8.3)."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Alert triage lifecycle status (defaults to 'new' per DDL Section 8.3)."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class CaseStatus(str, Enum):
    """Case lifecycle status per DDL Section 8.3."""
    OPEN = "open"
    CLOSED = "closed"


class ArtifactType(str, Enum):
    """Observable security artifact (retained for Phase 6 compatibility)."""
    IP = "IP"
    USER = "USER"
    PROCESS = "PROCESS"
    FILE_HASH = "FILE_HASH"
    URL = "URL"
    DOMAIN = "DOMAIN"


class AgentVerdict(str, Enum):
    """AI SOC Analyst conclusion (retained for Phase 6 compatibility)."""
    TRUE_POSITIVE = "True Positive"
    FALSE_POSITIVE = "False Positive"
    INCONCLUSIVE = "Inconclusive"


# ============================================================================
# Client Ingestion Contracts (Section 5)
# ============================================================================

class RawEventFileMeta(BaseModel):
    """File tailing metadata attached by the thin Linux collector agent."""
    model_config = ConfigDict(extra="ignore")

    path: str = Field(..., min_length=1)
    device: int = Field(..., ge=0)
    inode: int = Field(..., ge=0)
    stream_id: str = Field(..., min_length=1)
    offset: int = Field(..., ge=0)


class RawLogEvent(BaseModel):
    """Single raw log line and collection metadata sent inside an ingest batch."""
    model_config = ConfigDict(extra="ignore")

    log_type: LogType
    file: RawEventFileMeta
    collected_at: datetime
    message: str
    message_truncated: bool = False

    @field_validator("collected_at", mode="after")
    @classmethod
    def _normalize_collected_at(cls, v: datetime) -> datetime:
        normalized = _ensure_utc(v)
        assert normalized is not None
        return normalized


class AgentMetadata(BaseModel):
    """Source agent metadata included in the batch envelope."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    ip: List[str] = Field(default_factory=list)
    timezone: Optional[str] = None

    @field_validator("timezone", mode="after")
    @classmethod
    def _validate_iana_timezone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"Invalid IANA timezone: {v!r}") from exc
        return v


class IngestBatchRequest(BaseModel):
    """
    Batch ingestion payload sent by endpoint collector agents (POST /api/v1/ingest/logs).
    Note: Max 500 events / 1 MB limit is enforced at the API layer to return HTTP 413 instead of 422.
    """
    model_config = ConfigDict(extra="ignore")

    schema_version: str = Field(default="1.1", min_length=1)
    batch_id: str = Field(..., min_length=1)
    sent_at: datetime
    agent: AgentMetadata
    events: List[RawLogEvent] = Field(..., min_length=1)

    @field_validator("sent_at", mode="after")
    @classmethod
    def _normalize_sent_at(cls, v: datetime) -> datetime:
        normalized = _ensure_utc(v)
        assert normalized is not None
        return normalized

    def event_id_for(self, raw_event: RawLogEvent) -> str:
        """Computes the deterministic SHA-1 event.id for an event in this batch."""
        return compute_event_id(
            agent_id=self.agent.id,
            device=raw_event.file.device,
            inode=raw_event.file.inode,
            stream_id=raw_event.file.stream_id,
            offset=raw_event.file.offset,
        )


class IngestBatchResponse(BaseModel):
    """HTTP 202 response acknowledging batch processing metrics (Section 5)."""
    accepted: int = Field(..., ge=0)
    duplicates: int = Field(default=0, ge=0)
    unparsed: int = Field(default=0, ge=0)
    parse_errors: int = Field(default=0, ge=0)


# ============================================================================
# Normalized ECS Subset Event Contracts (Section 6)
# ============================================================================

class EcsVersionInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    version: str = "8.11"


class EcsEventMeta(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., min_length=1)
    kind: str = "event"
    category: List[str] = Field(..., min_length=1)
    type: List[str] = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    outcome: Optional[EventOutcome] = None
    dataset: str = Field(..., min_length=1)
    original: str
    created: datetime
    ingested: datetime

    @field_validator("created", "ingested", mode="after")
    @classmethod
    def _normalize_dt(cls, v: datetime) -> datetime:
        normalized = _ensure_utc(v)
        assert normalized is not None
        return normalized


class EcsHostInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., min_length=1)
    ip: List[str] = Field(default_factory=list)


class EcsAgentInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., min_length=1)
    type: str = "asp-agent"
    version: str = Field(..., min_length=1)


class EcsLogFileInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    path: str = Field(..., min_length=1)


class EcsLogInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    file: EcsLogFileInfo


class EcsEndpointInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=0, le=65535)


class EcsUserInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = Field(..., min_length=1)


class EcsProcessInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: Optional[str] = None
    pid: Optional[int] = Field(default=None, ge=0)
    args: Optional[str] = None


class EcsHttpRequestInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    method: Optional[str] = None


class EcsHttpResponseInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    status_code: Optional[int] = Field(default=None, ge=100, le=599)


class EcsHttpInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    request: Optional[EcsHttpRequestInfo] = None
    response: Optional[EcsHttpResponseInfo] = None


class EcsUrlInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    original: Optional[str] = None


class EcsUserAgentInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    original: Optional[str] = None


class EcsRelatedInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: List[str] = Field(default_factory=list)
    user: List[str] = Field(default_factory=list)


class AspMetaInfo(BaseModel):
    """ASP-specific parsing metadata stored under 'asp'."""
    model_config = ConfigDict(extra="allow")

    parse_status: ParseStatus
    parser: Optional[str] = None
    auth_method: Optional[str] = None
    sudo_target_user: Optional[str] = None
    ts_clamped: Optional[bool] = None
    message_truncated: Optional[bool] = None


class ECSEvent(BaseModel):
    """
    Normalized ECS-subset event stored in the `events` table (`doc` JSONB + indexed columns).
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    timestamp: datetime = Field(..., alias="@timestamp")
    ecs: EcsVersionInfo = Field(default_factory=EcsVersionInfo)
    event: EcsEventMeta
    host: EcsHostInfo
    agent: EcsAgentInfo
    log: Optional[EcsLogInfo] = None
    source: Optional[EcsEndpointInfo] = None
    user: Optional[EcsUserInfo] = None
    process: Optional[EcsProcessInfo] = None
    http: Optional[EcsHttpInfo] = None
    url: Optional[EcsUrlInfo] = None
    user_agent: Optional[EcsUserAgentInfo] = None
    related: Optional[EcsRelatedInfo] = None
    message: Optional[str] = None
    asp: AspMetaInfo

    @field_validator("timestamp", mode="after")
    @classmethod
    def _normalize_timestamp(cls, v: datetime) -> datetime:
        normalized = _ensure_utc(v)
        assert normalized is not None
        return normalized

    def to_ecs_dict(self) -> Dict[str, Any]:
        """Serializes to ECS JSON dict with '@timestamp' alias and None fields omitted."""
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


# ============================================================================
# Security Detection & Case Management Contracts (Section 8.3)
# ============================================================================

class Alert(BaseModel):
    """
    Security alert produced by the detection engine, aligned with `alerts` DDL (Section 8.3).
    """
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    alert_key: str = Field(..., min_length=1)
    rule_id: str = Field(..., min_length=1)
    title: Optional[str] = None
    level: AlertLevel
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    group_key: Dict[str, Any] = Field(default_factory=dict)
    event_count: int = Field(default=0, ge=0)
    event_uids: List[str] = Field(default_factory=list, max_length=200)
    status: AlertStatus = AlertStatus.NEW
    case_id: Optional[int] = None
    tags: List[str] = Field(default_factory=list)

    @field_validator("created_at", "window_start", "window_end", mode="after")
    @classmethod
    def _normalize_alert_dates(cls, v: Optional[datetime]) -> Optional[datetime]:
        return _ensure_utc(v)


class Artifact(BaseModel):
    """Extracted observable / IoC (retained for Phase 6 compatibility)."""
    model_config = ConfigDict(extra="ignore")

    artifact_type: ArtifactType
    value: str = Field(..., min_length=1)
    reputation_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Reputation confidence score (e.g., AbuseIPDB abuseConfidenceScore 0-100)",
    )
    reputation_vendor: Optional[str] = Field(default=None, description="e.g., AbuseIPDB, VirusTotal")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentReportUpdate(BaseModel):
    """Payload to update a case after automated agent triage (Phase 6 compatibility)."""
    agent_verdict: AgentVerdict
    agent_confidence: float = Field(..., ge=0.0, le=1.0)
    agent_report_markdown: str = Field(..., min_length=1)
    extracted_artifacts: List[Artifact] = Field(default_factory=list)


class Case(BaseModel):
    """
    Security incident case aligned with `cases` DDL (Section 8.3).
    Retains optional Phase 6 fields (agent_verdict, agent_confidence, ai_report) defaulting to None.
    """
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    case_key: str = Field(..., min_length=1)
    source_ip: Optional[str] = None
    level: AlertLevel
    status: CaseStatus = CaseStatus.OPEN
    first_activity_at: datetime
    last_activity_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Optional AI / Investigation & API-enrichment fields (default None / empty for Phase 6 compatibility)
    ai_report: Optional[Dict[str, Any]] = None
    ai_investigated_at: Optional[datetime] = None
    agent_verdict: Optional[str] = None
    agent_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    agent_report_markdown: Optional[str] = None
    title: Optional[str] = None
    alerts: List[Alert] = Field(default_factory=list)
    artifacts: List[Artifact] = Field(default_factory=list)

    @field_validator(
        "first_activity_at",
        "last_activity_at",
        "created_at",
        "updated_at",
        "ai_investigated_at",
        mode="after",
    )
    @classmethod
    def _normalize_case_dates(cls, v: Optional[datetime]) -> Optional[datetime]:
        return _ensure_utc(v)
