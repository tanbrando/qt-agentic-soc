"""
Data Contracts and Pydantic v2 Models for the Agentic SOC Platform.
Follows a Hybrid ECS-style (Elastic Common Schema) envelope pattern.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Enums
# ============================================================================

class LogType(str, Enum):
    """Supported log source categories."""
    AUTH = "auth"
    SYSLOG = "syslog"
    APACHE = "apache"
    KERNEL = "kernel"
    PACKAGE = "package"


class EventOutcome(str, Enum):
    """ECS-standardized event outcome."""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """SOC alert and case severity tiers."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    """Case and alert triage lifecycle status."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ArtifactType(str, Enum):
    """Observable security artifact (Indicator of Compromise / Observable)."""
    IP = "IP"
    USER = "USER"
    PROCESS = "PROCESS"
    FILE_HASH = "FILE_HASH"
    URL = "URL"
    DOMAIN = "DOMAIN"


class AgentVerdict(str, Enum):
    """AI SOC Analyst conclusion."""
    TRUE_POSITIVE = "True Positive"
    FALSE_POSITIVE = "False Positive"
    INCONCLUSIVE = "Inconclusive"


# ============================================================================
# Client Ingestion Contracts
# ============================================================================

class LogEventEnvelope(BaseModel):
    """
    Standardized telemetry envelope ingested from edge agents or collector services.
    Preserves raw log line for cryptographic / forensic auditability.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    event_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this log event",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO 8601 timestamp with timezone when the event occurred",
    )
    agent_id: str = Field(..., min_length=1, description="Host agent collector ID")
    hostname: str = Field(..., min_length=1, description="Source endpoint hostname")
    log_type: LogType = Field(..., description="Classification category of the log")
    source_file: str = Field(..., min_length=1, description="Source path (e.g., /var/log/auth.log)")
    raw: str = Field(..., description="Verbatim raw log line")
    fields: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parsed normalized attributes (e.g. service, pid, src_ip, user, event_outcome)",
    )

    @field_validator("timestamp", mode="after")
    @classmethod
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Enforces UTC if timezone information was missing."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    def get_field(self, key: str, default: Any = None) -> Any:
        """Helper to safely access parsed fields."""
        return self.fields.get(key, default)


class IngestBatchRequest(BaseModel):
    """Batch ingestion payload sent by endpoint collector agents."""
    model_config = ConfigDict(extra="ignore")

    agent_id: str = Field(..., min_length=1)
    client_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    batch_size: int = Field(..., ge=1, le=10000)
    events: List[LogEventEnvelope] = Field(..., min_length=1)

    @field_validator("batch_size", mode="after")
    @classmethod
    def validate_batch_size_matches(cls, v: int, info) -> int:
        events = info.data.get("events")
        if events is not None and len(events) != v:
            # Synchronize or accept as count
            return len(events)
        return v


class IngestBatchResponse(BaseModel):
    """Server response acknowledging received batch."""
    accepted_count: int
    alerts_generated: int = 0
    case_ids: List[UUID] = Field(default_factory=list)
    status: str = "ok"


# ============================================================================
# Security Detection & Case Management Contracts
# ============================================================================

class Alert(BaseModel):
    """
    Security alert produced by the detection engine when a rule condition is satisfied.
    """
    model_config = ConfigDict(extra="ignore")

    alert_id: UUID = Field(default_factory=uuid4)
    rule_id: Optional[str] = Field(default=None, description="Identifier of the firing rule")
    rule_name: str = Field(..., min_length=1)
    severity: Severity = Field(...)
    hostname: str = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed contextual attributes (e.g. attacker IP, target user, failure count)",
    )
    evidence_raw_events: List[UUID] = Field(
        default_factory=list,
        description="Correlated LogEventEnvelope event IDs that triggered this alert",
    )
    mitre_tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK Tactics (e.g. TA0006)")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK Techniques (e.g. T1110)")
    dedup_key: Optional[str] = Field(
        default=None,
        description="Correlation key used to group related alerts into the same case",
    )


class Artifact(BaseModel):
    """Extracted observable / Indicator of Compromise (IoC) with threat intel enrichment."""
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
    """Payload to update a case after automated agent triage."""
    agent_verdict: AgentVerdict
    agent_confidence: float = Field(..., ge=0.0, le=1.0)
    agent_report_markdown: str = Field(..., min_length=1)
    extracted_artifacts: List[Artifact] = Field(default_factory=list)


class Case(BaseModel):
    """
    Security incident case grouping one or more alerts, correlated artifacts,
    and agent investigation reports.
    """
    model_config = ConfigDict(extra="ignore")

    case_id: UUID = Field(default_factory=uuid4)
    title: str = Field(..., min_length=1)
    severity: Severity = Field(...)
    status: AlertStatus = Field(default=AlertStatus.OPEN)
    alerts: List[Alert] = Field(default_factory=list)
    artifacts: List[Artifact] = Field(default_factory=list)
    agent_verdict: Optional[str] = Field(default=None)
    agent_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    agent_report_markdown: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

