"""
Base interfaces, pure `parse(log_type, message, meta)` entrypoint, and ParserRegistry.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

from server.src.common.schemas import (
    AgentMetadata,
    AspMetaInfo,
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
    LogType,
    ParseStatus,
    RawLogEvent,
)


def _coerce_utc(value: Any) -> datetime:
    if isinstance(value, str):
        dt = datetime.fromisoformat(value)
    elif isinstance(value, datetime):
        dt = value
    else:
        raise ValueError(f"Invalid datetime value: {value!r}")
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class BaseLogParser(ABC):
    """
    Abstract Base Class for pure log source parsers.
    Subclasses must not read DB, call network, or read system clock.
    """

    @property
    @abstractmethod
    def supported_log_type(self) -> LogType:
        """The primary LogType handled by this parser."""
        pass

    @abstractmethod
    def can_handle(self, log_type: str, source_path: str) -> bool:
        """Determines if this parser supports the given log type and/or file path."""
        pass

    @abstractmethod
    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """
        Backward-compatible line parser extracting flat attributes.
        Returns None if the line cannot be parsed.
        """
        pass

    def parse_with_meta(
        self,
        message: str,
        meta: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Pure parsing hook receiving normalized metadata (`collected_at`, `received_at`,
        `agent`, `file`, `default_timezone`, `future_tolerance_seconds`).
        Subclasses may override to extract `@timestamp` and full ECS metadata.
        """
        return self.parse_line(message)


class ParserRegistry:
    """
    Registry maintaining active log parsers in priority order.
    """

    _registry: List[BaseLogParser] = []

    @classmethod
    def register(cls, parser_cls: Type[BaseLogParser]) -> Type[BaseLogParser]:
        instance = parser_cls()
        if not any(isinstance(p, parser_cls) for p in cls._registry):
            cls._registry.append(instance)
        return parser_cls

    @classmethod
    def register_instance(cls, parser: BaseLogParser) -> None:
        if parser not in cls._registry:
            cls._registry.append(parser)

    @classmethod
    def clear(cls) -> None:
        cls._registry.clear()

    @classmethod
    def get_parsers(cls, log_type: str, source_path: str = "") -> List[BaseLogParser]:
        """Returns all registered parsers capable of handling (log_type, source_path)."""
        return [p for p in cls._registry if p.can_handle(log_type, source_path)]

    @classmethod
    def get_parser(cls, log_type: str, source_path: str = "") -> Optional[BaseLogParser]:
        """Finds the first parser capable of handling the specified log_type and path."""
        parsers = cls.get_parsers(log_type, source_path)
        return parsers[0] if parsers else None

    @classmethod
    def parse(cls, log_type: str, message: str, meta: Dict[str, Any]) -> ECSEvent:
        """
        Pure normalization function (Section 7.1):
        `meta` contains: event_uid, collected_at, received_at, agent, file, message_truncated,
        and optional default_timezone / future_tolerance_seconds.
        Always returns a valid ECSEvent (with parse_status ok | unparsed | error).
        """
        collected_at = _coerce_utc(meta["collected_at"])
        received_at = _coerce_utc(meta.get("received_at") or collected_at)
        agent_meta = meta.get("agent") or {}
        file_meta = meta.get("file") or {}
        event_uid = str(meta["event_uid"])
        message_truncated = bool(meta.get("message_truncated", False))

        agent_id = str(agent_meta.get("id", "unknown"))
        host_name = str(agent_meta.get("hostname") or agent_id)
        host_ip = list(agent_meta.get("ip") or [])
        agent_version = str(agent_meta.get("version", "0.1.0"))
        source_path = str(file_meta.get("path", ""))

        dataset = "apache.access" if log_type == LogType.APACHE.value else f"linux.{log_type}"
        parsers = cls.get_parsers(log_type, source_path)

        fields: Optional[Dict[str, Any]] = None
        parse_status = ParseStatus.UNPARSED

        for parser in parsers:
            try:
                candidate = parser.parse_with_meta(message, meta)
                if candidate:
                    fields = candidate
                    parse_status = ParseStatus.OK
                    break
            except Exception:
                fields = None
                parse_status = ParseStatus.ERROR
                break

        if parse_status != ParseStatus.OK or not fields:
            action = "parse_error" if parse_status == ParseStatus.ERROR else "unparsed"
            return ECSEvent(
                timestamp=collected_at,
                event=EcsEventMeta(
                    id=event_uid,
                    category=["host"],
                    type=["info"],
                    action=action,
                    outcome=EventOutcome.UNKNOWN,
                    dataset=dataset,
                    original=message,
                    created=collected_at,
                    ingested=received_at,
                ),
                host=EcsHostInfo(name=host_name, ip=host_ip),
                agent=EcsAgentInfo(id=agent_id, version=agent_version),
                log=EcsLogInfo(file=EcsLogFileInfo(path=source_path)) if source_path else None,
                message=message if parse_status == ParseStatus.UNPARSED else None,
                asp=AspMetaInfo(
                    parse_status=parse_status,
                    message_truncated=message_truncated or None,
                ),
            )

        event_ts = _coerce_utc(fields["@timestamp"]) if "@timestamp" in fields else collected_at
        ts_clamped = bool(fields.get("ts_clamped", False))
        service = fields.get("service")
        action = fields.get("event_action") or "syslog_message"
        raw_outcome = fields.get("event_outcome")
        outcome = EventOutcome(raw_outcome) if raw_outcome else EventOutcome.UNKNOWN

        category = list(fields.get("category") or [])
        ev_type = list(fields.get("event_type") or [])
        if not category or not ev_type:
            if service == "sshd" or (log_type == LogType.AUTH.value and "ssh" in action):
                category = category or ["authentication"]
                ev_type = ev_type or ["start"]
            elif service == "sudo":
                category = category or ["process"]
                ev_type = ev_type or ["start"]
            elif service == "useradd":
                category = category or ["iam"]
                ev_type = ev_type or ["creation"]
            elif log_type == LogType.APACHE.value:
                category = category or ["web"]
                ev_type = ev_type or ["access"]
            else:
                category = category or ["host"]
                ev_type = ev_type or ["info"]

        src_ip = fields.get("src_ip")
        src_port = fields.get("src_port")
        user_name = fields.get("user")
        pid = fields.get("pid")
        command = fields.get("command")

        related_ip = [src_ip] if src_ip else []
        related_user = [user_name] if user_name else []

        http_info = None
        if fields.get("http_method") is not None or fields.get("http_status") is not None:
            http_info = EcsHttpInfo(
                request=EcsHttpRequestInfo(method=fields.get("http_method"))
                if "http_method" in fields
                else None,
                response=EcsHttpResponseInfo(status_code=fields.get("http_status"))
                if fields.get("http_status") is not None
                else None,
            )

        return ECSEvent(
            timestamp=event_ts,
            event=EcsEventMeta(
                id=event_uid,
                category=category,
                type=ev_type,
                action=action,
                outcome=outcome,
                dataset=dataset,
                original=message,
                created=collected_at,
                ingested=received_at,
            ),
            host=EcsHostInfo(name=host_name, ip=host_ip),
            agent=EcsAgentInfo(id=agent_id, version=agent_version),
            log=EcsLogInfo(file=EcsLogFileInfo(path=source_path)) if source_path else None,
            source=EcsEndpointInfo(ip=src_ip, port=src_port) if (src_ip or src_port is not None) else None,
            user=EcsUserInfo(name=user_name) if user_name else None,
            process=(
                EcsProcessInfo(
                    name=service if service and service != "unknown" else None,
                    pid=pid,
                    args=command,
                )
                if (service and service != "unknown") or pid is not None or command is not None
                else None
            ),
            http=http_info,
            url=EcsUrlInfo(original=fields["url_original"]) if "url_original" in fields else None,
            user_agent=(
                EcsUserAgentInfo(original=fields["user_agent_original"])
                if fields.get("user_agent_original") is not None
                else None
            ),
            related=(
                EcsRelatedInfo(ip=related_ip, user=related_user)
                if (related_ip or related_user)
                else None
            ),
            message=fields.get("body_message"),
            asp=AspMetaInfo(
                parse_status=ParseStatus.OK,
                parser=fields.get("parser"),
                auth_method=fields.get("auth_method"),
                sudo_target_user=fields.get("target_user"),
                ts_clamped=ts_clamped or None,
                message_truncated=message_truncated or None,
                failure_reason=fields.get("failure_reason"),
            ),
        )

    @classmethod
    def parse_raw_event(
        cls,
        raw_event: RawLogEvent,
        agent: AgentMetadata,
        event_uid: str,
        ingested_at: Optional[datetime] = None,
        default_timezone: str = "Asia/Ho_Chi_Minh",
        future_tolerance_seconds: int = 300,
    ) -> ECSEvent:
        """Builds metadata dict from RawLogEvent + AgentMetadata and invokes pure parse()."""
        meta = {
            "event_uid": event_uid,
            "collected_at": raw_event.collected_at,
            "received_at": ingested_at or raw_event.collected_at,
            "agent": agent.model_dump(mode="json"),
            "file": raw_event.file.model_dump(mode="json"),
            "message_truncated": raw_event.message_truncated,
            "default_timezone": default_timezone,
            "future_tolerance_seconds": future_tolerance_seconds,
        }
        return cls.parse(raw_event.log_type.value, raw_event.message, meta)


def parse(log_type: str, message: str, meta: Dict[str, Any]) -> ECSEvent:
    """Module-level pure parse() entrypoint delegating to ParserRegistry.parse."""
    return ParserRegistry.parse(log_type, message, meta)
