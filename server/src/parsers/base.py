"""
Base interfaces and registry for log parsing and normalization.
Supports clean plugin-style expansion for new log formats (Apache, Syslog, Dpkg, etc.).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

from server.src.common.schemas import LogEventEnvelope, LogType


class BaseLogParser(ABC):
    """
    Abstract Base Class for all log source parsers.
    Parsers are responsible for extracting structured ECS-compatible fields from raw log lines.
    """

    @property
    @abstractmethod
    def supported_log_type(self) -> LogType:
        """The primary LogType handled by this parser."""
        pass

    @abstractmethod
    def can_handle(self, log_type: str, source_path: str) -> bool:
        """
        Determines if this parser supports the given log type and/or file path.
        Allows fine-grained routing (e.g. matching '/var/log/auth.log' specifically).
        """
        pass

    @abstractmethod
    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """
        Extracts structured attributes from a single verbatim log line.
        Returns None or empty dict if the line is not matching / non-parsable.
        """
        pass

    def enrich_envelope(self, envelope: LogEventEnvelope) -> LogEventEnvelope:
        """
        Enriches an incoming LogEventEnvelope by parsing its raw string
        if its fields dictionary is empty or needs normalization.
        """
        if not envelope.fields:
            extracted = self.parse_line(envelope.raw)
            if extracted:
                envelope.fields = extracted
        return envelope


class ParserRegistry:
    """
    Registry that maintains all active log parsers.
    Allows easy plugin registration via decorator or runtime injection.
    """

    _registry: List[BaseLogParser] = []

    @classmethod
    def register(cls, parser_cls: Type[BaseLogParser]) -> Type[BaseLogParser]:
        """Class decorator or method to register a parser implementation."""
        instance = parser_cls()
        # Avoid duplicate types
        if not any(isinstance(p, parser_cls) for p in cls._registry):
            cls._registry.append(instance)
        return parser_cls

    @classmethod
    def register_instance(cls, parser: BaseLogParser) -> None:
        """Register an existing parser instance."""
        if parser not in cls._registry:
            cls._registry.append(parser)

    @classmethod
    def clear(cls) -> None:
        """Clears all registered parsers (primarily for testing)."""
        cls._registry.clear()

    @classmethod
    def get_parser(cls, log_type: str, source_path: str = "") -> Optional[BaseLogParser]:
        """Finds the first parser capable of handling the specified log_type and path."""
        for parser in cls._registry:
            if parser.can_handle(log_type, source_path):
                return parser
        return None

    @classmethod
    def parse_or_fallback(cls, envelope: LogEventEnvelope) -> LogEventEnvelope:
        """
        Attempts to enrich envelope fields using registered parsers.
        If no parser matches, returns envelope as is.
        """
        parser = cls.get_parser(envelope.log_type.value, envelope.source_file)
        if parser:
            return parser.enrich_envelope(envelope)
        return envelope

