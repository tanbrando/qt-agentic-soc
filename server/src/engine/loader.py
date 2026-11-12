"""
YAML Rule Schema Validator & Loader (Sections 9.0, 9.1, 9.2, 9.3).
Validates rule YAML files with Pydantic v2; invalid rules are logged and skipped
without crashing the engine or blocking valid rules.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from server.src.common.config import parse_duration_seconds
from server.src.common.schemas import AlertLevel

logger = logging.getLogger(__name__)


class SequenceStepSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selection: Dict[str, Any] = Field(..., min_length=1)
    min_count: int = Field(default=1, ge=1)


class RuleDetectionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["match", "event_count", "value_count", "sequence"]
    group_by: List[str] = Field(default_factory=list)
    timespan: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    steps: Optional[List[SequenceStepSpec]] = None

    @model_validator(mode="after")
    def _validate_by_type(self) -> RuleDetectionSpec:
        if self.type == "match":
            return self

        if not self.group_by:
            raise ValueError(f"detection.group_by is required for rule type {self.type!r}")
        if not self.timespan:
            raise ValueError(f"detection.timespan is required for rule type {self.type!r}")
        parse_duration_seconds(self.timespan)

        if self.type == "event_count":
            if not self.condition or "gte" not in self.condition or int(self.condition["gte"]) < 1:
                raise ValueError("event_count requires condition.gte >= 1")
        elif self.type == "value_count":
            if (
                not self.condition
                or not self.condition.get("field")
                or "gte" not in self.condition
                or int(self.condition["gte"]) < 1
            ):
                raise ValueError("value_count requires condition.field and condition.gte >= 1")
        elif self.type == "sequence":
            if not self.steps or len(self.steps) < 2:
                raise ValueError("sequence requires at least 2 steps")
        return self


class RuleYamlSpec(BaseModel):
    """Pydantic v2 contract for YAML detection rules (Section 9.1)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    level: AlertLevel
    tags: List[str] = Field(default_factory=list)
    cooldown: Optional[str] = None
    selection: Dict[str, Any] = Field(default_factory=dict)
    detection: RuleDetectionSpec

    @model_validator(mode="after")
    def _validate_rule_semantics(self) -> RuleYamlSpec:
        if self.cooldown is not None:
            parse_duration_seconds(self.cooldown)
        if self.detection.type in ("match", "event_count", "value_count") and not self.selection:
            raise ValueError(f"selection is required for rule type {self.detection.type!r}")
        return self

    @property
    def cooldown_seconds(self) -> int:
        if not self.cooldown or self.detection.type == "match":
            return 0
        return parse_duration_seconds(self.cooldown)

    @property
    def timespan_seconds(self) -> int:
        if not self.detection.timespan:
            return 0
        return parse_duration_seconds(self.detection.timespan)


def load_rule_spec_from_file(yaml_path: Path) -> RuleYamlSpec:
    """Loads and validates a single YAML rule file."""
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Rule file {yaml_path.name} must contain a YAML mapping")
    return RuleYamlSpec.model_validate(data)


def load_rule_specs_from_dir(rules_dir: Path) -> List[RuleYamlSpec]:
    """
    Loads all *.yaml / *.yml rule files from `rules_dir`.
    Invalid files are logged clearly and skipped without crashing the engine.
    """
    if not rules_dir.exists():
        logger.warning("Rules directory does not exist: %s", rules_dir)
        return []

    specs: List[RuleYamlSpec] = []
    files = sorted(
        p for p in rules_dir.iterdir() if p.is_file() and p.suffix in (".yaml", ".yml")
    )
    for path in files:
        try:
            spec = load_rule_spec_from_file(path)
            specs.append(spec)
        except (yaml.YAMLError, ValidationError, ValueError, OSError) as exc:
            logger.error("Skipping invalid rule file %s: %s", path.name, exc)
    return specs

