"""
Generic YAML-driven Rule Classes (Sections 9.0, 9.2, 9.3, 9.5).
Implements MatchRule, EventCountRule, ValueCountRule, and SequenceRule.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple

from server.src.common.schemas import Alert, AlertLevel, ECSEvent, LogType
from server.src.engine.base import BaseRule
from server.src.engine.loader import RuleYamlSpec
from server.src.engine.state_store import ISlidingWindowStore, InMemorySlidingWindowStore, WindowEntry

MAX_RULE_REGEX_INPUT_LEN = 4096
MAX_ALERT_EVENT_UIDS = 200


def extract_ecs_field(event: ECSEvent, dotted_path: str) -> Any:
    """
    Fast dotted-path field extractor over ECSEvent attributes and extra fields.
    Supports ECS keys such as 'event.action', 'source.ip', 'http.response.status_code',
    'asp.sudo_target_user', 'process.args', etc.
    """
    cur: Any = event
    for part in dotted_path.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)
    return cur


def _cap_event_uids(uids: List[str], limit: int = MAX_ALERT_EVENT_UIDS) -> List[str]:
    """Bounds stored event_uids to at most 200 (preserving head & tail of window)."""
    if len(uids) <= limit:
        return list(uids)
    half = limit // 2
    return list(uids[:half]) + list(uids[-(limit - half) :])


def _make_alert_key(
    rule_id: str,
    group_val_key: str,
    event_ts: datetime,
    cooldown_seconds: int,
    event_uid: str,
    is_match: bool,
) -> str:
    if is_match or cooldown_seconds <= 0:
        return f"{rule_id}:{event_uid}"
    epoch = int(event_ts.astimezone(timezone.utc).timestamp())
    slot = epoch // cooldown_seconds
    return f"{rule_id}:{group_val_key}:{slot}"


def _build_field_predicate(raw_key: str, expected: Any) -> Callable[[ECSEvent], bool]:
    if "|" in raw_key:
        field_path, op = raw_key.split("|", 1)
    else:
        field_path, op = raw_key, "eq"

    compiled_re: Optional[Pattern[str]] = None
    if op == "re":
        compiled_re = re.compile(str(expected))

    def _matches(event: ECSEvent) -> bool:
        val = extract_ecs_field(event, field_path)

        if op == "exists":
            exists = val is not None and val != ""
            return exists if bool(expected) else not exists

        if val is None:
            return False

        if op == "eq":
            if isinstance(expected, list):
                if isinstance(val, list):
                    return any(item in expected for item in val)
                return val in expected
            if isinstance(val, list):
                return expected in val
            return val == expected

        if op == "contains":
            targets = expected if isinstance(expected, list) else [expected]
            if isinstance(val, list):
                return any(str(t) in str(item) for item in val for t in targets)
            val_s = str(val)
            return any(str(t) in val_s for t in targets)

        if op == "startswith":
            targets = expected if isinstance(expected, list) else [expected]
            val_s = str(val)
            return any(val_s.startswith(str(t)) for t in targets)

        if op == "endswith":
            targets = expected if isinstance(expected, list) else [expected]
            val_s = str(val)
            return any(val_s.endswith(str(t)) for t in targets)

        if op == "re":
            assert compiled_re is not None
            bounded = str(val)[:MAX_RULE_REGEX_INPUT_LEN]
            return compiled_re.search(bounded) is not None

        if op in ("gte", "gt", "lte", "lt"):
            try:
                num_val = float(val)
                num_exp = float(expected)
            except (TypeError, ValueError):
                return False
            if op == "gte":
                return num_val >= num_exp
            if op == "gt":
                return num_val > num_exp
            if op == "lte":
                return num_val <= num_exp
            return num_val < num_exp

        raise ValueError(f"Unsupported selection operator: {op!r}")

    return _matches


def compile_selection(selection: Dict[str, Any]) -> Callable[[ECSEvent], bool]:
    """Compiles a selection mapping into a pure event predicate (AND across keys)."""
    predicates = [_build_field_predicate(k, v) for k, v in selection.items()]
    if not predicates:
        return lambda _ev: True
    return lambda ev: all(pred(ev) for pred in predicates)


class _GenericStatefulRuleBase(BaseRule):
    """Shared group_by and cooldown helpers for YAML-driven stateful rules."""

    supported_log_types: Set[LogType] = set()  # Evaluated against all ECS events via selection

    def __init__(
        self,
        spec: RuleYamlSpec,
        state_store: Optional[ISlidingWindowStore] = None,
        allowed_lateness_seconds: int = 60,
    ) -> None:
        self.spec = spec
        self.rule_id = spec.id
        self.rule_name = spec.title
        self.level: AlertLevel = spec.level
        self.tags: List[str] = list(spec.tags)
        self.cooldown_seconds: int = spec.cooldown_seconds
        self.timespan_seconds: int = spec.timespan_seconds
        self.group_by: List[str] = list(spec.detection.group_by)
        self.state_store = state_store or InMemorySlidingWindowStore()
        self.allowed_lateness_seconds = allowed_lateness_seconds

    def applies_to(self, event: ECSEvent) -> bool:
        return True

    def _extract_group(self, event: ECSEvent) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Extracts group key tuple + dict. Returns None if ANY group_by field is missing (Section 9.0).
        """
        group_dict: Dict[str, Any] = {}
        parts: List[str] = []
        for field_path in self.group_by:
            val = extract_ecs_field(event, field_path)
            if val is None or val == "":
                return None
            group_dict[field_path] = val
            parts.append(str(val))
        if event.host.name and "host.name" not in group_dict:
            group_dict["host.name"] = event.host.name
        return "|".join(parts), group_dict


class MatchRule(BaseRule):
    """Stateless rule firing one alert for each matching event (Section 9.3)."""

    supported_log_types: Set[LogType] = set()

    def __init__(self, spec: RuleYamlSpec) -> None:
        self.spec = spec
        self.rule_id = spec.id
        self.rule_name = spec.title
        self.level: AlertLevel = spec.level
        self.tags: List[str] = list(spec.tags)
        self._predicate = compile_selection(spec.selection)

    def applies_to(self, event: ECSEvent) -> bool:
        return True

    def evaluate(self, event: ECSEvent, replay_only: bool = False) -> Optional[Alert]:
        if not self._predicate(event) or replay_only:
            return None

        group_key: Dict[str, Any] = {"host.name": event.host.name}
        if event.source and event.source.ip:
            group_key["source.ip"] = event.source.ip
        if event.user and event.user.name:
            group_key["user.name"] = event.user.name
        if event.process and event.process.args:
            group_key["process.args"] = event.process.args
        if event.event.action:
            group_key["event.action"] = event.event.action
        if event.asp and event.asp.sudo_target_user:
            group_key["asp.sudo_target_user"] = event.asp.sudo_target_user
        failure_reason = getattr(event.asp, "failure_reason", None) if event.asp else None
        if failure_reason:
            group_key["asp.failure_reason"] = failure_reason

        return Alert(
            alert_key=_make_alert_key(
                self.rule_id, "", event.timestamp, 0, event.event.id, is_match=True
            ),
            rule_id=self.rule_id,
            title=self.rule_name,
            level=self.level,
            window_start=event.timestamp,
            window_end=event.timestamp,
            group_key=group_key,
            event_count=1,
            event_uids=[event.event.id],
            tags=list(self.tags),
        )


class EventCountRule(_GenericStatefulRuleBase):
    """Triggers when at least N matching events occur per group within timespan."""

    def __init__(
        self,
        spec: RuleYamlSpec,
        state_store: Optional[ISlidingWindowStore] = None,
        allowed_lateness_seconds: int = 60,
    ) -> None:
        super().__init__(spec, state_store, allowed_lateness_seconds)
        self._predicate = compile_selection(spec.selection)
        assert spec.detection.condition is not None
        self.threshold = int(spec.detection.condition["gte"])

    def evaluate(self, event: ECSEvent, replay_only: bool = False) -> Optional[Alert]:
        if not self._predicate(event):
            return None
        grouped = self._extract_group(event)
        if grouped is None:
            return None
        group_str, group_dict = grouped

        bucket_key = f"{self.rule_id}:{group_str}"
        win = self.state_store.add_entry_and_get_window(
            bucket_key=bucket_key,
            event_id=event.event.id,
            timestamp=event.timestamp,
            window_seconds=self.timespan_seconds,
            allowed_lateness_seconds=self.allowed_lateness_seconds,
        )

        if replay_only or win.is_late or len(win.entries) < self.threshold:
            return None

        cd_key = f"cd:{self.rule_id}:{group_str}"
        if self.state_store.is_in_cooldown(cd_key, event.timestamp, self.cooldown_seconds):
            return None
        self.state_store.record_cooldown(cd_key, event.timestamp, self.cooldown_seconds)

        uids = [e.event_id for e in win.entries]
        return Alert(
            alert_key=_make_alert_key(
                self.rule_id,
                group_str,
                event.timestamp,
                self.cooldown_seconds,
                event.event.id,
                is_match=False,
            ),
            rule_id=self.rule_id,
            title=self.rule_name,
            level=self.level,
            window_start=win.entries[0].timestamp,
            window_end=win.entries[-1].timestamp,
            group_key=group_dict,
            event_count=len(uids),
            event_uids=_cap_event_uids(uids),
            tags=list(self.tags),
        )


class ValueCountRule(_GenericStatefulRuleBase):
    """Triggers when at least N distinct values of `condition.field` occur per group within timespan."""

    def __init__(
        self,
        spec: RuleYamlSpec,
        state_store: Optional[ISlidingWindowStore] = None,
        allowed_lateness_seconds: int = 60,
    ) -> None:
        super().__init__(spec, state_store, allowed_lateness_seconds)
        self._predicate = compile_selection(spec.selection)
        assert spec.detection.condition is not None
        self.target_field = str(spec.detection.condition["field"])
        self.threshold = int(spec.detection.condition["gte"])

    def evaluate(self, event: ECSEvent, replay_only: bool = False) -> Optional[Alert]:
        if not self._predicate(event):
            return None
        grouped = self._extract_group(event)
        if grouped is None:
            return None
        target_val = extract_ecs_field(event, self.target_field)
        if target_val is None or target_val == "":
            return None
        group_str, group_dict = grouped

        bucket_key = f"{self.rule_id}:{group_str}"
        win = self.state_store.add_entry_and_get_window(
            bucket_key=bucket_key,
            event_id=event.event.id,
            timestamp=event.timestamp,
            window_seconds=self.timespan_seconds,
            value=str(target_val),
            allowed_lateness_seconds=self.allowed_lateness_seconds,
        )

        distinct_vals = {e.value for e in win.entries if e.value is not None}
        if replay_only or win.is_late or len(distinct_vals) < self.threshold:
            return None

        cd_key = f"cd:{self.rule_id}:{group_str}"
        if self.state_store.is_in_cooldown(cd_key, event.timestamp, self.cooldown_seconds):
            return None
        self.state_store.record_cooldown(cd_key, event.timestamp, self.cooldown_seconds)

        uids = [e.event_id for e in win.entries]
        return Alert(
            alert_key=_make_alert_key(
                self.rule_id,
                group_str,
                event.timestamp,
                self.cooldown_seconds,
                event.event.id,
                is_match=False,
            ),
            rule_id=self.rule_id,
            title=self.rule_name,
            level=self.level,
            window_start=win.entries[0].timestamp,
            window_end=win.entries[-1].timestamp,
            group_key={**group_dict, "distinct_count": len(distinct_vals)},
            event_count=len(uids),
            event_uids=_cap_event_uids(uids),
            tags=list(self.tags),
        )


class SequenceRule(_GenericStatefulRuleBase):
    """
    Ordered multi-step sequence rule (Section 9.3):
    Step 1 completes at the ts of its min_count-th matching event;
    each subsequent step requires min_count events with ts >= previous step completion ts;
    entire chain from first event of step 1 to last event of final step must fit within timespan.
    """

    def __init__(
        self,
        spec: RuleYamlSpec,
        state_store: Optional[ISlidingWindowStore] = None,
        allowed_lateness_seconds: int = 60,
    ) -> None:
        super().__init__(spec, state_store, allowed_lateness_seconds)
        assert spec.detection.steps is not None and len(spec.detection.steps) >= 2
        self._steps = [
            (compile_selection(st.selection), st.min_count) for st in spec.detection.steps
        ]

    def _bucket_for_step(self, group_str: str, step_idx: int) -> str:
        return f"{self.rule_id}:{group_str}:step{step_idx}"

    def _find_matching_chain(
        self,
        step_entries: List[List[WindowEntry]],
    ) -> Optional[Tuple[datetime, datetime, List[str]]]:
        span = timedelta(seconds=self.timespan_seconds)
        min0 = self._steps[0][1]
        s0 = step_entries[0]
        if len(s0) < min0:
            return None

        for i in range(len(s0) - min0 + 1):
            t_chain_start = s0[i].timestamp
            t_max_end = t_chain_start + span
            t_cursor = s0[i + min0 - 1].timestamp
            collected_uids = [e.event_id for e in s0[i : i + min0]]
            matched_all = True

            for step_idx in range(1, len(step_entries)):
                min_k = self._steps[step_idx][1]
                candidates = [
                    e
                    for e in step_entries[step_idx]
                    if t_cursor <= e.timestamp <= t_max_end
                ]
                if len(candidates) < min_k:
                    matched_all = False
                    break
                chosen = candidates[:min_k]
                collected_uids.extend(e.event_id for e in chosen)
                t_cursor = chosen[-1].timestamp

            if matched_all:
                return t_chain_start, t_cursor, collected_uids

        return None

    def evaluate(self, event: ECSEvent, replay_only: bool = False) -> Optional[Alert]:
        matched_step_indices = [
            idx for idx, (pred, _) in enumerate(self._steps) if pred(event)
        ]
        if not matched_step_indices:
            return None

        grouped = self._extract_group(event)
        if grouped is None:
            return None
        group_str, group_dict = grouped

        any_late = False
        for step_idx in matched_step_indices:
            res = self.state_store.add_entry_and_get_window(
                bucket_key=self._bucket_for_step(group_str, step_idx),
                event_id=event.event.id,
                timestamp=event.timestamp,
                window_seconds=self.timespan_seconds,
                allowed_lateness_seconds=self.allowed_lateness_seconds,
            )
            if res.is_late:
                any_late = True

        if replay_only or any_late:
            return None

        step_entries = [
            self.state_store.get_window_entries(
                self._bucket_for_step(group_str, idx),
                event.timestamp,
                self.timespan_seconds,
            )
            for idx in range(len(self._steps))
        ]
        chain = self._find_matching_chain(step_entries)
        if chain is None:
            return None

        cd_key = f"cd:{self.rule_id}:{group_str}"
        if self.state_store.is_in_cooldown(cd_key, event.timestamp, self.cooldown_seconds):
            return None
        self.state_store.record_cooldown(cd_key, event.timestamp, self.cooldown_seconds)

        win_start, win_end, uids = chain
        return Alert(
            alert_key=_make_alert_key(
                self.rule_id,
                group_str,
                event.timestamp,
                self.cooldown_seconds,
                event.event.id,
                is_match=False,
            ),
            rule_id=self.rule_id,
            title=self.rule_name,
            level=self.level,
            window_start=win_start,
            window_end=win_end,
            group_key=group_dict,
            event_count=len(uids),
            event_uids=_cap_event_uids(uids),
            tags=list(self.tags),
        )


def build_rule_from_spec(
    spec: RuleYamlSpec,
    state_store: Optional[ISlidingWindowStore] = None,
    allowed_lateness_seconds: int = 60,
) -> BaseRule:
    """Factory creating one of the 4 generic BaseRule implementations from a YAML spec."""
    rule_type = spec.detection.type
    if rule_type == "match":
        return MatchRule(spec)
    if rule_type == "event_count":
        return EventCountRule(spec, state_store=state_store, allowed_lateness_seconds=allowed_lateness_seconds)
    if rule_type == "value_count":
        return ValueCountRule(spec, state_store=state_store, allowed_lateness_seconds=allowed_lateness_seconds)
    if rule_type == "sequence":
        return SequenceRule(spec, state_store=state_store, allowed_lateness_seconds=allowed_lateness_seconds)
    raise ValueError(f"Unsupported rule detection type: {rule_type!r}")
