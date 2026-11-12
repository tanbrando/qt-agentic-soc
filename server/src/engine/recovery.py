"""
Startup sliding-window & cooldown state recovery from Postgres/repositories (Section 9.0 & 9.5).
Replays recent events into ISlidingWindowStore in replay_only=True mode and restores active cooldowns.
"""

from __future__ import annotations

import logging
from datetime import timedelta, timezone
from typing import Tuple

from server.src.engine.base import RuleEngine
from server.src.engine.state_store import ISlidingWindowStore
from server.src.repositories.base import IAlertRepository, ILogRepository

logger = logging.getLogger(__name__)


def reload_engine_state(
    rule_engine: RuleEngine,
    state_store: ISlidingWindowStore,
    log_repo: ILogRepository,
    alert_repo: IAlertRepository,
    allowed_lateness_seconds: int = 60,
) -> Tuple[int, int]:
    """
    Rehydrates in-memory sliding windows and cooldown buckets after server startup.
    Returns (replayed_event_count, restored_cooldown_count).
    """
    max_ts = log_repo.get_max_event_ts()
    if max_ts is None:
        return 0, 0
    if max_ts.tzinfo is None:
        max_ts = max_ts.replace(tzinfo=timezone.utc)
    else:
        max_ts = max_ts.astimezone(timezone.utc)

    max_timespan = max((getattr(r, "timespan_seconds", 0) for r in rule_engine.rules), default=0)
    event_cutoff = max_ts - timedelta(seconds=max_timespan + max(0, allowed_lateness_seconds))
    events = log_repo.find_events_since(event_cutoff)

    for ev in events:
        rule_engine.evaluate_event(ev, replay_only=True)

    max_cooldown = max((getattr(r, "cooldown_seconds", 0) for r in rule_engine.rules), default=0)
    restored_cooldowns = 0
    if max_cooldown > 0:
        alert_cutoff = max_ts - timedelta(seconds=max_cooldown)
        recent_alerts = alert_repo.list_alerts_since(alert_cutoff)
        rules_by_id = {r.rule_id: r for r in rule_engine.rules}

        for al in recent_alerts:
            rule = rules_by_id.get(al.rule_id)
            cd_sec = getattr(rule, "cooldown_seconds", 0) if rule is not None else 0
            if cd_sec <= 0:
                continue

            prefix = f"{al.rule_id}:"
            if al.alert_key.startswith(prefix):
                rest = al.alert_key[len(prefix) :]
                if ":" in rest:
                    group_str, slot_str = rest.rsplit(":", 1)
                    if slot_str.isdigit():
                        state_store.record_cooldown_slot(f"cd:{al.rule_id}:{group_str}", int(slot_str))
                        restored_cooldowns += 1
                        continue

            group_by = getattr(rule, "group_by", [])
            if group_by:
                parts = [str(al.group_key.get(f, "")) for f in group_by]
                if all(parts):
                    group_str = "|".join(parts)
                    ref_ts = al.window_end or al.created_at
                    state_store.record_cooldown(f"cd:{al.rule_id}:{group_str}", ref_ts, cd_sec)
                    restored_cooldowns += 1

    logger.info(
        "Engine state recovery finished: replayed_events=%d restored_cooldowns=%d max_ts=%s",
        len(events),
        restored_cooldowns,
        max_ts.isoformat(),
    )
    return len(events), restored_cooldowns

