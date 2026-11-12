from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from severity import CRITICAL, SEVERITY_RANK

logger = logging.getLogger("state")

FAILURE_ALERT_AFTER = 3
FAILURE_ALERT_TTL = 3600
DEGRADED_ALERT_TTL = 21600
HEARTBEAT_TTL = 172800


class Store:
    """Key/value store with TTLs. In memory, optionally mirrored to a JSON file (STATE_FILE)."""

    def __init__(self, path: str = "", clock: Callable[[], float] = time.time) -> None:
        self._path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._data: dict[str, list[Any]] = {}
        # Why the last write to STATE_FILE failed ("" = it worked, or there is no file).
        self.write_error = ""
        if path:
            self._load()

    def get(self, key: str) -> Any:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            if item[1] is not None and item[1] <= self._clock():
                del self._data[key]
                return None
            return item[0]

    def put(self, key: str, value: Any, ttl: int | None = None) -> None:
        with self._lock:
            self._data[key] = [value, self._clock() + ttl if ttl else None]
            self._save()

    def delete(self, key: str) -> None:
        with self._lock:
            if self._data.pop(key, None) is not None:
                self._save()

    def incr(self, key: str, by: int = 1) -> int:
        val = int(self.get(key) or 0) + by
        self.put(key, val)
        return val

    def expires_at(self, key: str) -> float | None:
        with self._lock:
            item = self._data.get(key)
            return item[1] if item else None

    def __len__(self) -> int:
        return len(self._data)

    def _load(self) -> None:
        try:
            with open(self._path, encoding="utf-8") as f:
                raw = json.load(f)
            now = self._clock()
            self._data = {
                k: v
                for k, v in raw.items()
                if isinstance(v, list) and len(v) == 2 and (v[1] is None or v[1] > now)
            }
            logger.info("state: loaded %d keys from STATE_FILE", len(self._data))
        except FileNotFoundError:
            pass
        except (OSError, ValueError, AttributeError) as e:
            logger.warning("state: ignoring unreadable STATE_FILE (%s)", type(e).__name__)

    def _save(self) -> None:
        now = self._clock()
        self._data = {k: v for k, v in self._data.items() if v[1] is None or v[1] > now}
        if not self._path:
            return
        directory = os.path.dirname(os.path.abspath(self._path))
        try:
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f)
            os.replace(tmp, self._path)
            self.write_error = ""
        except OSError as e:
            if not self.write_error:  # once, not on every write of every tick
                logger.warning("state: could not write STATE_FILE (%s) — state is kept in memory only", type(e).__name__)
            self.write_error = type(e).__name__


# --- alert dedupe -----------------------------------------------------------------


def dedupe_key(ip: str, rule_id: str) -> str:
    return f"dedupe:{ip.lower()}:{rule_id}"


def should_alert(store: Store, ip: str, rule_id: str, severity: str) -> bool:
    """True for a new (ip, rule), or when it escalated above the severity already alerted."""
    prev = store.get(dedupe_key(ip, rule_id))
    if prev is None:
        return True
    return SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(prev, 0)


def mark_alerted(store: Store, ip: str, rule_id: str, severity: str, ttl: int) -> None:
    key = dedupe_key(ip, rule_id)
    if store.get(key) == CRITICAL:
        severity = CRITICAL
    store.put(key, severity, ttl)


# --- first seen: lets an alert say "still going, first flagged 40 min ago" ---------


def first_seen(store: Store, ip: str, now: datetime, ttl: int) -> str:
    """Timestamp of the first alert for this IP in the current episode (sliding TTL)."""
    key = f"firstseen:{ip.lower()}"
    stamp = store.get(key) or iso(now)
    store.put(key, stamp, ttl)
    return stamp


def peek_first_seen(store: Store, ip: str) -> str | None:
    return store.get(f"firstseen:{ip.lower()}")


# --- service health ---------------------------------------------------------------


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_success(store: Store, now: datetime) -> bool:
    """Returns True when this success ends an outage that was reported to Slack."""
    failures = int(store.get("health:consecutiveFailures") or 0)
    store.put("health:consecutiveFailures", 0)
    store.put("health:lastSuccess", iso(now))
    # The outage is over: the next one must be reported even if it starts within the hour.
    store.delete("health:lastFailureAlert")
    return failures >= FAILURE_ALERT_AFTER


def record_failure(store: Store) -> int:
    return store.incr("health:consecutiveFailures")


def failure_alert_due(store: Store, failures: int) -> bool:
    return failures >= FAILURE_ALERT_AFTER and store.get("health:lastFailureAlert") is None


def mark_failure_alerted(store: Store, now: datetime) -> None:
    store.put("health:lastFailureAlert", iso(now), FAILURE_ALERT_TTL)


def record_query_health(store: Store, names: list[str], failed: dict[str, str]) -> list[tuple[str, str, int]]:
    """Track optional queries that keep failing while the tick itself succeeds.

    Returns (query, error, consecutive failures) for the ones that should be reported now.
    """
    due: list[tuple[str, str, int]] = []
    for name in names:
        key = f"health:query:{name}"
        if name not in failed:
            if store.get(key):
                store.put(key, 0)
            continue
        streak = store.incr(key)
        if streak >= FAILURE_ALERT_AFTER and store.get(f"health:queryAlert:{name}") is None:
            due.append((name, failed[name], streak))
    return due


def mark_query_alerted(store: Store, name: str, now: datetime) -> None:
    store.put(f"health:queryAlert:{name}", iso(now), DEGRADED_ALERT_TTL)


def skip_heartbeat_after_boot(store: Store, now: datetime, hour_utc: int) -> None:
    """A fresh store that starts after today's heartbeat hour has nothing to report yet.

    Without this, every restart of a memory-only service posts "is watching: 1 runs" on its first tick.
    """
    if heartbeat_due(store, now, hour_utc) and not store.get("stats:runs"):
        store.put(f"health:heartbeat:{now.astimezone(timezone.utc):%Y-%m-%d}", "1", HEARTBEAT_TTL)


# --- bursts already reported: lets a long-window rule ignore traffic a burst rule covered ----


def note_burst(store: Store, ip: str, rule_id: str, count: float, ttl: int) -> None:
    key = f"burst:{ip.lower()}:{rule_id}"
    store.put(key, float(store.get(key) or 0) + count, ttl)


def burst_total(store: Store, ip: str, rule_id: str) -> float:
    return float(store.get(f"burst:{ip.lower()}:{rule_id}") or 0)


def heartbeat_due(store: Store, now: datetime, hour_utc: int) -> bool:
    now = now.astimezone(timezone.utc)
    return now.hour >= hour_utc and store.get(f"health:heartbeat:{now:%Y-%m-%d}") is None


def mark_heartbeat(store: Store, now: datetime) -> None:
    store.put(f"health:heartbeat:{now.astimezone(timezone.utc):%Y-%m-%d}", "1", HEARTBEAT_TTL)
    for key in ("stats:runs", "stats:alerts", "stats:ips", "stats:failedRuns"):
        store.put(key, 0)
