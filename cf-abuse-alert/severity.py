from __future__ import annotations

WARNING = "WARNING"
CRITICAL = "CRITICAL"
SEVERITY_RANK = {WARNING: 1, CRITICAL: 2}


def highest(severities) -> str:
    return CRITICAL if any(s == CRITICAL for s in severities) else WARNING
