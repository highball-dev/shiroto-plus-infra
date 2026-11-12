from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_TZ_SPEC = re.compile(r"^([A-Za-z]{2,6})([+-])(\d{1,2})(?::?(\d{2}))?$")


def parse_display_tz(spec: str) -> timezone:
    """`JST+9`, `ICT+7`, `UTC+0`, `IST+5:30` -> a fixed-offset timezone.

    A fixed offset keeps the image free of tzdata; Japan and Vietnam have no DST.
    """
    m = _TZ_SPEC.match((spec or "").strip())
    if not m:
        raise ValueError(f"expected NAME+H or NAME-H (e.g. JST+9), got {spec!r}")
    name, sign, hours, minutes = m.group(1).upper(), m.group(2), int(m.group(3)), int(m.group(4) or 0)
    if hours > 14 or minutes > 59:
        raise ValueError(f"offset out of range in {spec!r}")
    delta = timedelta(hours=hours, minutes=minutes)
    return timezone(delta if sign == "+" else -delta, name)


JST = parse_display_tz("JST+9")


@dataclass(frozen=True)
class Window:
    """Half-open [start, end) interval in UTC."""

    start: datetime
    end: datetime

    def iso(self) -> tuple[str, str]:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        return self.start.strftime(fmt), self.end.strftime(fmt)

    @property
    def minutes(self) -> int:
        return int((self.end - self.start).total_seconds() // 60)

    def label(self, tz: timezone = JST) -> str:
        ls, le = self.start.astimezone(tz), self.end.astimezone(tz)
        local = f"{ls:%H:%M}–{le:%H:%M} {tz.tzname(None)}"
        if tz.utcoffset(None) == timedelta(0):
            return local
        return f"{local} ({self.start:%H:%M}–{self.end:%H:%M} UTC)"


def floor_to_minute(t: datetime) -> datetime:
    return t.astimezone(timezone.utc).replace(second=0, microsecond=0)


def compute_window(scheduled_time: datetime, *, lag_minutes: int, window_minutes: int) -> Window:
    """The window ends `lag_minutes` before the tick: Cloudflare analytics lag behind real time."""
    end = floor_to_minute(scheduled_time) - timedelta(minutes=lag_minutes)
    return Window(start=end - timedelta(minutes=window_minutes), end=end)


def floor_to_period(t: datetime, minutes: int) -> datetime:
    t = floor_to_minute(t)
    return t - timedelta(minutes=(t.hour * 60 + t.minute) % minutes)
