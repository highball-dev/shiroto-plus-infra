"""Webhook and callback monitoring.

Provider webhooks (Stripe, RevenueCat, SB Payment, Bunny …) and our own jobs are excluded from
the per-IP traffic rules, and watched here instead:

- `webhook_rejected` needs no setup: someone keeps calling a webhook and the server (or the
  WAF) keeps answering 400/401/403. Either a forged call, or a real provider being refused.
- The `webhook_unknown_*` / `webhook_new_ip` rules compare each caller with a source profile
  (`webhook_sources.json`: the provider's networks, user agents and known IPs). They are off
  until that file exists; build it with `cf_webhook_baseline.py`.

The profile is a monitoring layer only. Networks are shared and user agents can be spoofed;
the real protection is each provider's signature check on the server.
"""
from __future__ import annotations

import json
import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import endpoints
from aggregate import normalize_ip, normalize_path
from allowlist import Allowlist
from severity import CRITICAL, WARNING

logger = logging.getLogger("webhooks")

LINK_PREVIEW_UAS = (
    "slackbot",
    "whatsapp",
    "twitterbot",
    "facebookexternalhit",
    "discordbot",
    "telegrambot",
    "linkedinbot",
    "skypeuripreview",
    "mezondesktop",
    "line-poker",
)
HARMLESS_STATUSES = frozenset({301, 302, 307, 308, 404, 405})
# What the server answers when a webhook check fails (read from the controllers and guards):
# 400 Stripe and MyChips (bad signature), 401 RevenueCat / Bunny / Tally / Lambda keys,
# 403 the cron guard, and Cloudflare itself when the WAF blocks the call.
DENIED_STATUSES = frozenset({400, 401, 403})

REJECTED = "webhook_rejected"
UNKNOWN_PATH = "webhook_unknown_path"
UNKNOWN_ASN = "webhook_unknown_asn"
UNKNOWN_UA = "webhook_unknown_ua"
NEW_IP = "webhook_new_ip"

REJECTED_WARNING = 5
REJECTED_CRITICAL = 30

DEDUPE_TTL = {REJECTED: 3600, UNKNOWN_PATH: 3600, UNKNOWN_ASN: 3600, UNKNOWN_UA: 3600, NEW_IP: 21600}
HISTORY_TTL = 7200


@dataclass(frozen=True)
class Source:
    path: str
    name: str
    asns: frozenset[int]
    user_agents: tuple[str, ...]
    ips: Allowlist | None  # None = any IP (rotating pool)
    strict: bool = False

    def matches_path(self, path: str) -> bool:
        return path == self.path or path.startswith(self.path.rstrip("/") + "/")

    def ua_allowed(self, ua: str) -> bool:
        if not self.user_agents:
            return True
        low = (ua or "").lower()
        return any((p == "" and low == "") or (p and p.lower() in low) for p in self.user_agents)


@dataclass(frozen=True)
class Thresholds:
    burst: int = 20
    streak: int = 3
    hourly: int = 50
    rejected_warning: float = REJECTED_WARNING
    rejected_critical: float = REJECTED_CRITICAL


@dataclass
class Traffic:
    path: str
    ip: str
    asn: int = 0
    asn_name: str = ""
    country: str = ""
    hosts: set[str] = field(default_factory=set)
    user_agents: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    count: int = 0

    @property
    def ok(self) -> int:
        return sum(n for s, n in self.statuses.items() if 200 <= s < 300)

    @property
    def rejected(self) -> int:
        return sum(n for s, n in self.statuses.items() if 400 <= s < 500 and s not in HARMLESS_STATUSES)

    @property
    def denied(self) -> int:
        return sum(n for s, n in self.statuses.items() if s in DENIED_STATUSES)

    @property
    def user_agent(self) -> str:
        return self.user_agents.most_common(1)[0][0] if self.user_agents else ""

    def harmless_preview(self) -> bool:
        """A chat app unfurling a pasted link, answered 404/405."""
        uas = [ua.lower() for ua in self.user_agents]
        return bool(uas) and all(any(p in ua for p in LINK_PREVIEW_UAS) for ua in uas) and set(
            self.statuses
        ) <= HARMLESS_STATUSES


@dataclass(frozen=True)
class WebhookFinding:
    rule_id: str
    severity: str
    traffic: Traffic
    source: Source | None
    reason: str
    history: dict = field(default_factory=dict)
    looks_like: tuple[str, ...] = ()

    @property
    def ip(self) -> str:
        return self.traffic.ip

    @property
    def provider(self) -> str:
        return self.source.name if self.source is not None else endpoints.webhook_name(self.traffic.path)

    @property
    def dedupe_rule(self) -> str:
        return f"{self.rule_id}:{self.traffic.path}"


def load_profiles(path: str) -> list[Source]:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        logger.error("webhook profiles unreadable (%s) — profile rules are off", type(e).__name__)
        return []
    # The file is edited by hand: a wrong shape turns the profile rules off, it does not stop the service.
    try:
        out = []
        for key, spec in raw.items():
            if key.startswith("_") or not isinstance(spec, dict):
                continue
            out.append(
                Source(
                    path=key,
                    name=str(spec.get("name") or key),
                    asns=frozenset(int(str(a).upper().removeprefix("AS")) for a in spec.get("asns", [])),
                    user_agents=tuple(str(u) for u in spec.get("user_agents", [])),
                    ips=_ips(spec),
                    strict=bool(spec.get("strict")),
                )
            )
    except (AttributeError, TypeError, ValueError) as e:
        logger.error("webhook profiles malformed (%s) — profile rules are off", type(e).__name__)
        return []
    out.sort(key=lambda s: -len(s.path))
    return out


def _ips(spec: dict) -> Allowlist | None:
    if spec.get("ips") == "*":
        return None
    learned = spec.get("ips") or []
    official = spec.get("official_ips") or []
    entries = list(dict.fromkeys(normalize_ip(str(i)) for i in [*official, *learned]))
    return Allowlist.parse(entries, source="webhook_sources.json")


def match(profiles: list[Source], path: str) -> Source | None:
    return next((s for s in profiles if s.matches_path(path)), None)


def group(rows: list[dict]) -> dict[tuple[str, str], Traffic]:
    out: dict[tuple[str, str], Traffic] = {}
    for row in rows or ():
        d = row.get("dimensions") or {}
        ip = normalize_ip(d.get("clientIP", ""))
        if not ip:
            continue
        path = normalize_path(d.get("clientRequestPath") or "/")
        t = out.setdefault((path, ip), Traffic(path=path, ip=ip))
        n = int(row.get("count") or 0)
        t.count += n
        t.asn = int(d.get("clientAsn") or 0) or t.asn
        t.asn_name = d.get("clientASNDescription") or t.asn_name
        t.country = d.get("clientCountryName") or t.country
        if d.get("clientRequestHTTPHost"):
            t.hosts.add(d["clientRequestHTTPHost"].lower())
        t.user_agents[d.get("userAgent") or ""] += n
        t.statuses[int(d.get("edgeResponseStatus") or 0)] += n
    return out


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def track_new_ip(store, traffic: Traffic, tick: datetime, period_minutes: int) -> dict:
    """60-minute history of a new IP on a webhook path, so one stray call never alerts."""
    key = f"webhook:newip:{traffic.path}:{traffic.ip}"
    stamp = _iso(tick)
    ticks = [t for t in (store.get(key) or []) if t[0] != stamp]
    ticks.append([stamp, traffic.count])
    cutoff = _iso(tick - timedelta(minutes=60))
    ticks = sorted(t for t in ticks if t[0] > cutoff)
    store.put(key, ticks, HISTORY_TTL)

    seen = {t[0] for t in ticks}
    streak = 0
    cursor = tick
    while _iso(cursor) in seen:
        streak += 1
        cursor -= timedelta(minutes=period_minutes)
    return {
        "window": traffic.count,
        "streak": streak,
        "hourly": sum(t[1] for t in ticks),
        "active_ticks": len(ticks),
    }


def identify(profiles: list[Source], traffic: Traffic) -> tuple[str, ...]:
    """Which known providers this caller resembles."""
    by_ip: list[str] = []
    by_network: list[str] = []
    for s in profiles:
        if s.ips and s.ips.contains(traffic.ip):
            by_ip.append(f"{s.name} (known IP)")
        elif traffic.asn in s.asns and all(s.ua_allowed(ua) for ua in traffic.user_agents):
            by_network.append(f"{s.name} (same network and UA)")
    return tuple(dict.fromkeys(by_ip + by_network))


def _profile_finding(
    traffic: Traffic, profiles: list[Source], *, store, tick: datetime, period_minutes: int, thresholds: Thresholds
) -> WebhookFinding | None:
    source = match(profiles, traffic.path)
    accepted = CRITICAL if traffic.ok else WARNING
    if source is None:
        return WebhookFinding(UNKNOWN_PATH, accepted, traffic, None, "this path has no webhook profile")
    if source.asns and traffic.asn not in source.asns:
        return WebhookFinding(
            UNKNOWN_ASN, accepted, traffic, source, f"AS{traffic.asn} is not a {source.name} network"
        )
    if any(not source.ua_allowed(ua) for ua in traffic.user_agents):
        return WebhookFinding(UNKNOWN_UA, accepted, traffic, source, f"the user agent does not match {source.name}")
    if source.ips is None or source.ips.contains(traffic.ip):
        return None
    history = track_new_ip(store, traffic, tick, period_minutes)
    if source.strict:
        return WebhookFinding(
            NEW_IP, accepted, traffic, source, f"the IP is not in {source.name}'s official IP list", history
        )
    over = (
        history["window"] >= thresholds.burst
        or history["streak"] >= thresholds.streak
        or history["hourly"] >= thresholds.hourly
    )
    if not over:
        return None
    sev = CRITICAL if traffic.rejected * 2 >= traffic.count else WARNING
    return WebhookFinding(NEW_IP, sev, traffic, source, f"a new IP in {source.name}'s network keeps sending", history)


def evaluate(
    rows: list[dict],
    profiles: list[Source],
    *,
    store,
    tick: datetime,
    period_minutes: int,
    thresholds: Thresholds,
    allowlist,
    disabled: frozenset[str] = frozenset(),
) -> list[WebhookFinding]:
    findings: list[WebhookFinding] = []
    for traffic in group(rows).values():
        if allowlist.contains(traffic.ip) or traffic.harmless_preview():
            continue
        finding = None
        if profiles:
            finding = _profile_finding(
                traffic, profiles, store=store, tick=tick, period_minutes=period_minutes, thresholds=thresholds
            )
            if finding is not None and finding.rule_id in disabled:
                finding = None  # fall through: the calls may still be a run of rejections
        rejected = REJECTED not in disabled and traffic.denied >= thresholds.rejected_warning
        flood = rejected and traffic.denied >= thresholds.rejected_critical
        if finding is None and rejected:
            finding = WebhookFinding(
                REJECTED,
                CRITICAL if flood else WARNING,
                traffic,
                match(profiles, traffic.path),
                f"{traffic.denied:,} calls answered 400/401/403 (signature or secret check failed, or the WAF blocked them)",
            )
        elif finding is not None and flood and finding.severity != CRITICAL:
            # A profile mismatch the server refused is a warning, but not when it is a flood of them.
            finding = WebhookFinding(
                finding.rule_id,
                CRITICAL,
                traffic,
                finding.source,
                f"{finding.reason} ({traffic.denied:,} calls answered 400/401/403)",
                finding.history,
            )
        if finding is None:
            continue
        findings.append(finding)
    findings = [
        WebhookFinding(f.rule_id, f.severity, f.traffic, f.source, f.reason, f.history, identify(profiles, f.traffic))
        for f in findings
    ]
    findings.sort(key=lambda f: (f.severity != CRITICAL, -f.traffic.count))
    return findings
