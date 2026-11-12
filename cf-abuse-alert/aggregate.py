"""Turn Cloudflare rows into one `IpStats` per client IP.

Two passes, because the detailed breakdown (A2) is only fetched for a short list of candidates:
1. `collect()` reads every cheap per-IP source (top talkers, signals, security events).
2. `pick_candidates()` ranks IPs by how far they exceed a threshold.
3. `add_details()` fills in paths, statuses, network and user agent for those candidates.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable

import signatures
from cf_graphql import row_bytes, row_count
from endpoints import sensitive_group

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NUMBER = re.compile(r"^\d+$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_TOKEN = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_-]{20,}$")
_EXT = re.compile(r"^(.+)(\.[A-Za-z0-9]{1,5})$")


def _is_id(seg: str) -> bool:
    return bool(_UUID.match(seg) or _NUMBER.match(seg) or _HEX.match(seg) or _TOKEN.match(seg))


def _normalize_segment(seg: str) -> str:
    if not seg:
        return seg
    if _is_id(seg):
        return ":id"
    m = _EXT.match(seg)
    if m and _is_id(m.group(1)):
        return ":id" + m.group(2).lower()
    return seg


def normalize_path(path: str) -> str:
    """`/api/movies/8231/episodes/5f2b…` -> `/api/movies/:id/episodes/:id`."""
    path = (path or "/").split("?", 1)[0]
    return "/".join(_normalize_segment(seg) for seg in path.split("/")) or "/"


@lru_cache(maxsize=256)
def _prefix_regex(prefix: str) -> re.Pattern:
    return re.compile(re.escape(prefix).replace(r"\*", ".*"))


def is_excluded(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(_prefix_regex(p).match(path) if "*" in p else path.startswith(p) for p in prefixes)


def is_media(host: str, path: str, media_hosts: tuple[str, ...], media_prefixes: tuple[str, ...]) -> bool:
    return (host or "").lower() in media_hosts or any(path.startswith(p) for p in media_prefixes)


def normalize_ip(ip: str) -> str:
    return (ip or "").strip().lower()


def _most_common(c: Counter):
    return c.most_common(1)[0][0] if c else None


@dataclass
class IpStats:
    ip: str
    detailed: bool = False  # True once the A2 breakdown is in
    truncated: bool = False
    hosts: set[str] = field(default_factory=set)

    # request breakdown (A2)
    total_requests: int = 0
    api_requests: int = 0
    statuses: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    path_statuses: dict[str, Counter] = field(default_factory=dict)
    path_bytes: Counter = field(default_factory=Counter)
    sensitive_hits: Counter = field(default_factory=Counter)
    not_found_paths: set[str] = field(default_factory=set)
    id_paths: dict[str, set[str]] = field(default_factory=dict)
    countries: Counter = field(default_factory=Counter)
    asns: Counter = field(default_factory=Counter)
    asn_names: dict[int, str] = field(default_factory=dict)
    user_agents: Counter = field(default_factory=Counter)

    # volume
    bytes: int = 0
    media_requests: int = 0
    sustained_requests: int = 0
    sustained_bytes: int = 0

    # exact-endpoint signals (A7, A8)
    signals: Counter = field(default_factory=Counter)
    purchases_1h: int = 0

    # suspicious requests (S2, S3, S4)
    scanner_hits: int = 0
    scanner_kinds: Counter = field(default_factory=Counter)
    scanner_paths: Counter = field(default_factory=Counter)
    tool_hits: int = 0
    tools: Counter = field(default_factory=Counter)
    injection_hits: int = 0
    injection_kinds: Counter = field(default_factory=Counter)
    injection_paths: Counter = field(default_factory=Counter)

    # Cloudflare's own verdict (B)
    cf_events: int = 0
    cf_blocked: int = 0
    cf_rate_limited: int = 0
    cf_actions: Counter = field(default_factory=Counter)
    cf_rules: Counter = field(default_factory=Counter)

    # per-IP totals seen before the detailed breakdown, used to rank candidates
    hint_requests: int = 0
    hint_errors: int = 0
    hint_sensitive: int = 0

    # --- derived ---------------------------------------------------------------------

    def status_class(self, hundreds: int) -> int:
        return sum(n for s, n in self.statuses.items() if s // 100 == hundreds)

    @property
    def status_4xx(self) -> int:
        return self.status_class(4)

    @property
    def error_ratio(self) -> float:
        return self.status_4xx / self.total_requests if self.total_requests else 0.0

    @property
    def denied(self) -> int:
        """401s plus the 403s the origin answered (403s Cloudflare served are `cf_blocked`)."""
        return self.statuses.get(401, 0) + max(0, self.statuses.get(403, 0) - self.cf_blocked)

    @property
    def server_rate_limited(self) -> int:
        """429s from the API's own throttler (429s from Cloudflare are `cf_rate_limited`)."""
        return max(0, self.statuses.get(429, 0) - self.cf_rate_limited)

    @property
    def distinct_not_found(self) -> int:
        return len(self.not_found_paths)

    @property
    def id_sweep(self) -> int:
        return max((len(v) for v in self.id_paths.values()), default=0)

    @property
    def id_sweep_path(self) -> str | None:
        if not self.id_paths:
            return None
        return max(self.id_paths.items(), key=lambda kv: len(kv[1]))[0]

    @property
    def blocked_share(self) -> float:
        """Share of this IP's requests that Cloudflare stopped."""
        base = max(self.total_requests, self.cf_blocked)
        return self.cf_blocked / base if base else 0.0

    def top_paths(self, n: int = 5) -> list[tuple[str, int]]:
        return self.paths.most_common(n)

    def top_paths_by_bytes(self, n: int = 3) -> list[tuple[str, int]]:
        return [(p, b) for p, b in self.path_bytes.most_common(n) if b > 0]

    def path_status(self, path: str) -> int | None:
        return _most_common(self.path_statuses.get(path, Counter()))

    @property
    def country(self) -> str | None:
        return _most_common(self.countries)

    @property
    def asn(self) -> int | None:
        return _most_common(self.asns)

    @property
    def asn_name(self) -> str:
        return self.asn_names.get(self.asn or 0, "")

    @property
    def user_agent(self) -> str | None:
        return _most_common(self.user_agents)


Stats = dict[str, IpStats]


def _per_ip(rows, value) -> Counter:
    out: Counter = Counter()
    for row in rows or ():
        ip = normalize_ip((row.get("dimensions") or {}).get("clientIP", ""))
        if ip:
            out[ip] += value(row)
    return out


def _get(stats: Stats, ip: str) -> IpStats:
    if ip not in stats:
        stats[ip] = IpStats(ip=ip)
    return stats[ip]


def collect(
    *,
    top_rows: list[dict] = (),
    error_rows: list[dict] = (),
    sensitive_rows: list[dict] = (),
    bytes_rows: list[dict] = (),
    media_rows: list[dict] = (),
    sustained_rows: list[dict] = (),
    signal_counts: dict[str, Counter] | None = None,
    purchases_1h: dict[str, int] | None = None,
    scanner_rows: list[dict] = (),
    tool_rows: list[dict] = (),
    injection_rows: list[dict] = (),
    events: list[dict] = (),
    excluded_prefixes: tuple[str, ...] = (),
    block_actions: frozenset[str] = frozenset(),
    rate_limit_sources: frozenset[str] = frozenset(),
) -> Stats:
    """First pass: everything known about an IP without the per-path breakdown."""
    stats: Stats = {}

    for ip, n in _per_ip(top_rows, row_count).items():
        _get(stats, ip).hint_requests = n
    for ip, n in _per_ip(error_rows, row_count).items():
        _get(stats, ip).hint_errors = n
    for ip, n in _per_ip(sensitive_rows, row_count).items():
        _get(stats, ip).hint_sensitive = n
    for ip, b in _per_ip(bytes_rows, row_bytes).items():
        _get(stats, ip).bytes = b
    for ip, n in _per_ip(media_rows, row_count).items():
        _get(stats, ip).media_requests = n
    sustained_b = _per_ip(sustained_rows, row_bytes)
    for ip, n in _per_ip(sustained_rows, row_count).items():
        s = _get(stats, ip)
        s.sustained_requests, s.sustained_bytes = n, sustained_b[ip]

    for ip, counts in (signal_counts or {}).items():
        _get(stats, ip).signals.update(counts)
    for ip, n in (purchases_1h or {}).items():
        if n:
            _get(stats, ip).purchases_1h = n

    for row in scanner_rows or ():
        d = row.get("dimensions") or {}
        ip = normalize_ip(d.get("clientIP", ""))
        path = d.get("clientRequestPath") or "/"
        kind = signatures.scanner_kind(path)
        if not ip or not kind:
            continue
        n = row_count(row)
        s = _get(stats, ip)
        s.scanner_hits += n
        s.scanner_kinds[kind] += n
        s.scanner_paths[signatures.safe_path(path)] += n

    for row in tool_rows or ():
        d = row.get("dimensions") or {}
        ip = normalize_ip(d.get("clientIP", ""))
        tool = signatures.attack_tool(d.get("userAgent") or "")
        if not ip or not tool:
            continue
        n = row_count(row)
        s = _get(stats, ip)
        s.tool_hits += n
        s.tools[tool] += n
        s.user_agents[d["userAgent"]] += 0  # keeps the UA for display if A2 has none

    for row in injection_rows or ():
        d = row.get("dimensions") or {}
        ip = normalize_ip(d.get("clientIP", ""))
        path = d.get("clientRequestPath") or "/"
        if not ip or is_excluded(path, excluded_prefixes):
            continue
        kind = signatures.injection_kind(path, d.get("clientRequestQuery") or "")
        if not kind:
            continue
        n = row_count(row)
        s = _get(stats, ip)
        s.injection_hits += n
        s.injection_kinds[kind] += n
        s.injection_paths[normalize_path(signatures.safe_path(path))] += n

    for ev in events or ():
        action = (ev.get("action") or "").lower()
        ip = normalize_ip(ev.get("clientIP", ""))
        path = ev.get("clientRequestPath") or "/"
        if action == "skip" or not ip or is_excluded(path, excluded_prefixes):
            continue
        s = _get(stats, ip)
        s.cf_events += 1
        if ev.get("clientRequestHTTPHost"):
            s.hosts.add(ev["clientRequestHTTPHost"].lower())
        if action in block_actions:
            s.cf_blocked += 1
        source = ev.get("source") or "unknown"
        if source.lower() in rate_limit_sources:
            s.cf_rate_limited += 1
        s.cf_actions[action or "unknown"] += 1
        rule = (ev.get("description") or "").strip() or ev.get("ruleId") or ""
        s.cf_rules[f"{rule} ({source})" if rule else source] += 1
        # Fallbacks, replaced by the A2 breakdown when the IP becomes a candidate.
        if ev.get("clientCountryName"):
            s.countries[ev["clientCountryName"]] += 0
        if ev.get("clientAsn"):
            s.asns[int(ev["clientAsn"])] += 0
        if ev.get("userAgent"):
            s.user_agents[ev["userAgent"]] += 0

    return stats


@dataclass(frozen=True)
class CandidateThresholds:
    requests: float
    errors: float
    sensitive: float
    events: float
    # What `requests` is ranked against (0 = the same value). See rules.candidate_volume_threshold.
    volume: float = 0.0
    bytes: float = float("inf")
    media: float = float("inf")
    sustained: float = float("inf")


def pick_candidates(
    stats: Stats,
    thresholds: CandidateThresholds,
    *,
    allowlist,
    limit: int,
    early_score: Callable[[IpStats], float] = lambda s: 0.0,
) -> list[str]:
    """IPs worth a detailed look, the ones furthest above a threshold first.

    Ranking by excess rather than by request count keeps a low-volume scanner or card tester
    from being pushed out by ordinary heavy users.
    """
    scored: dict[str, float] = {}
    for ip, s in stats.items():
        if allowlist.contains(ip):
            continue
        score = early_score(s)
        # Any IP Cloudflare acted on is a candidate, however few events it has.
        if s.cf_events:
            score = max(score, s.cf_events / thresholds.events)
        # Enough requests makes an IP eligible, but it only outranks a real signal by volume.
        if s.hint_requests >= thresholds.requests:
            score = max(score, s.hint_requests / (thresholds.volume or thresholds.requests))
        for value, threshold in (
            (s.hint_errors, thresholds.errors),
            (s.hint_sensitive, thresholds.sensitive),
            (s.bytes, thresholds.bytes),
            (s.media_requests, thresholds.media),
            (s.sustained_requests, thresholds.sustained),
        ):
            if value >= threshold:
                score = max(score, value / threshold)
        if score > 0:
            scored[ip] = score
    return sorted(scored, key=lambda ip: (-scored[ip], ip))[:limit]


def add_details(
    stats: Stats,
    detail_rows: list[dict],
    *,
    excluded_prefixes: tuple[str, ...],
    api_prefixes: tuple[str, ...] = ("/api/",),
    media_hosts: tuple[str, ...] = (),
    media_prefixes: tuple[str, ...] = (),
    sensitive_methods: frozenset[str] | None = None,
    truncated: bool = False,
) -> Stats:
    """Second pass: the per-path breakdown of the candidate IPs."""
    media_seen: Counter = Counter()
    bytes_seen: Counter = Counter()

    for row in detail_rows or ():
        d = row.get("dimensions") or {}
        ip = normalize_ip(d.get("clientIP", ""))
        path = d.get("clientRequestPath") or "/"
        if not ip or is_excluded(path, excluded_prefixes):
            continue
        n, b = row_count(row), row_bytes(row)
        host = (d.get("clientRequestHTTPHost") or "").lower()
        s = _get(stats, ip)
        if not s.detailed:
            # Network and client fallbacks from security events give way to real traffic.
            s.detailed = True
            s.countries.clear()
            s.asns.clear()
            s.user_agents.clear()
        s.truncated = truncated
        if host:
            s.hosts.add(host)
        s.total_requests += n
        bytes_seen[ip] += b
        if any(path == p.rstrip("/") or path.startswith(p) for p in api_prefixes):
            s.api_requests += n
        if is_media(host, path, media_hosts, media_prefixes):
            media_seen[ip] += n
        status = int(d.get("edgeResponseStatus") or 0)
        s.statuses[status] += n
        method = (d.get("clientRequestHTTPMethodName") or "").upper()
        if method:
            s.methods[method] += n
        group = sensitive_group(path)
        if group and (not sensitive_methods or not method or method in sensitive_methods):
            s.sensitive_hits[group] += n
        norm = normalize_path(path)
        s.paths[norm] += n
        s.path_statuses.setdefault(norm, Counter())[status] += n
        s.path_bytes[norm] += b
        if status == 404:
            s.not_found_paths.add(path)
        if ":id" in norm:
            s.id_paths.setdefault(norm, set()).add(path)
        if d.get("clientCountryName"):
            s.countries[d["clientCountryName"]] += n
        if d.get("clientAsn"):
            asn = int(d["clientAsn"])
            s.asns[asn] += n
            if d.get("clientASNDescription"):
                s.asn_names[asn] = d["clientASNDescription"]
        if d.get("userAgent"):
            s.user_agents[d["userAgent"]] += n

    # A crawler with thousands of distinct paths can be cut off by the A2 row limit, so bytes
    # and media counts keep the larger of the two sources.
    for ip, b in bytes_seen.items():
        stats[ip].bytes = max(stats[ip].bytes, b)
    for ip, n in media_seen.items():
        stats[ip].media_requests = max(stats[ip].media_requests, n)
    return stats
