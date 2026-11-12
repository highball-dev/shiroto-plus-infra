"""Rules: what is measured per IP, the thresholds, and what the alert says about it.

Thresholds are per IP per window (5 minutes unless `long_window`), before THRESHOLD_MULTIPLIER.
They are starting values. Retune them from the production baseline (README, "Tuning").

The order of RULES matters: the first rule that fired for an IP gives the alert its headline,
so specific attack signatures come before generic volume rules.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import endpoints
from severity import CRITICAL, SEVERITY_RANK, WARNING, highest

GIB = 1024**3

# The three classes of activity SD-1178 asks for.
REQUEST = "Suspicious requests"
USER = "Abnormal user behaviour"
INFRA = "Scanning / infrastructure"


def _top(counter, n: int = 3) -> str:
    return ", ".join(f"{k} ×{v:,}" for k, v in counter.most_common(n))


@dataclass(frozen=True)
class Rule:
    id: str
    title: str  # headline of the alert
    meaning: str  # one line: what this usually is
    metric: Callable[["object"], float]
    warning: float
    critical: float
    category: str
    noun: str = "requests"  # what the number counts
    advice: str = ""  # what to do, shown when this rule is the headline
    min_requests: int = 0
    ratio: bool = False
    unit: str = ""
    dedupe_ttl: int | None = None
    long_window: bool = False
    volume: bool = False  # expected from our own infrastructure: skipped for TRUSTED_ASNS
    early: bool = False  # measurable before the A2 breakdown: can make an IP a candidate
    detail: Callable[["object"], str] | None = None  # extra evidence line

    def thresholds(self, multiplier: float) -> tuple[float, float, int]:
        """(warning, critical, min_requests). A ratio cannot be scaled, so its sample size is."""
        if self.ratio:
            return self.warning, self.critical, round(self.min_requests * multiplier)
        return self.warning * multiplier, self.critical * multiplier, self.min_requests


BLOCK_ADVICE = (
    "Block this IP with a WAF custom rule scoped to the host (expression below). "
    "Do not use Managed Challenge on the API host: the app and webhooks cannot solve it."
)

RULES: tuple[Rule, ...] = (
    # ---- Suspicious requests: attack signatures --------------------------------------
    Rule(
        "injection_attempts",
        "Injection attempts",
        "SQLi / XSS / traversal / template payloads in the URL",
        lambda s: s.injection_hits,
        5,
        30,
        REQUEST,
        noun="requests with a payload",
        advice="Check the response codes above: any 2xx/5xx on a payload request needs a look at the server logs for that route. " + BLOCK_ADVICE,
        early=True,
        detail=lambda s: _top(s.injection_kinds),
    ),
    Rule(
        "scanner_paths",
        "Vulnerability scan",
        "Requests for files this stack never serves (/.env, /.git, wp-login.php …)",
        lambda s: s.scanner_hits,
        15,
        60,
        REQUEST,
        noun="probe requests",
        advice="Confirm in the top paths that no probe path answered 200. " + BLOCK_ADVICE,
        early=True,
        detail=lambda s: _top(s.scanner_kinds),
    ),
    Rule(
        "attack_tool",
        "Attack tool detected",
        "The User-Agent names a scanner or exploitation tool",
        lambda s: s.tool_hits,
        10,
        100,
        REQUEST,
        noun="requests from the tool",
        advice="Someone is running a security tool against us. If it is not a planned pentest: " + BLOCK_ADVICE,
        early=True,
        detail=lambda s: _top(s.tools),
    ),
    Rule(
        "restricted_denied",
        "Admin area probing",
        "401/403 on /api/admin, /api/test-support or MCP client management",
        lambda s: s.signals.get(endpoints.RESTRICTED_DENIED, 0),
        10,
        40,
        REQUEST,
        noun="denied requests",
        advice="If this is a team member, check their Cloudflare Access / role. Otherwise: " + BLOCK_ADVICE,
        early=True,
    ),
    Rule(
        "not_found_sweep",
        "Path enumeration",
        "Many different paths that do not exist (directory brute force)",
        lambda s: s.distinct_not_found,
        40,
        150,
        REQUEST,
        noun="distinct 404 paths",
        advice="Likely a wordlist scan. " + BLOCK_ADVICE,
    ),
    Rule(
        "id_enumeration",
        "ID enumeration",
        "Walking through IDs on one endpoint (scraping or IDOR sweep)",
        lambda s: s.id_sweep,
        150,
        500,
        INFRA,
        noun="distinct IDs on one endpoint",
        advice="Check whether the endpoint returned other users' data (IDOR) or only public content (scraping).",
        volume=True,
        detail=lambda s: f"on `{s.id_sweep_path}`" if s.id_sweep_path else "",
    ),
    Rule(
        "denied_requests",
        "Access-denied burst",
        "401s and origin 403s: guessing tokens or reaching for other users' data",
        lambda s: s.denied,
        60,
        200,
        REQUEST,
        noun="denied requests",
        advice="Look at which routes were denied. A logged-out client retrying is noisy but harmless; many different routes is probing.",
    ),
    Rule(
        "high_4xx_ratio",
        "Mostly failing requests",
        "Most of this IP's requests are 4xx",
        lambda s: s.error_ratio,
        0.5,
        0.8,
        REQUEST,
        noun="of requests are 4xx",
        advice="Check the top paths: one broken client retrying looks different from a scan across many paths.",
        min_requests=100,
        ratio=True,
        unit="ratio",
    ),
    # ---- Abnormal user behaviour ------------------------------------------------------
    Rule(
        "auth_abuse",
        "Login / token abuse",
        "Burst of calls to /api/auth and the OAuth token endpoints",
        lambda s: s.sensitive_hits.get("auth", 0),
        20,
        60,
        USER,
        noun="auth calls",
        advice="Compare with the status codes: mostly 401/403 is credential stuffing or token guessing; mostly 2xx is a script holding valid accounts.",
    ),
    Rule(
        "account_farming",
        "Account farming",
        "One IP creating or rebinding many accounts (POST /api/users, /api/users/device)",
        lambda s: s.sensitive_hits.get("signup", 0),
        10,
        30,
        USER,
        noun="account writes",
        advice="Cross-check with /fraud/devices in the metrics proxy. Shared IPs (carrier CGNAT) can reach the warning level honestly.",
    ),
    Rule(
        "reward_farming",
        "Reward farming",
        "Burst of mission / ad-reward / check-in / referral claims",
        lambda s: s.sensitive_hits.get("rewards", 0),
        40,
        120,
        USER,
        noun="reward claims",
        advice="Check the accounts behind this IP in /fraud/cohorts before blocking; consider freezing their points.",
    ),
    Rule(
        "unlock_scraping",
        "Episode unlock burst",
        "Unlocking episodes faster than a person watches them",
        lambda s: s.sensitive_hits.get("unlock", 0),
        60,
        200,
        USER,
        noun="unlock calls",
        advice="Likely scripted unlocking or content scraping. Find the account(s) in the server logs and review their balance history.",
    ),
    Rule(
        "upload_abuse",
        "Upload abuse",
        "Burst of presigned-upload requests",
        lambda s: s.sensitive_hits.get("upload", 0),
        20,
        60,
        USER,
        noun="presign calls",
        advice="Check S3 for what was uploaded and how much.",
    ),
    Rule(
        "purchase_failures",
        "Failed purchases",
        "Purchase calls the server rejected: card testing, tampered amounts, blocked retries",
        lambda s: s.signals.get(endpoints.PURCHASE_FAILURES, 0),
        15,
        30,
        USER,
        noun="failed purchase calls",
        advice="Check /payments/error-codes for this window. Many different cards from one IP is card testing: block it and tell the payment provider.",
        early=True,
    ),
    Rule(
        "iap_validation_failures",
        "Rejected IAP receipts",
        "Receipts the server refused on /api/iap/validate*: forged or replayed receipts",
        lambda s: s.signals.get(endpoints.IAP_FAILURES, 0),
        10,
        30,
        USER,
        noun="rejected receipts",
        advice="Run the IAP reconcile for the accounts behind this IP; confirm nothing was granted.",
        early=True,
    ),
    Rule(
        "purchase_attempts",
        "Purchase burst",
        "Many payment attempts in one window (Stripe, Paidy, SB Payment)",
        lambda s: s.signals.get(endpoints.PURCHASES, 0),
        20,
        40,
        USER,
        noun="purchase calls",
        advice="Compare with failed purchases. All successful from one IP is unusual too: check for stolen cards.",
        early=True,
    ),
    Rule(
        "purchase_attempts_1h",
        "Purchasing all hour long",
        "Steady payment attempts over the long window",
        lambda s: s.purchases_1h,
        30,
        60,
        USER,
        noun="purchase calls",
        advice="A slow card tester stays under the 5-minute limits. Review the invoices behind this IP.",
        dedupe_ttl=3600,
        long_window=True,
        early=True,
    ),
    Rule(
        "card_churn",
        "Card add/remove churn",
        "Creating setup intents and replacing/removing saved cards",
        lambda s: s.signals.get(endpoints.CARD_CHANGES, 0),
        12,
        25,
        USER,
        noun="card changes",
        advice="Card testing often shows as add → fail → remove. Check Stripe Radar for the customer(s).",
        early=True,
    ),
    Rule(
        "purchase_check_enumeration",
        "Purchase-check enumeration",
        "Sweeping GET /api/payment/check-purchase/:name/:external_id (no auth guard)",
        lambda s: s.signals.get(endpoints.PURCHASE_CHECKS, 0),
        30,
        100,
        USER,
        noun="check-purchase calls",
        advice="This endpoint has no guard: someone may be enumerating purchase ids. Review what it returns.",
        early=True,
    ),
    Rule(
        "payment_rate_limited",
        "Payment rate limit hit",
        "429 on payment endpoints",
        lambda s: s.signals.get(endpoints.RATE_LIMITED, 0),
        5,
        20,
        USER,
        noun="rate-limited payment calls",
        advice="The limiter is doing its job; block the IP if it keeps going.",
        early=True,
    ),
    # ---- Scanning / infrastructure ----------------------------------------------------
    Rule(
        "cf_rate_limited",
        "Cloudflare rate limit hit",
        "Repeatedly exceeding a Cloudflare rate-limiting rule",
        lambda s: s.cf_rate_limited,
        20,
        100,
        INFRA,
        noun="rate-limited requests",
        advice="Cloudflare is throttling it. Block the IP if it does not stop.",
        early=True,
    ),
    Rule(
        "server_rate_limited",
        "API rate limit hit",
        "429 from the API's own throttler (120 requests / 10 s)",
        lambda s: s.server_rate_limited,
        30,
        150,
        INFRA,
        noun="429 responses",
        advice="The origin is absorbing this. Consider a Cloudflare rate-limiting rule so it stops at the edge.",
    ),
    Rule(
        "high_api_requests",
        "API flood",
        "Very high request rate on the API",
        lambda s: s.api_requests,
        1000,
        3000,
        INFRA,
        noun="API requests",
        advice="Check the API's CPU/memory and Neon connections. " + BLOCK_ADVICE,
        volume=True,
    ),
    Rule(
        "high_total_requests",
        "Request flood",
        "Very high request rate",
        lambda s: s.total_requests,
        1500,
        5000,
        INFRA,
        advice="Check the API's CPU/memory and Neon connections. " + BLOCK_ADVICE,
        volume=True,
    ),
    Rule(
        "cf_blocked",
        "Blocked by Cloudflare",
        "Cloudflare keeps blocking or challenging this IP",
        lambda s: s.cf_blocked,
        50,
        300,
        INFRA,
        noun="blocked requests",
        advice="If this looks like a real user (app UA, Japanese carrier), the WAF may be blocking a customer: check /sw-waf. Otherwise Cloudflare is handling it.",
        early=True,
        detail=lambda s: _top(s.cf_rules, 2),
    ),
    Rule(
        "high_bytes",
        "Heavy download",
        "Large data egress: API scraping or bulk download",
        lambda s: s.bytes,
        2 * GIB,
        10 * GIB,
        INFRA,
        noun="downloaded",
        advice="A few KB per request is API scraping; MB per request is file or video download.",
        unit="bytes",
        volume=True,
        early=True,
    ),
    Rule(
        "media_requests",
        "Media crawling",
        "Many image/media requests",
        lambda s: s.media_requests,
        600,
        2000,
        INFRA,
        noun="media requests",
        advice="Check the top paths by bytes.",
        volume=True,
        early=True,
    ),
    Rule(
        "sustained_requests",
        "Slow, sustained crawl",
        "Stays under the 5-minute limits but never stops",
        lambda s: s.sustained_requests,
        10000,
        30000,
        INFRA,
        advice="A patient crawler. Decide whether the content it reads is meant to be public at this volume.",
        dedupe_ttl=3600,
        long_window=True,
        volume=True,
        early=True,
    ),
)
RULES_BY_ID = {r.id: r for r in RULES}

SPIKE_RULE_ID = "distributed_spike"
SPIKE_PER_IP_REQUESTS = 500
SPIKE_WARNING = 5
SPIKE_CRITICAL = 20

_SENSITIVE_RULES = ("auth_abuse", "account_farming", "reward_farming", "unlock_scraping", "upload_abuse")
_ERROR_RULES = ("not_found_sweep", "denied_requests", "server_rate_limited")


def warning_threshold(rule_id: str, multiplier: float) -> float:
    return RULES_BY_ID[rule_id].thresholds(multiplier)[0]


def candidate_request_threshold(multiplier: float) -> float:
    """The lowest request count at which any request-based rule could fire."""
    return min(
        warning_threshold("high_total_requests", multiplier),
        warning_threshold("high_api_requests", multiplier),
        warning_threshold("id_enumeration", multiplier),
        SPIKE_PER_IP_REQUESTS * multiplier,
        RULES_BY_ID["high_4xx_ratio"].thresholds(multiplier)[2],
    )


def candidate_volume_threshold(multiplier: float) -> float:
    """The lowest request count that is a finding by itself. Used to rank candidates.

    `candidate_request_threshold` also lets in IPs that merely have enough requests for a ratio
    rule; ranking by it would put every moderately busy IP above a low-volume abuser.
    """
    return min(
        warning_threshold("high_total_requests", multiplier),
        warning_threshold("high_api_requests", multiplier),
        warning_threshold("id_enumeration", multiplier),
        SPIKE_PER_IP_REQUESTS * multiplier,
    )


def candidate_error_threshold(multiplier: float) -> float:
    return min(warning_threshold(r, multiplier) for r in _ERROR_RULES)


def candidate_sensitive_threshold(multiplier: float) -> float:
    return min(warning_threshold(r, multiplier) for r in _SENSITIVE_RULES)


def early_score(s, multiplier: float, disabled: frozenset[str] = frozenset()) -> float:
    """How far an IP is above the warning level of a rule that needs no detailed breakdown."""
    best = 0.0
    for rule in RULES:
        if not rule.early or rule.id in disabled:
            continue
        ratio = rule.metric(s) / rule.thresholds(multiplier)[0]
        if ratio >= 1:
            best = max(best, ratio)
    return best


@dataclass(frozen=True)
class Finding:
    ip: str
    rule: Rule
    severity: str
    value: float
    threshold: float
    stats: object

    @property
    def excess(self) -> float:
        return self.value / self.threshold if self.threshold else 0.0


@dataclass(frozen=True)
class SpikeFinding:
    severity: str
    ip_count: int
    threshold: float
    per_ip: float
    ips: list


# A long-window rule repeats its burst rule when the whole hour is explained by that burst.
LONG_OVERLAPS: dict[str, tuple[str, Callable[["object"], float]]] = {
    "purchase_attempts_1h": (
        "purchase_attempts",
        lambda s: s.purchases_1h - s.signals.get(endpoints.PURCHASES, 0),
    ),
}


def _repeats_burst(rule: Rule, s, fired: set[str], multiplier: float) -> bool:
    overlap = LONG_OVERLAPS.get(rule.id)
    if overlap is None:
        return False
    burst_id, earlier = overlap
    return burst_id in fired and earlier(s) < warning_threshold(burst_id, multiplier)


def evaluate(
    stats: dict,
    multiplier: float,
    allowlist=None,
    *,
    trusted_asns: frozenset[int] = frozenset(),
    disabled: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Findings for every IP, most severe and furthest over the limit first."""
    out: list[Finding] = []
    for ip, s in stats.items():
        if allowlist is not None and allowlist.contains(ip):
            continue
        trusted = s.asn in trusted_asns if s.asn else False
        fired: set[str] = set()
        # Burst rules first so a long-window rule can tell it only repeats one.
        for rule in sorted(RULES, key=lambda r: r.long_window):
            if rule.id in disabled or (rule.volume and trusted):
                continue
            if _repeats_burst(rule, s, fired, multiplier):
                continue
            warn, crit, min_req = rule.thresholds(multiplier)
            if min_req and s.total_requests < min_req:
                continue
            value = rule.metric(s)
            if value >= crit:
                out.append(Finding(ip, rule, CRITICAL, value, crit, s))
            elif value >= warn:
                out.append(Finding(ip, rule, WARNING, value, warn, s))
            else:
                continue
            fired.add(rule.id)
    out.sort(key=lambda f: (-SEVERITY_RANK[f.severity], -f.excess))
    return out


def evaluate_spike(
    stats: dict, multiplier: float, allowlist=None, *, trusted_asns: frozenset[int] = frozenset()
) -> SpikeFinding | None:
    """Many IPs each sending a lot at once: a distributed flood no single-IP rule sees."""
    per_ip = SPIKE_PER_IP_REQUESTS * multiplier
    over = sorted(
        (
            s
            for ip, s in stats.items()
            if s.total_requests >= per_ip
            and not (allowlist is not None and allowlist.contains(ip))
            and not (s.asn and s.asn in trusted_asns)
        ),
        key=lambda s: -s.total_requests,
    )
    warn, crit = SPIKE_WARNING * multiplier, SPIKE_CRITICAL * multiplier
    if len(over) >= crit:
        return SpikeFinding(CRITICAL, len(over), crit, per_ip, over)
    if len(over) >= warn:
        return SpikeFinding(WARNING, len(over), warn, per_ip, over)
    return None


def max_severity(findings: list[Finding]) -> str:
    return highest(f.severity for f in findings)


_RULE_ORDER = {r.id: i for i, r in enumerate(RULES)}


def by_importance(findings: list[Finding]) -> list[Finding]:
    """Most severe first; among equals, the most specific rule (RULES order)."""
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], _RULE_ORDER[f.rule.id]))


def headline(findings: list[Finding]) -> Finding:
    """The finding that names the alert."""
    return by_importance(findings)[0]


def group_by_ip(findings: list[Finding]) -> list[list[Finding]]:
    """One group (one Slack message) per IP, keeping the order of the most severe finding."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.ip, []).append(f)
    return list(groups.values())
