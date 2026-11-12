"""Made-up Cloudflare rows for `--preview`, `--test-alert` and the tests.

The sample alerts are produced by the real pipeline (collect -> details -> rules -> Slack), so
what `--test-alert` posts is exactly what a real detection of the same traffic would look like.
Only documentation IP ranges are used (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24, 2001:db8::/32).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import endpoints
import webhooks
from aggregate import add_details, collect, normalize_ip
from allowlist import Allowlist
from rules import evaluate, evaluate_spike, group_by_ip
from slack import build_ip_alert, build_spike, build_webhook_alert
from window import Window, floor_to_period

HOST = "api.swipedrama.com"
SCANNER_IP = "203.0.113.7"
FARMER_IP = "198.51.100.24"
FORGER_IP = "192.0.2.44"
NUCLEI_UA = "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
ANDROID_UA = "okhttp/4.12.0"

BLOCK_ACTIONS = frozenset({"block", "managed_challenge", "challenge", "jschallenge"})
RATE_LIMIT_SOURCES = frozenset({"ratelimit"})


# --- row builders (the shapes Cloudflare returns) ---------------------------------


def talker(ip: str, count: int, nbytes: int = 0, host: str = HOST) -> dict:
    return {"count": count, "sum": {"edgeResponseBytes": nbytes}, "dimensions": {"clientIP": ip, "clientRequestHTTPHost": host}}


def detail(
    ip: str,
    path: str,
    count: int,
    status: int = 200,
    *,
    method: str = "GET",
    nbytes: int = 0,
    host: str = HOST,
    country: str = "SG",
    asn: int = 14061,
    asn_name: str = "DIGITALOCEAN-ASN",
    ua: str = "Go-http-client/2.0",
) -> dict:
    return {
        "count": count,
        "sum": {"edgeResponseBytes": nbytes},
        "dimensions": {
            "clientIP": ip,
            "clientRequestHTTPHost": host,
            "clientRequestPath": path,
            "clientRequestHTTPMethodName": method,
            "edgeResponseStatus": status,
            "clientCountryName": country,
            "clientAsn": asn,
            "clientASNDescription": asn_name,
            "userAgent": ua,
        },
    }


def signal(ip: str, path: str, count: int, status: int = 200, method: str = "POST", host: str = HOST) -> dict:
    return {
        "count": count,
        "dimensions": {
            "clientIP": ip,
            "clientRequestHTTPHost": host,
            "clientRequestPath": path,
            "clientRequestHTTPMethodName": method,
            "edgeResponseStatus": status,
        },
    }


def scanner(ip: str, path: str, count: int, status: int = 404) -> dict:
    return {"count": count, "dimensions": {"clientIP": ip, "clientRequestPath": path, "edgeResponseStatus": status}}


def tool(ip: str, ua: str, count: int) -> dict:
    return {"count": count, "dimensions": {"clientIP": ip, "userAgent": ua}}


def injection(ip: str, path: str, query: str, count: int, status: int = 403) -> dict:
    return {
        "count": count,
        "dimensions": {"clientIP": ip, "clientRequestPath": path, "clientRequestQuery": query, "edgeResponseStatus": status},
    }


def event(
    ip: str,
    path: str,
    *,
    action: str = "block",
    source: str = "firewallManaged",
    description: str = "Cloudflare Managed Ruleset",
    country: str = "SG",
    asn: int = 14061,
    ua: str = "Go-http-client/2.0",
    host: str = HOST,
) -> dict:
    return {
        "datetime": "2026-11-12T03:30:00Z",
        "action": action,
        "source": source,
        "ruleId": "0123456789abcdef",
        "description": description,
        "clientIP": ip,
        "clientAsn": str(asn),
        "clientCountryName": country,
        "clientRequestHTTPHost": host,
        "clientRequestHTTPMethodName": "GET",
        "clientRequestPath": path,
        "edgeResponseStatus": 403,
        "userAgent": ua,
    }


def webhook(
    ip: str,
    path: str,
    count: int,
    status: int,
    *,
    asn: int = 16509,
    asn_name: str = "AMAZON-02",
    country: str = "US",
    ua: str = "",
    host: str = HOST,
) -> dict:
    return {
        "count": count,
        "dimensions": {
            "clientIP": ip,
            "clientAsn": asn,
            "clientASNDescription": asn_name,
            "clientCountryName": country,
            "userAgent": ua,
            "clientRequestHTTPHost": host,
            "clientRequestPath": path,
            "edgeResponseStatus": status,
        },
    }


# --- scenarios --------------------------------------------------------------------


def scanner_scenario(ip: str = SCANNER_IP) -> dict:
    """A nuclei run: probe paths, a few payloads, mostly stopped by the WAF."""
    probes = [
        ("/.env", 96, 403),
        ("/.git/config", 64, 403),
        ("/wp-login.php", 58, 403),
        ("/phpmyadmin/index.php", 41, 403),
        ("/actuator/env", 33, 404),
        ("/api/.env", 28, 403),
        ("/backup.sql", 12, 404),
    ]
    other = [("/api/movies", 22, 200), ("/api/users", 14, 401), ("/admin", 9, 404), ("/api/v2/packages", 6, 200)]
    kw = {"ua": NUCLEI_UA}
    return {
        "top": [talker(ip, 395)],
        "errors": [talker(ip, 355)],
        "scanner": [scanner(ip, p, n, st) for p, n, st in probes],
        "tools": [tool(ip, NUCLEI_UA, 395)],
        "injection": [
            injection(ip, "/api/movies", "?q=1%27%20UNION%20SELECT%20null,version()--", 9),
            injection(ip, "/api/movies", "?q=%3Cscript%3Ealert(1)%3C/script%3E", 4),
            injection(ip, "/api/v2/packages", "?id=../../../../etc/passwd", 3),
        ],
        "events": [event(ip, p, ua=NUCLEI_UA) for p, n, st in probes if st == 403 for _ in range(n)]
        + [event(ip, "/api/movies", ua=NUCLEI_UA, description="SQLi") for _ in range(16)],
        "details": [detail(ip, p, n, st, **kw) for p, n, st in probes + other],
    }


def farmer_scenario(ip: str = FARMER_IP) -> dict:
    """A script on a phone network claiming rewards and unlocking episodes far too fast."""
    kw = {"country": "JP", "asn": 17676, "asn_name": "SoftBank Corp.", "ua": ANDROID_UA}
    calls = [
        ("/api/user-ads/get-point", 92, 201, "POST"),
        ("/api/unlock-episode", 74, 201, "POST"),
        ("/api/user-missions/bonus-points", 38, 201, "POST"),
        ("/api/user-checkins/checkin", 11, 400, "POST"),
        ("/api/episode/88213", 70, 200, "GET"),
        ("/api/user-ads/get-point", 35, 429, "POST"),
    ]
    return {
        "top": [talker(ip, 320)],
        "sensitive": [talker(ip, 250)],
        "details": [detail(ip, p, n, st, method=m, **kw) for p, n, st, m in calls],
    }


def forged_webhook_rows(ip: str = FORGER_IP) -> list[dict]:
    # The Stripe controller answers 400 to a missing or invalid stripe-signature.
    return [webhook(ip, "/webhook/stripe", 14, 400, ua="python-requests/2.31.0")]


def spike_details(count: int = 8) -> list[dict]:
    nets = [("BR", 28573, "Claro NXT"), ("ID", 7713, "Telkom Indonesia"), ("VN", 45899, "VNPT Corp"), ("US", 14061, "DIGITALOCEAN-ASN")]
    rows = []
    for i in range(count):
        cc, asn, name = nets[i % len(nets)]
        rows.append(detail(f"203.0.113.{100 + i}", "/api/movies", 900 - i * 37, country=cc, asn=asn, asn_name=name, ua="Mozilla/5.0"))
    return rows


def build_stats(scenario: dict, *, excluded: tuple[str, ...] = endpoints.DEFAULT_EXCLUDED_PATH_PREFIXES):
    stats = collect(
        top_rows=scenario.get("top", []),
        error_rows=scenario.get("errors", []),
        sensitive_rows=scenario.get("sensitive", []),
        signal_counts=endpoints.counters(scenario.get("signals", []), normalize_ip),
        scanner_rows=scenario.get("scanner", []),
        tool_rows=scenario.get("tools", []),
        injection_rows=scenario.get("injection", []),
        events=scenario.get("events", []),
        excluded_prefixes=excluded,
        block_actions=BLOCK_ACTIONS,
        rate_limit_sources=RATE_LIMIT_SOURCES,
    )
    return add_details(
        stats,
        scenario.get("details", []),
        excluded_prefixes=excluded,
        sensitive_methods=frozenset({"POST", "PUT", "PATCH", "DELETE"}),
    )


def payloads(cfg) -> list[tuple[str, dict]]:
    """(name, Slack payload) for one alert of each kind, marked as a test."""
    end = floor_to_period(datetime.now(timezone.utc), cfg.window_minutes)
    window = Window(end - timedelta(minutes=cfg.window_minutes), end)
    out: list[tuple[str, dict]] = []

    for name, scenario in (("scanner", scanner_scenario()), ("reward farming", farmer_scenario())):
        findings = evaluate(build_stats(scenario), 1.0)
        for group in group_by_ip(findings):
            out.append((f"test alert: {name}", build_ip_alert(cfg, window, group, test=True)))

    found = webhooks.evaluate(
        forged_webhook_rows(),
        [],
        store=None,
        tick=end,
        period_minutes=cfg.window_minutes,
        thresholds=webhooks.Thresholds(),
        allowlist=Allowlist(),
    )
    out += [("test alert: webhook", build_webhook_alert(cfg, window, f, test=True)) for f in found]

    spike_stats = add_details({}, spike_details(), excluded_prefixes=())
    spike = evaluate_spike(spike_stats, 1.0)
    if spike:
        out.append(("test alert: spike", build_spike(cfg, window, spike, test=True)))
    return out
