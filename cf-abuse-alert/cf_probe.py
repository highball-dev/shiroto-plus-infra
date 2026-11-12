"""Setup tool: run every query of a tick against the real zone and show what comes back.

    python cf_probe.py                 # last 15 minutes
    python cf_probe.py --minutes 60    # a quiet zone needs a wider window to show rows

Run it once before the first deploy and after any change to cf_graphql.py or signatures.py.
It needs the same env as the service (SLACK_WEBHOOK_URL is required by the config but never
used here). IPs are masked in the output.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

import cf_graphql as q
import config
import endpoints
import signatures
from aggregate import normalize_ip
from cf_graphql import HTTP_FILTER, GraphQLClient, GraphQLError, row_bytes
from slack import fmt_bytes, mask_ip
from window import Window, floor_to_minute

LATEST_MINUTE = f"""
query LatestMinute($zoneTag: string, $filter: {HTTP_FILTER}) {{
  viewer {{
    zones(filter: {{ zoneTag: $zoneTag }}) {{
      httpRequestsAdaptiveGroups(filter: $filter, limit: 1, orderBy: [datetimeMinute_DESC]) {{
        count
        dimensions {{ datetimeMinute }}
      }}
    }}
  }}
}}
"""

HINTS = {
    "notlike": "the `_notlike` filter is not supported: remove _exclude_paths() in cf_graphql.py and allowlist provider IPs",
    "edgeResponseBytes": "the bytes field is unknown: check the dataset schema in the GraphQL explorer",
    "clientRequestQuery": "the query-string dimension is not available: set DISABLED_RULES=injection_attempts",
    "clientASNDescription": "drop clientASNDescription from DETAIL_DIMENSIONS / WEBHOOK_DIMENSIONS (alerts then show the AS number only)",
    "userAgent": "the userAgent dimension is not available on this plan: drop it from the *_DIMENSIONS constants",
    "requestSource": 'remove "requestSource" from http_filter() in cf_graphql.py',
}


def step(title: str) -> None:
    print(f"\n=== {title} ===")


def describe(name: str, rows: list[dict]) -> list[str]:
    """What the service would make of these rows."""
    if name == q.S2_SCANNER:
        kinds = Counter()
        for r in rows:
            kind = signatures.scanner_kind(r["dimensions"].get("clientRequestPath") or "")
            kinds[kind or "(not confirmed by the regexes)"] += r["count"]
        return [f"probe kinds: {dict(kinds.most_common()) or 'none'}"]
    if name == q.S3_TOOLS:
        tools = Counter()
        for r in rows:
            tool = signatures.attack_tool(r["dimensions"].get("userAgent") or "")
            tools[tool or "(not confirmed by the regexes)"] += r["count"]
        return [f"tools: {dict(tools.most_common()) or 'none'}"]
    if name == q.S4_INJECTION:
        kinds = Counter()
        for r in rows:
            d = r["dimensions"]
            kind = signatures.injection_kind(d.get("clientRequestPath") or "", d.get("clientRequestQuery") or "")
            kinds[kind or "(not confirmed by the regexes)"] += r["count"]
        return [f"payload kinds: {dict(kinds.most_common()) or 'none'}  (query strings are never printed)"]
    if name == q.A7_SIGNALS:
        totals: Counter = Counter()
        for counts in endpoints.counters(rows, normalize_ip).values():
            totals.update(counts)
        return [f"signals: {dict(totals) or 'none in this window'}"]
    if name == q.A9_WEBHOOKS:
        paths = Counter()
        for r in rows:
            d = r["dimensions"]
            paths[f"{d.get('clientRequestPath')} -> {d.get('edgeResponseStatus')}"] += r["count"]
        return [f"{n:7,}  {p}" for p, n in paths.most_common(12)]
    if name == q.B_EVENTS:
        actions = Counter(r.get("action") for r in rows)
        sources = Counter(r.get("source") for r in rows)
        return [f"actions: {dict(actions.most_common())}", f"sources: {dict(sources.most_common())}"]
    out = []
    for r in rows[:3]:
        d = r.get("dimensions") or r
        out.append(
            f"{mask_ip(d.get('clientIP', ''))} {d.get('clientRequestHTTPHost') or ''} "
            f"count={r.get('count', 1):,} bytes={fmt_bytes(row_bytes(r))}"
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="cf-abuse-alert probe: verify the GraphQL queries on the real zone")
    parser.add_argument("--minutes", type=int, default=15, help="window for the queries (default 15)")
    args = parser.parse_args()

    try:
        cfg = config.load()
    except config.ConfigError as e:
        print(f"config invalid: {e}")
        return 2
    gql = GraphQLClient(cfg.cf_api_token, cfg.cf_zone_tag, cfg.graphql_url, max(30, cfg.graphql_timeout_seconds))
    hosts = cfg.query_hosts
    excluded = cfg.excluded_path_prefixes
    now = datetime.now(timezone.utc)
    ok = True

    step("1. token, zone and dataset limits")
    try:
        settings = gql.settings()
        print(json.dumps(settings, indent=2))
        for node, limit in (
            ("httpRequestsAdaptiveGroups", q.CANDIDATE_DETAILS_LIMIT),
            ("firewallEventsAdaptive", q.SECURITY_EVENTS_LIMIT),
        ):
            page = (settings.get(node) or {}).get("maxPageSize")
            if page and page < limit:
                print(f"!! {node}.maxPageSize={page} < {limit} used by the queries: lower the limit in cf_graphql.py")
        max_duration = (settings.get("httpRequestsAdaptiveGroups") or {}).get("maxDuration")
        if isinstance(max_duration, (int, float)) and max_duration < cfg.sustained_window_minutes * 60:
            print(f"!! httpRequestsAdaptiveGroups.maxDuration={max_duration}s < SUSTAINED_WINDOW_MINUTES: lower it")
    except GraphQLError as e:
        print(f"FAILED: {e}")
        print("   403 / no zone -> the token lacks Zone > Analytics > Read on this zone, or CF_ZONE_TAG is wrong")
        return 1

    step(f"2. the queries of one tick over the last {args.minutes} min, hosts={','.join(hosts)}")
    end = floor_to_minute(now) - timedelta(minutes=cfg.ingest_lag_minutes)
    window = Window(end - timedelta(minutes=args.minutes), end)
    long_window = Window(end - timedelta(minutes=cfg.sustained_window_minutes), end)
    print(f"window {window.label(cfg.display_tz)} · long window {long_window.label(cfg.display_tz)}")
    if not cfg.media_enabled:
        print("   MEDIA_HOSTS / MEDIA_PATH_PREFIXES are empty: A5 and media_requests are off")

    calls = [
        (q.A1_TOP, "top IPs by requests", lambda: gql.top_talkers(window, hosts)),
        (q.B_EVENTS, "security events (not skip)", lambda: gql.security_events(window, hosts)),
        (
            q.A3_SENSITIVE,
            "top IPs writing to sensitive endpoints",
            lambda: gql.sensitive_talkers(window, hosts, endpoints.all_sensitive_prefixes(), cfg.sensitive_methods),
        ),
        (q.A4_BYTES, "top IPs by bytes", lambda: gql.top_bytes(window, hosts, excluded)),
        (
            q.A5_MEDIA,
            "top IPs on media",
            lambda: gql.media_talkers(window, hosts, cfg.media_hosts, cfg.media_path_prefixes, excluded),
        ),
        (q.A6_SUSTAINED, f"top IPs over {cfg.sustained_window_minutes} min", lambda: gql.sustained_talkers(long_window, hosts, excluded)),
        (q.A7_SIGNALS, "payment / restricted-area signals", lambda: gql.endpoint_signals(window, hosts, endpoints.signal_filters())),
        (q.A8_PURCHASES, f"purchases per IP over {cfg.sustained_window_minutes} min", lambda: gql.purchase_talkers(long_window, hosts, endpoints.purchase_filters())),
        (q.A9_WEBHOOKS, "webhook / callback calls", lambda: gql.webhook_requests(window, hosts, cfg.webhook_prefixes)),
        (q.S1_ERRORS, "top IPs by 4xx", lambda: gql.error_talkers(window, hosts, excluded)),
        (q.S2_SCANNER, "scanner paths", lambda: gql.scanner_requests(window, hosts)),
        (q.S3_TOOLS, "attack-tool user agents", lambda: gql.tool_requests(window, hosts)),
        (q.S4_INJECTION, "injection payloads", lambda: gql.injection_requests(window, hosts, excluded)),
    ]
    top: list = []
    events: list = []
    for name, label, call in calls:
        try:
            rows = call()
        except GraphQLError as e:
            ok = False
            print(f"FAIL {name} ({label}): {e}")
            for key, hint in HINTS.items():
                if key in str(e):
                    print(f"       -> {hint}")
            continue
        print(f"OK   {name} ({label}): {len(rows)} rows")
        for line in describe(name, rows):
            print(f"       {line}")
        if name == q.A1_TOP:
            top = rows
        if name == q.B_EVENTS:
            events = rows
            unknown = {
                (r.get("action") or "").lower() for r in rows
            } - cfg.block_actions - {"skip", "log", "allow", "bypass", ""}
            if unknown:
                print(f"       ?? actions not in BLOCK_ACTIONS: {sorted(unknown)} (add the ones that mean 'stopped')")

    ips = [(r.get("dimensions") or {}).get("clientIP") for r in top[:5]] or [e.get("clientIP") for e in events[:5]]
    ips = [ip for ip in ips if ip]
    if ips:
        try:
            rows = gql.candidate_details(window, hosts, ips)
            print(f"OK   {q.A2_DETAILS} (breakdown of {len(ips)} IPs): {len(rows)} rows")
            if rows:
                d = rows[0]["dimensions"]
                present = {k: ("empty" if d.get(k) in (None, "") else "ok") for k in d if k != "clientIP"}
                print(f"       dimensions: {present}")
        except GraphQLError as e:
            ok = False
            print(f"FAIL {q.A2_DETAILS}: {e}")
            for key, hint in HINTS.items():
                if key in str(e):
                    print(f"       -> {hint}")
    else:
        print(f"SKIP {q.A2_DETAILS}: no traffic in the window to pick IPs from; widen --minutes")

    step("3. ingest lag")
    try:
        zone = gql.query(
            LATEST_MINUTE,
            {
                "filter": {
                    "datetime_geq": (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "clientRequestHTTPHost_in": list(hosts),
                }
            },
        )
        rows = zone.get("httpRequestsAdaptiveGroups") or []
        if rows:
            latest = datetime.fromisoformat(rows[0]["dimensions"]["datetimeMinute"].replace("Z", "+00:00"))
            lag = (now - latest).total_seconds() / 60
            print(f"newest minute with data: {latest:%H:%M}Z, {lag:.1f} min ago (INGEST_LAG_MINUTES={cfg.ingest_lag_minutes})")
            print("   run this a few times; set INGEST_LAG_MINUTES 1-2 min above the worst value")
        else:
            print("no traffic on these hosts in the last 30 min: send a few requests and re-run")
    except GraphQLError as e:
        ok = False
        print(f"FAIL: {e}")

    print("\n" + ("All queries OK." if ok else "Some queries FAILED: fix them before deploying (see the hints above)."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
