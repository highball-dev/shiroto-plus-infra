"""Build webhook_sources.json from Cloudflare history (who really calls each webhook).

    python cf_webhook_baseline.py --days 30            # hosts from MONITOR_HOSTS
    python cf_webhook_baseline.py --days 30 --all-hosts

For every path under WEBHOOK_PREFIXES it records the networks (ASN), user-agent patterns and the
IPs that got a 2xx (i.e. passed the server's signature/secret check). Review the output before
committing: sources that look like people (browsers, Postman), link previews and rare callers
are left out and listed so you can decide. `official_ips` / `strict` / `name` that you added by
hand are kept when the file is regenerated.

Cloudflare keeps this data for about 30 days.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import config
import endpoints
from aggregate import normalize_ip, normalize_path
from cf_graphql import WEBHOOK_DIMENSIONS, GraphQLClient, groups_query, like_pattern
from webhooks import LINK_PREVIEW_UAS

ROW_LIMIT = 10000
QUERY = groups_query("WebhookBaseline", WEBHOOK_DIMENSIONS, ROW_LIMIT)

HUMAN_UA = re.compile(
    r"mozilla|postman|insomnia|curl/|httpie|wget|" + "|".join(re.escape(p) for p in LINK_PREVIEW_UAS),
    re.I,
)


def ua_pattern(ua: str) -> str:
    """`Stripe/1.0 (+https://…)` -> `Stripe/`: stable across the provider's version bumps."""
    if not ua:
        return ""
    first = ua.split(" ", 1)[0]
    return first.split("/", 1)[0] + "/" if "/" in first else ua[:60]


def fetch(gql: GraphQLClient, start: datetime, end: datetime, hosts, prefixes) -> list[dict]:
    rows: list[dict] = []
    cursor = start
    while cursor < end:
        nxt = min(cursor + timedelta(days=1), end)
        f = {
            "datetime_geq": cursor.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "datetime_lt": nxt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "OR": [{"clientRequestPath_like": like_pattern(p)} for p in prefixes],
        }
        if hosts:
            f["clientRequestHTTPHost_in"] = list(hosts)
        part = gql.query(QUERY, {"filter": f}).get("httpRequestsAdaptiveGroups") or []
        if len(part) >= ROW_LIMIT:
            print(f"!! {cursor:%Y-%m-%d}: {ROW_LIMIT} rows, the day was truncated", file=sys.stderr)
        rows += part
        cursor = nxt
    return rows


def build(rows: list[dict], min_count: int, min_share: float):
    by_path: dict[str, Counter] = defaultdict(Counter)
    ips: dict[tuple, Counter] = defaultdict(Counter)
    names: dict[int, str] = {}
    for r in rows:
        d = r["dimensions"]
        status = int(d.get("edgeResponseStatus") or 0)
        path = normalize_path(d.get("clientRequestPath") or "/")
        asn = int(d.get("clientAsn") or 0)
        ua = d.get("userAgent") or ""
        names[asn] = d.get("clientASNDescription") or ""
        by_path[path][(asn, ua_pattern(ua), ua)] += r["count"]
        # Only callers the server accepted become "known IPs".
        ips[(path, asn, ua_pattern(ua))][normalize_ip(d.get("clientIP", ""))] += r["count"] if 200 <= status < 300 else 0

    profiles: dict[str, dict] = {}
    review: list[tuple] = []
    for path, groups in sorted(by_path.items()):
        total = sum(groups.values())
        keep = {
            k: n for k, n in groups.items() if n >= min_count and n >= total * min_share and not HUMAN_UA.search(k[2])
        }
        review += [(path, n, k[0], names.get(k[0], ""), k[2]) for k, n in groups.items() if k not in keep]
        if not keep:
            continue
        asns = sorted({k[0] for k in keep})
        profiles[path] = {
            "name": endpoints.webhook_name(path),
            "asns": asns,
            "user_agents": sorted({k[1] for k in keep}),
            "ips": sorted({ip for k in keep for ip, n in ips[(path, k[0], k[1])].items() if ip and n > 0}),
            "_seen": {f"AS{a} {names.get(a, '')}".strip(): sum(n for k, n in keep.items() if k[0] == a) for a in asns},
        }
    return profiles, review


def main() -> int:
    parser = argparse.ArgumentParser(description="Build webhook_sources.json from Cloudflare history")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--out", default=config.DEFAULT_WEBHOOK_SOURCES_FILE)
    parser.add_argument("--all-hosts", action="store_true", help="ignore MONITOR_HOSTS (every host in the zone)")
    parser.add_argument("--min-count", type=int, default=10, help="requests for a source to count as a provider")
    parser.add_argument("--min-share", type=float, default=0.01, help="share of a path's traffic, same purpose")
    parser.add_argument("--max-ips", type=int, default=30, help='more known IPs than this -> "ips": "*" (rotating pool)')
    args = parser.parse_args()

    try:
        cfg = config.load()
    except config.ConfigError as e:
        print(f"config invalid: {e}")
        return 2
    gql = GraphQLClient(cfg.cf_api_token, cfg.cf_zone_tag, cfg.graphql_url, 60)
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = end - timedelta(days=min(args.days, 30))
    hosts = () if args.all_hosts else cfg.query_hosts
    profiles, review = build(fetch(gql, start, end, hosts, cfg.webhook_prefixes), args.min_count, args.min_share)
    for p in profiles.values():
        if len(p["ips"]) > args.max_ips:
            p["ips"] = "*"

    # Keep what was curated by hand.
    try:
        with open(args.out, encoding="utf-8") as f:
            previous = json.load(f)
    except (OSError, ValueError):
        previous = {}
    for path, old in previous.items():
        if path.startswith("_") or not isinstance(old, dict):
            continue
        kept = {k: old[k] for k in ("name", "official_ips", "strict") if k in old}
        if path in profiles:
            profiles[path].update(kept)
        elif kept.get("official_ips"):
            profiles[path] = {**old}

    doc = {
        "_generated": f"{start:%Y-%m-%d}..{end:%Y-%m-%d} hosts={','.join(hosts) or 'all'}; review before committing",
        **profiles,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"wrote {len(profiles)} webhook profiles to {args.out}\n")
    for path, p in profiles.items():
        n_ips = "any IP" if p["ips"] == "*" else f"{len(p['ips'])} IPs"
        print(f"{path}  [{p['name']}]  AS{p['asns']}  UA {p['user_agents']}  {n_ips}")
    if review:
        print("\nNOT included (people, link previews, or too rare). Check these by hand:")
        for path, n, asn, asn_name, ua in sorted(review, key=lambda r: -r[1]):
            print(f"  {n:6d}  {path}  AS{asn} {asn_name[:28]}  ua={ua[:70]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
