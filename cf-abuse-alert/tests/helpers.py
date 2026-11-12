"""Test doubles: a fake Cloudflare GraphQL API + Slack webhook behind the `Post` seam."""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import replace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cf_graphql as q  # noqa: E402
import config  # noqa: E402
import endpoints  # noqa: E402
import slack  # noqa: E402
from allowlist import Allowlist  # noqa: E402

# Retries stay on in the tests, without the waiting.
slack.Sender.retry_delays = (0.0, 0.0)

SLACK_URL = "https://hooks.slack.test/services/T000/B000/SECRETSECRET"
TOKEN = "cf-test-token-SECRETSECRET"
HOST = "api.swipedrama.com"
ALLOWLISTED_IP = "198.51.100.200"

# scenario key (samples.py) -> query id
QUERY_OF = {
    "top": q.A1_TOP,
    "details": q.A2_DETAILS,
    "sensitive": q.A3_SENSITIVE,
    "bytes": q.A4_BYTES,
    "media": q.A5_MEDIA,
    "sustained": q.A6_SUSTAINED,
    "signals": q.A7_SIGNALS,
    "purchases": q.A8_PURCHASES,
    "webhooks": q.A9_WEBHOOKS,
    "events": q.B_EVENTS,
    "errors": q.S1_ERRORS,
    "scanner": q.S2_SCANNER,
    "tools": q.S3_TOOLS,
    "injection": q.S4_INJECTION,
}


def make_cfg(**overrides) -> config.Config:
    base = config.Config(
        cf_api_token=TOKEN,
        cf_zone_tag="zone-tag-test",
        slack_webhook_url=SLACK_URL,
        environment_label="NON-PROD",
        monitor_hosts=(HOST,),
        allowlist=Allowlist.parse([ALLOWLISTED_IP]),
        excluded_path_prefixes=endpoints.DEFAULT_EXCLUDED_PATH_PREFIXES,
        block_actions=frozenset(config.DEFAULT_BLOCK_ACTIONS.split(",")),
        rate_limit_sources=frozenset(config.DEFAULT_RATE_LIMIT_SOURCES.split(",")),
        ingest_lag_minutes=3,
        window_minutes=5,
        dedupe_ttl_seconds=1800,
        max_alerts_per_run=10,
        max_candidates=50,
        threshold_multiplier=1.0,
        dry_run=False,
        heartbeat_hour_utc=23,
        dashboard_url=config.DEFAULT_DASHBOARD_URL,
        webhook_sources_file="",
    )
    return replace(base, **overrides)


def graphql(*scenarios: dict, **extra) -> dict:
    """Merge scenarios (rows keyed like samples.py) into {query id: rows}."""
    out: dict = {}
    for scenario in (*scenarios, extra):
        for key, rows in scenario.items():
            name = QUERY_OF.get(key, key)
            if isinstance(rows, list):
                out[name] = out.get(name, []) + rows
            else:
                out[name] = rows
    return out


class FakePost:
    """Answers GraphQL by operation name; records what was sent to Cloudflare and to Slack."""

    def __init__(self, graphql: dict | None = None, slack_status: int = 200, slack_body: bytes = b"ok"):
        self.graphql = graphql or {}
        self.slack_status = slack_status
        self.slack_body = slack_body
        self.slack: list[dict] = []
        self.gql: list[dict] = []

    def __call__(self, url, headers, payload, timeout):
        if "graphql" in url:
            assert headers["Authorization"] == f"Bearer {TOKEN}"
            name = re.search(r"query (\w+)", payload["query"]).group(1)
            self.gql.append({"name": name, **payload})
            resp = self.graphql.get(name, [])
            if isinstance(resp, Exception):
                raise resp
            if isinstance(resp, tuple):
                return resp
            if isinstance(resp, list):
                node = "firewallEventsAdaptive" if name == q.B_EVENTS else "httpRequestsAdaptiveGroups"
                resp = {"data": {"viewer": {"zones": [{node: resp}]}}}
            return 200, json.dumps(resp).encode()
        self.slack.append(payload)
        return self.slack_status, self.slack_body

    def sent(self, name: str) -> list[dict]:
        return [g for g in self.gql if g["name"] == name]

    def texts(self) -> list[str]:
        return [json.dumps(p, ensure_ascii=False) for p in self.slack]
