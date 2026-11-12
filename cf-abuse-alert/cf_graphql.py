"""Cloudflare GraphQL Analytics API client and the queries of one tick.

Every query is aggregated by Cloudflare (`httpRequestsAdaptiveGroups`), so the response size
depends on the limits below, not on how much traffic the zone has. The data is sampled:
counts are estimates, good for thresholds, not for billing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import signatures
from http_util import Post, post_json
from window import Window

HTTP_FILTER = "ZoneHttpRequestsAdaptiveGroupsFilter_InputObject"
FW_FILTER = "FirewallEventsAdaptiveFilter_InputObject"

TOP_TALKERS_LIMIT = 100
CANDIDATE_DETAILS_LIMIT = 5000
SECURITY_EVENTS_LIMIT = 1000
SIGNALS_LIMIT = 1000
WEBHOOK_REQUESTS_LIMIT = 2000
SCANNER_LIMIT = 1000
TOOL_UA_LIMIT = 500
INJECTION_LIMIT = 500

# Query ids, used in logs, in the "degraded" alert and by the tests' fake Cloudflare.
A1_TOP = "A1_TopTalkers"
A2_DETAILS = "A2_CandidateDetails"
A3_SENSITIVE = "A3_SensitiveTalkers"
A4_BYTES = "A4_TopBytes"
A5_MEDIA = "A5_MediaTalkers"
A6_SUSTAINED = "A6_SustainedTalkers"
A7_SIGNALS = "A7_EndpointSignals"
A8_PURCHASES = "A8_PurchaseTalkers"
A9_WEBHOOKS = "A9_WebhookRequests"
B_EVENTS = "B_SecurityEvents"
S1_ERRORS = "S1_ErrorTalkers"
S2_SCANNER = "S2_ScannerPaths"
S3_TOOLS = "S3_AttackTools"
S4_INJECTION = "S4_InjectionPayloads"

SETTINGS = """
query Settings($zoneTag: string) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      settings {
        firewallEventsAdaptive { maxDuration notOlderThan maxPageSize enabled }
        httpRequestsAdaptiveGroups { maxDuration notOlderThan maxPageSize enabled }
      }
    }
  }
}
"""

TALKER_DIMENSIONS = "clientIP clientRequestHTTPHost"
DETAIL_DIMENSIONS = (
    "clientIP clientRequestHTTPHost clientRequestPath clientRequestHTTPMethodName edgeResponseStatus "
    "clientCountryName clientAsn clientASNDescription userAgent"
)
SIGNAL_DIMENSIONS = "clientIP clientRequestHTTPHost clientRequestPath clientRequestHTTPMethodName edgeResponseStatus"
WEBHOOK_DIMENSIONS = (
    "clientIP clientAsn clientASNDescription clientCountryName userAgent "
    "clientRequestHTTPHost clientRequestPath edgeResponseStatus"
)
SCANNER_DIMENSIONS = "clientIP clientRequestPath edgeResponseStatus"
TOOL_DIMENSIONS = "clientIP userAgent"
INJECTION_DIMENSIONS = "clientIP clientRequestPath clientRequestQuery edgeResponseStatus"
EVENT_FIELDS = (
    "datetime action source ruleId description clientIP clientAsn clientCountryName "
    "clientRequestHTTPHost clientRequestHTTPMethodName clientRequestPath edgeResponseStatus userAgent"
)


def groups_query(name: str, dimensions: str, limit: int, order: str = "count_DESC", with_bytes: bool = False) -> str:
    total = "sum { edgeResponseBytes }" if with_bytes else ""
    return f"""
query {name}($zoneTag: string, $filter: {HTTP_FILTER}) {{
  viewer {{
    zones(filter: {{ zoneTag: $zoneTag }}) {{
      httpRequestsAdaptiveGroups(filter: $filter, limit: {limit}, orderBy: [{order}]) {{
        count
        {total}
        dimensions {{ {dimensions} }}
      }}
    }}
  }}
}}
"""


def events_query(name: str = B_EVENTS, limit: int = SECURITY_EVENTS_LIMIT) -> str:
    return f"""
query {name}($zoneTag: string, $filter: {FW_FILTER}) {{
  viewer {{
    zones(filter: {{ zoneTag: $zoneTag }}) {{
      firewallEventsAdaptive(filter: $filter, limit: {limit}, orderBy: [datetime_DESC]) {{
        {EVENT_FIELDS}
      }}
    }}
  }}
}}
"""


class GraphQLError(RuntimeError):
    pass


@dataclass
class GraphQLClient:
    token: str
    zone_tag: str
    url: str
    timeout: float = 15.0
    post: Post = post_json

    def query(self, query: str, variables: dict[str, Any]) -> dict:
        try:
            status, body = self.post(
                self.url,
                {"Authorization": f"Bearer {self.token}"},
                {"query": query, "variables": {"zoneTag": self.zone_tag, **variables}},
                self.timeout,
            )
        except TimeoutError:
            raise GraphQLError("timeout") from None
        except OSError as e:
            raise GraphQLError(str(e)) from None

        # Never put the response body of a non-2xx in the error: it can echo the token.
        if not 200 <= status < 300:
            raise GraphQLError(f"GraphQL {status}")
        try:
            doc = json.loads(body)
        except ValueError:
            raise GraphQLError("GraphQL response is not JSON") from None
        errors = doc.get("errors") or []
        if errors:
            first = str((errors[0] or {}).get("message", "unknown error"))[:200]
            raise GraphQLError(f"GraphQL errors ({len(errors)}): {first}")
        data = doc.get("data") or {}
        zones = ((data.get("viewer") or {}).get("zones")) or []
        if not zones:
            raise GraphQLError("GraphQL returned no zone — wrong CF_ZONE_TAG or token scope")
        return zones[0]

    def _groups(self, query: str, f: dict) -> list[dict]:
        return self.query(query, {"filter": f}).get("httpRequestsAdaptiveGroups") or []

    def settings(self) -> dict:
        return self.query(SETTINGS, {}).get("settings") or {}

    # --- who sends the most ---------------------------------------------------------

    def top_talkers(self, window: Window, hosts: tuple[str, ...]) -> list[dict]:
        """A1: top IPs by request count."""
        q = groups_query(A1_TOP, TALKER_DIMENSIONS, TOP_TALKERS_LIMIT, with_bytes=True)
        return self._groups(q, http_filter(window, hosts))

    def sensitive_talkers(
        self,
        window: Window,
        hosts: tuple[str, ...],
        prefixes: list[str],
        methods: frozenset[str] | None = None,
    ) -> list[dict]:
        """A3: top IPs writing to sensitive endpoints (auth, signup, rewards, unlock, upload)."""
        f = http_filter(window, hosts)
        f["OR"] = [{"clientRequestPath_like": f"{p}%"} for p in prefixes]
        if methods:
            f["clientRequestHTTPMethodName_in"] = sorted(methods)
        return self._groups(groups_query(A3_SENSITIVE, TALKER_DIMENSIONS, TOP_TALKERS_LIMIT), f)

    def top_bytes(self, window: Window, hosts: tuple[str, ...], excluded: tuple[str, ...]) -> list[dict]:
        """A4: top IPs by bytes downloaded."""
        f = http_filter(window, hosts)
        _exclude_paths(f, excluded)
        q = groups_query(A4_BYTES, TALKER_DIMENSIONS, TOP_TALKERS_LIMIT, "sum_edgeResponseBytes_DESC", True)
        return self._groups(q, f)

    def media_talkers(
        self,
        window: Window,
        hosts: tuple[str, ...],
        media_hosts: tuple[str, ...],
        media_prefixes: tuple[str, ...],
        excluded: tuple[str, ...],
    ) -> list[dict]:
        """A5: top IPs on media hosts / paths. Off when neither is configured."""
        scope = ([{"clientRequestHTTPHost_in": list(media_hosts)}] if media_hosts else []) + [
            {"clientRequestPath_like": f"{p}%"} for p in media_prefixes
        ]
        if not scope:
            return []
        f = http_filter(window, hosts)
        f["OR"] = scope
        _exclude_paths(f, excluded)
        return self._groups(groups_query(A5_MEDIA, TALKER_DIMENSIONS, TOP_TALKERS_LIMIT, with_bytes=True), f)

    def sustained_talkers(self, window: Window, hosts: tuple[str, ...], excluded: tuple[str, ...]) -> list[dict]:
        """A6: top IPs over the long window (slow crawls)."""
        f = http_filter(window, hosts)
        _exclude_paths(f, excluded)
        return self._groups(groups_query(A6_SUSTAINED, TALKER_DIMENSIONS, TOP_TALKERS_LIMIT, with_bytes=True), f)

    def error_talkers(self, window: Window, hosts: tuple[str, ...], excluded: tuple[str, ...]) -> list[dict]:
        """S1: top IPs by 4xx responses. A scanner with few requests never reaches A1's top 100."""
        f = http_filter(window, hosts)
        f["edgeResponseStatus_geq"] = 400
        f["edgeResponseStatus_lt"] = 500
        _exclude_paths(f, excluded)
        return self._groups(groups_query(S1_ERRORS, TALKER_DIMENSIONS, TOP_TALKERS_LIMIT), f)

    # --- suspicious requests ---------------------------------------------------------

    def scanner_requests(self, window: Window, hosts: tuple[str, ...]) -> list[dict]:
        """S2: requests for files and panels this stack never serves (/.env, /wp-login.php …)."""
        f = http_filter(window, hosts)
        f["OR"] = [{"clientRequestPath_like": p} for p in signatures.SCANNER_PATH_LIKES]
        return self._groups(groups_query(S2_SCANNER, SCANNER_DIMENSIONS, SCANNER_LIMIT), f)

    def tool_requests(self, window: Window, hosts: tuple[str, ...]) -> list[dict]:
        """S3: requests whose User-Agent names an attack tool (sqlmap, nuclei, ffuf …)."""
        f = http_filter(window, hosts)
        f["OR"] = [{"userAgent_like": p} for p in signatures.TOOL_UA_LIKES]
        return self._groups(groups_query(S3_TOOLS, TOOL_DIMENSIONS, TOOL_UA_LIMIT), f)

    def injection_requests(self, window: Window, hosts: tuple[str, ...], excluded: tuple[str, ...]) -> list[dict]:
        """S4: requests carrying an injection payload in the path or query string.

        Third-party callbacks are excluded: their query strings hold user ids, and the rows of
        this query are the only place a query string is ever read.
        """
        f = http_filter(window, hosts)
        f["OR"] = [{"clientRequestQuery_like": p} for p in signatures.INJECTION_QUERY_LIKES] + [
            {"clientRequestPath_like": p} for p in signatures.INJECTION_PATH_LIKES
        ]
        _exclude_paths(f, excluded)
        return self._groups(groups_query(S4_INJECTION, INJECTION_DIMENSIONS, INJECTION_LIMIT), f)

    # --- exact endpoints -------------------------------------------------------------

    def endpoint_signals(self, window: Window, hosts: tuple[str, ...], scope: list[dict]) -> list[dict]:
        """A7: payment / restricted-area calls per IP, path, method and status."""
        f = http_filter(window, hosts)
        f["OR"] = scope
        return self._groups(groups_query(A7_SIGNALS, SIGNAL_DIMENSIONS, SIGNALS_LIMIT), f)

    def purchase_talkers(self, window: Window, hosts: tuple[str, ...], scope: list[dict]) -> list[dict]:
        """A8: purchase calls per IP over the long window."""
        f = http_filter(window, hosts)
        f["OR"] = scope
        return self._groups(groups_query(A8_PURCHASES, TALKER_DIMENSIONS, TOP_TALKERS_LIMIT), f)

    def webhook_requests(self, window: Window, hosts: tuple[str, ...], prefixes: tuple[str, ...]) -> list[dict]:
        """A9: every call to a webhook / callback path, with its network and user agent."""
        start, end = window.iso()
        f = {
            "datetime_geq": start,
            "datetime_lt": end,
            "clientRequestHTTPHost_in": list(hosts),
            "OR": [{"clientRequestPath_like": like_pattern(p)} for p in prefixes],
        }
        return self._groups(groups_query(A9_WEBHOOKS, WEBHOOK_DIMENSIONS, WEBHOOK_REQUESTS_LIMIT), f)

    # --- details and Cloudflare's own verdict ----------------------------------------

    def candidate_details(self, window: Window, hosts: tuple[str, ...], ips: list[str]) -> list[dict]:
        """A2: path / method / status / network breakdown for the candidate IPs."""
        f = http_filter(window, hosts)
        f["clientIP_in"] = ips
        q = groups_query(A2_DETAILS, DETAIL_DIMENSIONS, CANDIDATE_DETAILS_LIMIT, with_bytes=True)
        return self._groups(q, f)

    def security_events(self, window: Window, hosts: tuple[str, ...]) -> list[dict]:
        """B: what the WAF, rate limiting and bot protection did (everything but `skip`)."""
        start, end = window.iso()
        return self.query(
            events_query(),
            {
                "filter": {
                    "datetime_geq": start,
                    "datetime_lt": end,
                    "clientRequestHTTPHost_in": list(hosts),
                    "action_neq": "skip",
                },
            },
        ).get("firewallEventsAdaptive") or []


def http_filter(window: Window, hosts: tuple[str, ...]) -> dict:
    start, end = window.iso()
    return {
        "datetime_geq": start,
        "datetime_lt": end,
        "clientRequestHTTPHost_in": list(hosts),
        "requestSource": "eyeball",
    }


def _exclude_paths(f: dict, excluded: tuple[str, ...]) -> None:
    if excluded:
        f["AND"] = [{"clientRequestPath_notlike": like_pattern(p)} for p in excluded]


def like_pattern(prefix: str) -> str:
    """`/api/movies/*/metadata` -> `/api/movies/%/metadata%` (prefix match, `*` = anything)."""
    return prefix.replace("*", "%") + "%"


def row_count(row: dict) -> int:
    return int(row.get("count") or 0)


def row_bytes(row: dict) -> int:
    return int((row.get("sum") or {}).get("edgeResponseBytes") or 0)
