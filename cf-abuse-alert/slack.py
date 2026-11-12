"""Slack messages (Block Kit) and delivery through an incoming webhook.

Every alert has the same shape, so the eye finds the same thing in the same place:

    🚨 [PROD] CRITICAL · Vulnerability scan · 203.0.113.7        <- header (large title)
    ┃ IP address / Network / Host / Time window / Requests / Cloudflare   <- facts, two columns
    ┃ ─────
    ┃ 🚩 Why it was flagged      one entry per rule: measured value · limit, evidence quoted below
    ┃ ─────
    ┃ 📊 What it sent            status codes, methods, user agent, table of top paths
    ┃ ─────
    ┃ 💡 What to do              one bullet per step + a WAF expression ready to paste
    ┃ links · rule ids · data caveats                                      <- small print

Rules of the layout: one topic per block, a titled section for each topic, `Label:  value` on
its own line, anything tabular in a monospace table with a header row.

`text` is what Slack puts in notifications; the header block is what shows in the channel.

Every string that comes from the request (path, user agent, ASN name) is attacker-controlled
and goes through `esc()` / `code()`: unescaped, `<!channel>` in a User-Agent would ping everyone.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote

from config import Config
from http_util import Post, post_json
from rules import Finding, SpikeFinding, by_importance, headline, max_severity
from severity import CRITICAL, WARNING
from window import Window

logger = logging.getLogger("slack")

SERVICE = "cf-abuse-alert"
COLOR = {CRITICAL: "#D72C2C", WARNING: "#F2A900", "ok": "#2EB67D", "error": "#8B0000", "info": "#4A90D9"}
EMOJI = {CRITICAL: "🚨", WARNING: "⚠️"}
DOT = {CRITICAL: "🔴", WARNING: "🟠"}
UA_MAX = 160
PATH_MAX = 64
HEADER_MAX = 150
SECTION_MAX = 2900
CONTEXT_MAX = 1900
# Lines in an overflow summary. Only the entries that are listed get marked as alerted.
SUMMARY_MAX = 30
DIVIDER = {"type": "divider"}

WHY = "🚩 *Why it was flagged*"
SENT = "📊 *What it sent*"
TODO = "💡 *What to do*"


# --- formatting helpers -----------------------------------------------------------


def esc(text: object) -> str:
    """Escape the three characters Slack treats as control characters."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def code(text: object, limit: int = UA_MAX) -> str:
    """Inline code that cannot be broken out of."""
    raw = " ".join(str(text or "").split()).replace("`", "'")
    if not raw:
        return "_none_"
    if len(raw) > limit:
        raw = raw[: limit - 1] + "…"
    return f"`{esc(raw)}`"


def mask_ip(ip: str) -> str:
    """For logs: full IPs only ever go to the private Slack channel."""
    if ":" in ip:
        return ":".join(ip.split(":")[:2]) + ":…"
    parts = ip.split(".")
    return ".".join(parts[:3] + ["x"]) if len(parts) == 4 else "ip?"


def flag(country: str | None) -> str:
    cc = (country or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha() or cc in ("XX", "T1"):
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


def num(v: float) -> str:
    return f"{v:,.2f}" if isinstance(v, float) and not v.is_integer() else f"{int(v):,}"


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def pct(part: float, whole: float) -> str:
    return f"{part / whole:.0%}" if whole else "0%"


def network(country: str | None, asn: int | None, asn_name: str = "") -> str:
    """`🇸🇬 SG · AS14061 DIGITALOCEAN-ASN`, leaving out whatever is unknown."""
    parts = []
    if country:
        parts.append(f"{flag(country)} {esc(country)}")
    if asn:
        parts.append(f"AS{asn}" + (f" {esc(asn_name[:40])}" if asn_name else ""))
    return " · ".join(parts) or "unknown"


def kv(label: str, value: str) -> str:
    """`*Label:*  value` — one fact per line."""
    return f"*{label}:*  {value}"


def table(headers: tuple[str, ...], rows: list[tuple], *, last_max: int = PATH_MAX) -> str:
    """Monospace table with a header row. Every column is right-aligned except the last."""
    cells = []
    for row in rows:
        *left, last = [" ".join(str(c).split()).replace("`", "'") for c in row]
        if len(last) > last_max:
            last = last[: last_max - 1] + "…"
        cells.append([*left, last])
    widths = [max(len(headers[i]), *(len(r[i]) for r in cells)) for i in range(len(headers) - 1)]
    lines = []
    for r in [list(headers), *cells]:
        left = "  ".join(esc(f"{r[i]:>{w}}") for i, w in enumerate(widths))
        lines.append(f"{left}  {esc(r[-1])}")
    return "```\n" + "\n".join(lines) + "\n```"


def status_codes(statuses: Counter, limit: int = 5) -> str:
    """`403` ×287 · `404` ×54 …, most frequent first."""
    items = [(c, n) for c, n in statuses.most_common() if c]
    if not items:
        return "n/a"
    out = " · ".join(f"`{c}` ×{n:,}" for c, n in items[:limit])
    return out + (f" · +{len(items) - limit} more" if len(items) > limit else "")


_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def steps(advice: str) -> list[str]:
    """Advice text split into one step per sentence."""
    return [p.strip() for p in _SENTENCE_END.split(advice.strip()) if p.strip()]


def bullets(items: list[str]) -> str:
    """One bullet per item; a single item stays a plain sentence."""
    if len(items) == 1:
        return items[0]
    return "\n".join(f"• {item}" for item in items)


_HOSTNAME = re.compile(r"^[a-z0-9.-]{1,253}$")


def waf_expression(ip: str, hosts) -> str:
    """A Cloudflare custom-rule expression matching this IP on the hosts it hit, or "" for a bad IP."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    names = sorted(h for h in hosts if _HOSTNAME.match(h))
    if not names:
        return f"(ip.src eq {addr})"
    if len(names) == 1:
        return f'(ip.src eq {addr} and http.host eq "{names[0]}")'
    quoted = " ".join(f'"{h}"' for h in names)
    return f"(ip.src eq {addr} and http.host in {{{quoted}}})"


def _local(stamp: str, tz: timezone) -> str:
    t = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone(tz)
    return f"{t:%H:%M} {tz.tzname(None)}"


# --- blocks -----------------------------------------------------------------------


def _header(text: str) -> dict:
    if len(text) > HEADER_MAX:
        text = text[: HEADER_MAX - 1] + "…"
    return {"type": "header", "text": {"type": "plain_text", "text": text, "emoji": True}}


def _section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:SECTION_MAX]}}


def _sections(title: str, lines: list[str]) -> list[dict]:
    """A titled section; lines that do not fit in one block continue in the next, never cut mid-line."""
    out, chunk, size = [], [title], len(title)
    for line in lines:
        line = line[:SECTION_MAX]
        if size + 1 + len(line) > SECTION_MAX:
            out.append(_section("\n".join(chunk)))
            chunk, size = [], -1
        chunk.append(line)
        size += 1 + len(line)
    out.append(_section("\n".join(chunk)))
    return out


def _fields(pairs: list[tuple[str, str]]) -> dict:
    return {
        "type": "section",
        "fields": [{"type": "mrkdwn", "text": f"*{label}*\n{value}"[:1900]} for label, value in pairs[:10]],
    }


def _context(*parts: str) -> dict:
    text = "  ·  ".join(p for p in parts if p)
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": text[:CONTEXT_MAX]}]}


def _wrap(text: str, color: str, blocks: list[dict], *, header: str = "", mention: str = "") -> dict:
    """`text` goes to notifications. With a `header`, the channel shows the header and then the card."""
    payload = {"text": text, "unfurl_links": False, "attachments": [{"color": color, "blocks": blocks}]}
    if header:
        payload["blocks"] = [_header(header)] + ([_section(mention.strip())] if mention.strip() else [])
    return payload


def _title(cfg_label: str, severity: str, what: str, test: bool = False) -> str:
    prefix = "🧪 *TEST* · " if test else ""
    return f"{prefix}{EMOJI[severity]} *[{esc(cfg_label)}] {severity} — {what}*"


def _head(cfg_label: str, severity: str, *parts: str, test: bool = False) -> str:
    """Plain-text header: `🚨 [PROD] CRITICAL · what · who`."""
    prefix = "🧪 TEST · " if test else ""
    return f"{prefix}{EMOJI[severity]} [{cfg_label}] " + " · ".join([severity, *[p for p in parts if p]])


def _mention(cfg: Config, severity: str, test: bool) -> str:
    return f"  {cfg.critical_mention}" if severity == CRITICAL and cfg.critical_mention and not test else ""


def _links(cfg: Config, ip: str | None = None) -> str:
    out = [f"🔎 <{cfg.dashboard_url}|Cloudflare Security Events>"]
    if ip:
        safe = quote(ip, safe=":.")
        out.append(f"<https://www.abuseipdb.com/check/{safe}|AbuseIPDB>")
        out.append(f"<https://ipinfo.io/{safe}|ipinfo>")
    return " · ".join(out)


def _counts(findings: list) -> str:
    """`4 critical · 2 warnings`."""
    by = Counter(f.severity for f in findings)
    names = ((CRITICAL, "critical", "critical"), (WARNING, "warning", "warnings"))
    return " · ".join(f"{by[s]} {one if by[s] == 1 else many}" for s, one, many in names if by[s])


# --- IP alert ---------------------------------------------------------------------


def _value(f: Finding) -> tuple[str, str]:
    if f.rule.ratio:
        return f"{f.value:.0%}", f"{f.threshold:.0%}"
    if f.rule.unit == "bytes":
        return fmt_bytes(f.value), fmt_bytes(f.threshold)
    return num(f.value), num(f.threshold)


def _measured(f: Finding, long_minutes: int) -> tuple[str, str, str]:
    value, threshold = _value(f)
    scope = f" in the last {long_minutes} min" if f.rule.long_window else ""
    return value, f"{f.rule.noun}{scope}", threshold


def _rule_entry(f: Finding, long_minutes: int) -> list[str]:
    """Two lines: what was measured against the limit, then the evidence as a quote."""
    value, noun, threshold = _measured(f, long_minutes)
    # Specific evidence (which probes, which tool, which WAF rule) beats the generic description.
    evidence = " ".join(((f.rule.detail(f.stats) if f.rule.detail else "") or f.rule.meaning).split())
    return [
        f"{DOT[f.severity]} *{f.rule.title}* — *{value}* {noun} · limit {threshold}",
        f">{esc(evidence)}",
    ]


def _known_entry(f: Finding, long_minutes: int) -> str:
    value, noun, _ = _measured(f, long_minutes)
    return f"⚪ {f.rule.title} — {value} {noun}"


def _traffic(s) -> str:
    if not s.detailed:
        return "_not in the detailed sample_"
    errors = s.status_class(4) + s.status_class(5)
    out = f"*{s.total_requests:,}* total"
    return out + (f" · {errors:,} errors ({pct(errors, s.total_requests)})" if errors else "")


def _cloudflare(s) -> str:
    if not s.cf_events:
        return "No action taken"
    out = f"🛡 Blocked *{s.cf_blocked:,}*"
    if s.detailed and s.cf_blocked:
        out += f" of {s.total_requests:,} ({s.blocked_share:.0%})"
    if s.cf_rate_limited:
        out += f" · rate-limited {s.cf_rate_limited:,}"
    return out


def _top_paths(s) -> str:
    """Titled table of the paths this IP asked for, or "" when nothing is known."""
    if s.detailed and s.paths:
        rows = [(f"{n:,}", s.path_status(p) or "-", p) for p, n in s.top_paths(6)]
        title = "*Top paths*  _(status = the most frequent answer)_"
    elif s.scanner_paths:
        rows = [(f"{n:,}", "-", p) for p, n in s.scanner_paths.most_common(6)]
        title = "*Probe paths*"
    elif s.injection_paths:
        rows = [(f"{n:,}", "-", p) for p, n in s.injection_paths.most_common(6)]
        title = "*Paths that received payloads*"
    else:
        return ""
    return f"{title}\n{table(('REQS', 'STATUS', 'PATH'), rows)}"


def _extras(s, window_minutes: int, long_minutes: int) -> list[str]:
    out = []
    if s.detailed and s.bytes:
        avg = f", {fmt_bytes(s.bytes / s.total_requests)}/request" if s.total_requests else ""
        out.append(kv("Downloaded", f"{fmt_bytes(s.bytes)} in {window_minutes} min{avg}"))
        by_bytes = s.top_paths_by_bytes()
        if by_bytes and s.bytes >= 100 * 1024**2:
            out.append(kv("Heaviest paths", " · ".join(f"{code(p, PATH_MAX)} {fmt_bytes(b)}" for p, b in by_bytes)))
    if s.media_requests:
        out.append(kv("Media", f"{s.media_requests:,} requests in {window_minutes} min"))
    if s.sustained_requests:
        out.append(kv(f"Last {long_minutes} min", f"{s.sustained_requests:,} requests · {fmt_bytes(s.sustained_bytes)}"))
    pay = _payments(s, long_minutes)
    if pay:
        out.append(kv("Payments", pay))
    return out


def _payments(s, long_minutes: int) -> str:
    p = s.signals
    parts = []
    purchases, failed, limited = p.get("purchases", 0), p.get("purchase_failures", 0), p.get("payment_rate_limited", 0)
    if purchases:
        parts.append(f"{purchases:,} purchase calls ({failed:,} failed)")
    if p.get("iap_failures"):
        parts.append(f"{p['iap_failures']:,} rejected IAP receipts")
    if limited:
        parts.append(f"{limited:,} rate-limited")
    if p.get("card_changes"):
        parts.append(f"{p['card_changes']:,} card changes")
    if p.get("purchase_checks"):
        parts.append(f"{p['purchase_checks']:,} check-purchase calls")
    if s.purchases_1h:
        parts.append(f"{s.purchases_1h:,} purchase calls in {long_minutes} min")
    return " · ".join(parts)


def _sent(s, window_minutes: int, long_minutes: int) -> list[dict]:
    """The "What it sent" blocks: facts one per line, then the path table."""
    lines = []
    if s.detailed:
        lines.append(kv("Status codes", status_codes(s.statuses)))
    if s.methods:
        total = sum(s.methods.values())
        lines.append(kv("Methods", " · ".join(f"{m} {pct(n, total)}" for m, n in s.methods.most_common(3))))
    if s.user_agent or s.methods:
        lines.append(kv("User agent", code(s.user_agent)))
    lines += _extras(s, window_minutes, long_minutes)
    paths = _top_paths(s)
    if not lines and not paths:
        return []
    blocks = _sections(SENT, lines) if lines else []
    if paths:
        blocks.append(_section(paths if lines else f"{SENT}\n{paths}"))
    return blocks


def _todo(top: Finding, expression: str) -> list[dict]:
    s = top.stats
    lines = []
    if s.detailed and s.cf_blocked and s.blocked_share >= 0.9:
        lines.append(f"_Cloudflare already stopped {s.blocked_share:.0%} of this IP's requests._")
    lines.append(bullets(steps(top.rule.advice)))
    blocks = _sections(TODO, lines)
    if expression:
        blocks.append(_section(f"*WAF expression for this IP*  _(if you decide to block)_\n```\n{expression}\n```"))
    return blocks


def build_ip_alert(
    cfg: Config,
    window: Window,
    findings: list[Finding],
    fresh: list[Finding] | None = None,
    *,
    first_seen: str | None = None,
    test: bool = False,
) -> dict:
    """One message per IP: every rule it tripped, new ones first."""
    s = findings[0].stats
    ip = findings[0].ip
    severity = max_severity(findings)
    fresh_ids = {f.rule.id for f in (findings if fresh is None else fresh)}
    new = by_importance([f for f in findings if f.rule.id in fresh_ids])
    known = by_importance([f for f in findings if f.rule.id not in fresh_ids])
    top = headline(new or findings)
    long_minutes = cfg.sustained_window_minutes
    mention = _mention(cfg, severity, test)

    text = _title(cfg.environment_label, severity, f"{top.rule.title} from", test) + f" `{esc(ip)}`" + mention
    head = _head(cfg.environment_label, severity, top.rule.title, ip, test=test)

    blocks = [
        _fields(
            [
                ("IP address", f"`{esc(ip)}`"),
                ("Network", network(s.country, s.asn, s.asn_name)),
                ("Host", esc(", ".join(sorted(s.hosts)) or "n/a")),
                (f"Time window ({window.minutes} min)", window.label(cfg.display_tz)),
                ("Requests", _traffic(s)),
                ("Cloudflare", _cloudflare(s)),
            ]
        ),
        DIVIDER,
    ]

    why = [line for f in new for line in _rule_entry(f, long_minutes)]
    if known:
        since = f" — first flagged {_local(first_seen, cfg.display_tz)}" if first_seen else ""
        why.append(f"⏱ _Still active{since}. Already alerted and still over the limit:_")
        why += [_known_entry(f, long_minutes) for f in known]
    blocks += _sections(f"{WHY}  ·  {esc(top.rule.category)}  ·  {_counts(findings)}", why)

    sent = _sent(s, window.minutes, long_minutes)
    if sent:
        blocks += [DIVIDER, *sent]

    blocks += [DIVIDER, *_todo(top, waf_expression(ip, s.hosts))]

    notes = ["counts are sampled estimates"]
    if s.truncated:
        notes.append("breakdown truncated (row limit reached)")
    if test:
        notes = ["made-up data, sent by --test-alert"]
    rule_ids = " ".join(f"`{f.rule.id}`" for f in new + known)
    blocks.append(_context(_links(cfg, ip)))
    blocks.append(_context(f"Rules: {rule_ids}", "ℹ️ " + ", ".join(notes)))

    return _wrap(text, COLOR[severity], blocks, header=head, mention=mention)


# --- many IPs at once -------------------------------------------------------------


def build_summary(cfg: Config, window: Window, rest: list[list[Finding]]) -> dict:
    """IPs beyond MAX_ALERTS_PER_RUN, one line each."""
    severity = max_severity([f for g in rest for f in g])
    lines = []
    for g in rest[:SUMMARY_MAX]:
        s, top = g[0].stats, headline(g)
        more = f" +{len(g) - 1} more" if len(g) > 1 else ""
        lines.append(
            f"{DOT[max_severity(g)]} `{esc(g[0].ip)}`  ·  *{top.rule.title}*{more}  ·  {network(s.country, s.asn)}"
        )
    if len(rest) > SUMMARY_MAX:
        lines.append(f"… and {len(rest) - SUMMARY_MAX} more, reported on the next run if still active")
    text = f"{EMOJI[severity]} *[{esc(cfg.environment_label)}] {len(rest)} more IPs over a threshold*"
    head = f"{EMOJI[severity]} [{cfg.environment_label}] {len(rest)} more IPs over a threshold"
    blocks = [
        _fields(
            [
                (f"Time window ({window.minutes} min)", window.label(cfg.display_tz)),
                ("IPs in this list", f"*{len(rest)}*  ·  {_counts([headline(g) for g in rest])}"),
            ]
        ),
        DIVIDER,
        *_sections("📋 *IP  ·  main rule  ·  network*", lines),
        _context(_links(cfg), f"ℹ️ condensed: more than {cfg.max_alerts_per_run} IPs in one run"),
    ]
    return _wrap(text, COLOR[severity], blocks, header=head)


SPIKE_ADVICE = (
    "Check Cloudflare's own DDoS alerts and the zone's traffic trend. If the origin is struggling, add a "
    "rate-limiting rule or block the dominant network/country for the host."
)


def build_spike(cfg: Config, window: Window, spike: SpikeFinding, *, test: bool = False) -> dict:
    countries: Counter = Counter()
    asns: Counter = Counter()
    for s in spike.ips:
        countries[s.country or "unknown"] += 1
        asns[f"AS{s.asn}" if s.asn else "unknown"] += 1
    mention = _mention(cfg, spike.severity, test)
    text = _title(
        cfg.environment_label,
        spike.severity,
        f"Distributed spike: {spike.ip_count} IPs each sent {num(spike.per_ip)}+ requests",
        test,
    ) + mention
    head = _head(cfg.environment_label, spike.severity, "Distributed spike", f"{spike.ip_count} IPs", test=test)
    total = sum(s.total_requests for s in spike.ips)
    facts = _fields(
        [
            ("IPs over the limit", f"*{spike.ip_count}* IPs with {num(spike.per_ip)}+ requests each · limit {num(spike.threshold)} IPs"),
            (f"Time window ({window.minutes} min)", window.label(cfg.display_tz)),
            ("Requests from them", f"*{total:,}* total"),
            ("Host", esc(", ".join(sorted({h for s in spike.ips for h in s.hosts})) or "n/a")),
            ("Countries", " · ".join(f"{flag(k)} {esc(k)} ×{v}" for k, v in countries.most_common(5))),
            ("Networks", " · ".join(f"{esc(k)} ×{v}" for k, v in asns.most_common(5))),
        ]
    )
    rows = [(f"{s.total_requests:,}", (s.country or "-")[:3], s.ip) for s in spike.ips[:10]]
    notes = "made-up data, sent by --test-alert" if test else "counts are sampled estimates"
    blocks = [
        facts,
        DIVIDER,
        _section(f"📊 *Top IPs*\n{table(('REQS', 'FROM', 'IP'), rows)}"),
        DIVIDER,
        *_sections(TODO, [bullets(steps(SPIKE_ADVICE))]),
        _context(_links(cfg)),
        _context("Rules: `distributed_spike`", f"ℹ️ {notes}"),
    ]
    return _wrap(text, COLOR[spike.severity], blocks, header=head, mention=mention)


# --- webhooks ---------------------------------------------------------------------

WEBHOOK_TITLES = {
    "webhook_rejected": "calls keep being rejected",
    "webhook_unknown_path": "call to a webhook path with no profile",
    "webhook_unknown_asn": "call from an unknown network",
    "webhook_unknown_ua": "call with an unexpected user agent",
    "webhook_new_ip": "traffic from a new IP",
}


def _webhook_hint(finding) -> str:
    t = finding.traffic
    if finding.rule_id == "webhook_rejected":
        return (
            "If the source is the real provider, its secret/signature is out of sync or the WAF is blocking it: "
            "events are being lost, fix it now. If not, someone is forging calls; the server is refusing them."
        )
    if finding.rule_id == "webhook_new_ip":
        return "If the provider rotated IPs, add this IP to `webhook_sources.json`. Otherwise check the server logs for this IP."
    if t.ok:
        return "The server *accepted* these calls (2xx): check the signature/guard of this webhook now."
    return "The server rejected these calls; likely probing. Block the IP at the WAF if it continues."


def build_webhook_alert(cfg: Config, window: Window, finding, *, test: bool = False) -> dict:
    t = finding.traffic
    src = finding.source
    sev = finding.severity
    what = f"{finding.provider} webhook: {WEBHOOK_TITLES.get(finding.rule_id, finding.rule_id)}"
    mention = _mention(cfg, sev, test)
    text = _title(cfg.environment_label, sev, esc(what), test) + f" · `{esc(t.ip)}`" + mention
    head = _head(cfg.environment_label, sev, what, t.ip, test=test)

    facts = _fields(
        [
            ("IP address", f"`{esc(t.ip)}`"),
            ("Network", network(t.country, t.asn, t.asn_name)),
            ("Webhook", f"{esc(finding.provider)} · {code(t.path, PATH_MAX)}"),
            (f"Time window ({window.minutes} min)", window.label(cfg.display_tz)),
            ("Calls", f"*{t.count:,}* total · {status_codes(t.statuses)}"),
            ("Host", esc(", ".join(sorted(t.hosts)) or "n/a")),
        ]
    )
    # "14 calls answered 400/401/403 (signature … failed)" -> a bold finding and its explanation.
    reason, _, explanation = finding.reason.partition(" (")
    why = [f"{DOT[sev]} *{esc(reason[0].upper() + reason[1:])}*"]
    if explanation:
        explanation = explanation.rstrip(")")
        why.append(f">{esc(explanation[0].upper() + explanation[1:])}")

    caller = [kv("User agent", code(t.user_agent or "(empty)"))]
    if src is not None:
        expected_ua = ", ".join(code(u or "(empty)", 60) for u in src.user_agents) or "any"
        ips = "any IP" if src.ips is None else f"{len(src.ips)} known IPs/ranges" + (" (official list)" if src.strict else "")
        asns = ", ".join(f"AS{a}" for a in sorted(src.asns)) or "any network"
        caller.append(kv(f"Expected for {esc(src.name)}", f"{asns} · UA {expected_ua} · {ips}"))
    if finding.looks_like:
        caller.append(kv("Sender looks like", esc(", ".join(finding.looks_like))))
    if finding.history:
        h = finding.history
        caller.append(
            kv(
                "New-IP activity",
                f"{h['window']:,} calls this window · {h['streak']} windows in a row · "
                f"{h['hourly']:,} calls in the last 60 min",
            )
        )
    notes = "made-up data, sent by --test-alert" if test else "counts are sampled estimates"
    blocks = [
        facts,
        DIVIDER,
        *_sections(WHY, why),
        DIVIDER,
        *_sections("🔍 *Who is calling*", caller),
        DIVIDER,
        *_sections(TODO, [bullets(steps(_webhook_hint(finding)))]),
        _context(_links(cfg, t.ip)),
        _context(f"Rules: `{finding.rule_id}`", f"ℹ️ {notes}"),
    ]
    return _wrap(text, COLOR[sev], blocks, header=head, mention=mention)


def build_webhook_summary(cfg: Config, window: Window, rest: list) -> dict:
    """Webhook findings beyond MAX_ALERTS_PER_RUN, one line each."""
    severity = CRITICAL if any(f.severity == CRITICAL for f in rest) else WARNING
    lines = [
        f"{DOT[f.severity]} `{esc(f.ip)}`  ·  *{esc(f.provider)}* {code(f.traffic.path, PATH_MAX)}  ·  "
        f"{f.traffic.count:,} calls  ·  {WEBHOOK_TITLES.get(f.rule_id, f.rule_id)}"
        for f in rest[:SUMMARY_MAX]
    ]
    if len(rest) > SUMMARY_MAX:
        lines.append(f"… and {len(rest) - SUMMARY_MAX} more, reported on the next run if still active")
    title = f"{len(rest)} more webhook callers flagged"
    blocks = [
        _fields(
            [
                (f"Time window ({window.minutes} min)", window.label(cfg.display_tz)),
                ("Callers in this list", f"*{len(rest)}*  ·  {_counts(rest)}"),
            ]
        ),
        DIVIDER,
        *_sections("📋 *IP  ·  webhook  ·  calls  ·  why*", lines),
        _context(_links(cfg), f"ℹ️ condensed: more than {cfg.max_alerts_per_run} webhook alerts in one run"),
    ]
    return _wrap(
        f"{EMOJI[severity]} *[{esc(cfg.environment_label)}] {title}*",
        COLOR[severity],
        blocks,
        header=f"{EMOJI[severity]} [{cfg.environment_label}] {title}",
    )


# --- service status ---------------------------------------------------------------


def build_failure(label: str, error: str, failures: int, last_success: str | None) -> dict:
    text = f"⚠️ *[{esc(label)}] {SERVICE} is failing* — {failures} runs in a row. Nothing is being watched."
    blocks = [
        _fields(
            [
                ("Failed runs in a row", f"*{failures}*"),
                ("Last successful run", esc(last_success or "never")),
                ("Error", code(error, 300)),
                ("Effect", "Nothing is being watched"),
            ]
        ),
        DIVIDER,
        *_sections(
            "🔧 *Common causes*",
            [
                "• `403` — the Cloudflare token expired or lost Analytics → Read",
                "• `429` — GraphQL quota used up",
                "• `config invalid` — a required environment variable is missing or wrong",
            ],
        ),
    ]
    return _wrap(text, COLOR["error"], blocks, header=f"⚠️ [{label}] {SERVICE} is failing")


def build_degraded(label: str, problems: list[tuple[str, str, int]]) -> dict:
    text = f"⚠️ *[{esc(label)}] {SERVICE} is partly blind* — some Cloudflare queries keep failing"
    lines = [f"• `{esc(name)}` — {streak} runs in a row\n>{code(error, 200)}" for name, error, streak in problems]
    blocks = [
        *_sections("🚩 *Queries that keep failing*", lines),
        DIVIDER,
        *_sections(TODO, ["The rules fed by these queries cannot fire until this is fixed. Run `python cf_probe.py`."]),
    ]
    return _wrap(text, COLOR[WARNING], blocks, header=f"⚠️ [{label}] {SERVICE} is partly blind")


def build_recovered(label: str) -> dict:
    return _wrap(
        f"✅ *[{esc(label)}] {SERVICE} is working again*",
        COLOR["ok"],
        [_context("Monitoring has resumed. Traffic during the outage was not checked.")],
    )


def build_heartbeat(cfg: Config, runs: int, alerts: int, failed_runs: int, last_success: str | None) -> dict:
    text = f"💚 *[{esc(cfg.environment_label)}] {SERVICE} is watching*"
    ok = _local(last_success, cfg.display_tz) if last_success else "n/a"
    blocks = [
        _fields(
            [
                ("Since the last heartbeat", f"{runs:,} runs · {failed_runs:,} failed · {alerts:,} alerts sent"),
                ("Last successful run", ok),
            ]
        ),
        _context(f"hosts: {esc(', '.join(cfg.monitor_hosts))}", "dry run" if cfg.dry_run else ""),
    ]
    return _wrap(text, COLOR["ok"], blocks)


def build_started(cfg: Config, rule_count: int, webhook_profiles: int) -> dict:
    text = f"🟢 *[{esc(cfg.environment_label)}] {SERVICE} started*"
    blocks = [
        _fields(
            [
                ("Watching", esc(", ".join(cfg.monitor_hosts))),
                ("Schedule", f"every {cfg.window_minutes} min · data lag {cfg.ingest_lag_minutes} min"),
                ("Rules", f"{rule_count} active · thresholds ×{cfg.threshold_multiplier:g}"),
                ("Webhook profiles", str(webhook_profiles) if webhook_profiles else "none (only `webhook_rejected`)"),
            ]
        ),
    ]
    return _wrap(text, COLOR["info"], blocks)


# --- delivery ---------------------------------------------------------------------


class Sender:
    """Posts to the incoming webhook. One instance per tick.

    A post that fails on something temporary (timeout, network, 429, 5xx) is tried again after
    `retry_delays`. After `give_up_after` messages in a row could not be delivered, the rest of
    the tick is not attempted: with Slack down, 30 messages × 3 attempts × 10 s would otherwise
    make the tick overrun. `send` never raises.
    """

    retry_delays: tuple[float, ...] = (1.0, 3.0)
    give_up_after = 2
    timeout = 10

    def __init__(self, webhook_url: str, *, dry_run: bool, post: Post = post_json) -> None:
        self._url = webhook_url
        self._dry_run = dry_run
        self._post = post
        self._failed_in_a_row = 0
        self.undelivered = 0

    def send(self, payload: dict, summary: str) -> bool:
        """True when Slack accepted the message (or in dry run). `summary` is the masked log line."""
        if self._dry_run:
            logger.info("[DRY_RUN] %s", summary)
            return True
        if not self._url:
            logger.error("no SLACK_WEBHOOK_URL — dropped: %s", summary)
            self.undelivered += 1
            return False
        if self._failed_in_a_row >= self.give_up_after:
            logger.error("slack unavailable — not sent: %s", summary)
            self.undelivered += 1
            return False
        if self._attempt(payload):
            self._failed_in_a_row = 0
            return True
        self._failed_in_a_row += 1
        self.undelivered += 1
        logger.error("slack: gave up — not sent: %s", summary)
        return False

    def _attempt(self, payload: dict) -> bool:
        for delay in (0.0, *self.retry_delays):
            if delay:
                time.sleep(delay)
            try:
                status, body = self._post(self._url, {}, payload, self.timeout)
            except (TimeoutError, OSError) as e:
                # post_json's messages never contain the URL.
                logger.error("slack failed: %s", e)
                continue
            except Exception as e:  # noqa: BLE001 — a custom `post` may raise anything; the text may hold the URL
                logger.error("slack failed: %s", type(e).__name__)
                return False
            if status == 200 and body.strip() == b"ok":
                return True
            logger.error("slack failed: HTTP %s %s", status, body[:100].decode("utf-8", "replace"))
            if status != 429 and status < 500:
                return False  # the payload or the webhook itself is refused: retrying cannot help
        return False
