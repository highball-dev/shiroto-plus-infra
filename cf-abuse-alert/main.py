"""cf-abuse-alert: every few minutes, read Cloudflare analytics for the monitored hosts, find the
IPs that look like an attack, and post them to Slack.

One tick:  queries -> per-IP stats -> candidates -> detailed breakdown -> rules -> dedupe -> Slack
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

import cf_graphql as q
import config
import endpoints
import signatures
import state
import webhooks
from aggregate import CandidateThresholds, add_details, collect, normalize_ip, pick_candidates
from cf_graphql import GraphQLClient, GraphQLError, row_count
from health import Health
from health import serve as serve_health
from http_util import Post, post_json
from rules import (
    LONG_OVERLAPS,
    RULES,
    SPIKE_RULE_ID,
    candidate_error_threshold,
    candidate_request_threshold,
    candidate_sensitive_threshold,
    candidate_volume_threshold,
    early_score,
    evaluate,
    evaluate_spike,
    group_by_ip,
    headline,
    max_severity,
    warning_threshold,
)
from slack import (
    SUMMARY_MAX,
    Sender,
    build_degraded,
    build_failure,
    build_heartbeat,
    build_ip_alert,
    build_recovered,
    build_spike,
    build_started,
    build_summary,
    build_webhook_alert,
    build_webhook_summary,
    mask_ip,
)
from window import Window, compute_window, floor_to_period

logger = logging.getLogger("main")

SPIKE_KEY_IP = "*"
HEALTH_GRACE_SECONDS = 600
FIRST_SEEN_TTL = 7200
STARTED_TTL = 600
# A tick that overran is followed at once by the windows it delayed, up to this many.
MAX_CATCH_UP_TICKS = 2

# Without these two a tick has nothing to work with and counts as failed.
CORE_QUERIES = (q.A1_TOP, q.B_EVENTS)
# Each of these feeds a few rules. If one fails, the tick still runs and reports it as degraded.
OPTIONAL_QUERIES = (
    q.A3_SENSITIVE,
    q.A4_BYTES,
    q.A5_MEDIA,
    q.A6_SUSTAINED,
    q.A7_SIGNALS,
    q.A8_PURCHASES,
    q.A9_WEBHOOKS,
    q.S1_ERRORS,
    q.S2_SCANNER,
    q.S3_TOOLS,
    q.S4_INJECTION,
)


@dataclass
class TickResult:
    ok: bool
    window: str = ""
    candidates: int = 0
    findings: int = 0
    sent: int = 0
    suppressed: int = 0
    undelivered: int = 0  # messages Slack did not take, after retries
    error: str = ""
    degraded: dict[str, str] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)


def error_kind(e: Exception) -> str:
    """A short error description that is safe to log and to post: never a token or a body."""
    if isinstance(e, config.ConfigError):
        return f"config invalid: {e}"
    if isinstance(e, GraphQLError):
        return str(e)
    return type(e).__name__


def run_tick(
    scheduled: datetime,
    *,
    store: state.Store,
    post: Post = post_json,
    load_config: Callable[[], config.Config] = config.load,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> TickResult:
    cfg: config.Config | None = None
    try:
        cfg = load_config()
        return _tick(cfg, scheduled, store=store, post=post, now=now())
    except Exception as e:
        kind = error_kind(e)
        failures = state.record_failure(store)
        store.incr("stats:failedRuns")
        known = isinstance(e, (config.ConfigError, GraphQLError))
        logger.error("tick %s failed (%d in a row): %s", f"{scheduled:%H:%M}Z", failures, kind, exc_info=not known)

        try:
            if state.failure_alert_due(store, failures):
                _report_failure(cfg, store, post, kind, failures, now())
        except Exception as report_error:  # noqa: BLE001 — reporting a failure must never end the loop
            logger.error("could not report the failure to Slack: %s", type(report_error).__name__)
        return TickResult(ok=False, error=kind)


def _report_failure(cfg: config.Config | None, store: state.Store, post: Post, kind: str, failures: int, now: datetime) -> None:
    if cfg:
        label, url, dry = cfg.environment_label, cfg.slack_webhook_url, cfg.dry_run
    else:
        # The config itself is what failed: read the three values directly.
        label, url = config.env("ENVIRONMENT_LABEL", "NON-PROD"), config.env("SLACK_WEBHOOK_URL")
        try:
            dry = config.env_bool("DRY_RUN", False)
        except config.ConfigError:
            dry = True  # an unreadable DRY_RUN must not turn into real posts
    sender = Sender(url, dry_run=dry, post=post)
    if sender.send(build_failure(label, kind, failures, store.get("health:lastSuccess")), f"failure alert: {kind}"):
        state.mark_failure_alerted(store, now)


def _fetch(cfg: config.Config, gql: GraphQLClient, window: Window, long_window: Window) -> tuple[dict, dict]:
    """Run the tick's queries in parallel. Returns (rows per query, error per failed optional query)."""
    hosts = cfg.query_hosts
    excluded = cfg.excluded_path_prefixes
    calls: dict[str, Callable[[], list[dict]]] = {
        q.A1_TOP: lambda: gql.top_talkers(window, hosts),
        q.B_EVENTS: lambda: gql.security_events(window, hosts),
        q.A3_SENSITIVE: lambda: gql.sensitive_talkers(
            window, hosts, endpoints.all_sensitive_prefixes(), cfg.sensitive_methods
        ),
        q.A4_BYTES: lambda: gql.top_bytes(window, hosts, excluded),
        q.A5_MEDIA: lambda: gql.media_talkers(window, hosts, cfg.media_hosts, cfg.media_path_prefixes, excluded),
        q.A6_SUSTAINED: lambda: gql.sustained_talkers(long_window, hosts, excluded),
        q.A7_SIGNALS: lambda: gql.endpoint_signals(window, hosts, endpoints.signal_filters()),
        q.A8_PURCHASES: lambda: gql.purchase_talkers(long_window, hosts, endpoints.purchase_filters()),
        q.A9_WEBHOOKS: lambda: (
            gql.webhook_requests(window, hosts, cfg.webhook_prefixes) if cfg.webhook_prefixes else []
        ),
        q.S1_ERRORS: lambda: gql.error_talkers(window, hosts, excluded),
        q.S2_SCANNER: lambda: gql.scanner_requests(window, hosts),
        q.S3_TOOLS: lambda: gql.tool_requests(window, hosts),
        q.S4_INJECTION: lambda: gql.injection_requests(window, hosts, excluded),
    }
    rows: dict[str, list[dict]] = {}
    failed: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {name: pool.submit(call) for name, call in calls.items()}
        for name, future in futures.items():
            try:
                rows[name] = future.result()
            except Exception as e:  # noqa: BLE001 — an optional query never fails the tick
                if name in CORE_QUERIES:
                    raise
                rows[name] = []
                failed[name] = error_kind(e)
    return rows, failed


def _tick(cfg: config.Config, scheduled: datetime, *, store: state.Store, post: Post, now: datetime) -> TickResult:
    window = compute_window(scheduled, lag_minutes=cfg.ingest_lag_minutes, window_minutes=cfg.window_minutes)
    long_window = Window(window.end - timedelta(minutes=cfg.sustained_window_minutes), window.end)
    gql = GraphQLClient(
        token=cfg.cf_api_token,
        zone_tag=cfg.cf_zone_tag,
        url=cfg.graphql_url,
        timeout=cfg.graphql_timeout_seconds,
        post=post,
    )
    sender = Sender(cfg.slack_webhook_url, dry_run=cfg.dry_run, post=post)
    mult = cfg.threshold_multiplier
    result = TickResult(ok=True, window=window.label(cfg.display_tz))

    rows, failed = _fetch(cfg, gql, window, long_window)
    result.degraded = failed
    for name, error in failed.items():
        logger.warning("tick %s: query %s failed, its rules are blind this run: %s", f"{scheduled:%H:%M}Z", name, error)

    # ---- per-IP stats --------------------------------------------------------------
    purchases_1h: Counter = Counter()
    for r in rows[q.A8_PURCHASES]:  # one row per (IP, host)
        purchases_1h[normalize_ip((r.get("dimensions") or {}).get("clientIP", ""))] += row_count(r)
    purchases_1h.pop("", None)
    stats = collect(
        top_rows=rows[q.A1_TOP],
        error_rows=rows[q.S1_ERRORS],
        sensitive_rows=rows[q.A3_SENSITIVE],
        bytes_rows=rows[q.A4_BYTES],
        media_rows=rows[q.A5_MEDIA],
        sustained_rows=rows[q.A6_SUSTAINED],
        signal_counts=endpoints.counters(rows[q.A7_SIGNALS], normalize_ip),
        purchases_1h=purchases_1h,
        scanner_rows=rows[q.S2_SCANNER],
        tool_rows=rows[q.S3_TOOLS],
        injection_rows=rows[q.S4_INJECTION],
        events=rows[q.B_EVENTS],
        excluded_prefixes=cfg.excluded_path_prefixes,
        block_actions=cfg.block_actions,
        rate_limit_sources=cfg.rate_limit_sources,
    )

    candidates = pick_candidates(
        stats,
        CandidateThresholds(
            requests=candidate_request_threshold(mult),
            volume=candidate_volume_threshold(mult),
            errors=candidate_error_threshold(mult),
            sensitive=candidate_sensitive_threshold(mult),
            events=warning_threshold("cf_blocked", mult),
            bytes=warning_threshold("high_bytes", mult),
            media=warning_threshold("media_requests", mult) if cfg.media_enabled else float("inf"),
            sustained=warning_threshold("sustained_requests", mult),
        ),
        allowlist=cfg.allowlist,
        limit=cfg.max_candidates,
        early_score=lambda s: early_score(s, mult, cfg.disabled_rules),
    )
    details = gql.candidate_details(window, cfg.query_hosts, candidates) if candidates else []
    truncated = len(details) >= q.CANDIDATE_DETAILS_LIMIT
    add_details(
        stats,
        details,
        excluded_prefixes=cfg.excluded_path_prefixes,
        api_prefixes=cfg.api_path_prefixes,
        media_hosts=cfg.media_hosts,
        media_prefixes=cfg.media_path_prefixes,
        sensitive_methods=cfg.sensitive_methods,
        truncated=truncated,
    )

    # ---- rules ---------------------------------------------------------------------
    findings = evaluate(stats, mult, cfg.allowlist, trusted_asns=cfg.trusted_asns, disabled=cfg.disabled_rules)
    findings = _drop_reported_bursts(findings, store, mult, cfg.sustained_window_minutes * 60)
    spike = None
    if SPIKE_RULE_ID not in cfg.disabled_rules:
        spike = evaluate_spike(stats, mult, cfg.allowlist, trusted_asns=cfg.trusted_asns)
    result.candidates = len(candidates)
    result.findings = len(findings) + (1 if spike else 0)

    # ---- dedupe: one message per IP, only when it has something new -----------------
    groups = []
    for group in group_by_ip(findings):
        fresh = [f for f in group if state.should_alert(store, f.ip, f.rule.id, f.severity)]
        result.suppressed += len(group) - len(fresh)
        if fresh:
            groups.append((group, fresh))

    def mark(fresh) -> None:
        for f in fresh:
            state.mark_alerted(store, f.ip, f.rule.id, f.severity, f.rule.dedupe_ttl or cfg.dedupe_ttl_seconds)
        state.first_seen(store, fresh[0].ip, now, FIRST_SEEN_TTL)

    detailed, rest = groups[: cfg.max_alerts_per_run], groups[cfg.max_alerts_per_run :]
    for group, fresh in detailed:
        ip = group[0].ip
        summary = f"[{max_severity(group)}] {mask_ip(ip)} {headline(fresh).rule.title}: " + ", ".join(
            f"{f.rule.id}={f.value:g}" for f in fresh
        )
        if len(group) > len(fresh):
            summary += f" (+{len(group) - len(fresh)} already alerted)"
        result.messages.append(summary)
        only_long = all(f.rule.long_window for f in group)
        payload = build_ip_alert(
            cfg,
            long_window if only_long else window,
            group,
            fresh=fresh,
            first_seen=state.peek_first_seen(store, ip),
        )
        if sender.send(payload, summary):
            mark(fresh)
            result.sent += 1
    if rest:
        summary = f"summary: +{len(rest)} IPs"
        result.messages.append(summary)
        if sender.send(build_summary(cfg, window, [group for group, _ in rest]), summary):
            # IPs past SUMMARY_MAX are not named, so they stay unmarked and come back next run.
            for _, fresh in rest[:SUMMARY_MAX]:
                mark(fresh)
            result.sent += 1

    if spike and state.should_alert(store, SPIKE_KEY_IP, SPIKE_RULE_ID, spike.severity):
        summary = f"[{spike.severity}] {SPIKE_RULE_ID}: {spike.ip_count} IPs"
        result.messages.append(summary)
        if sender.send(build_spike(cfg, window, spike), summary):
            state.mark_alerted(store, SPIKE_KEY_IP, SPIKE_RULE_ID, spike.severity, cfg.dedupe_ttl_seconds)
            result.sent += 1

    # ---- webhooks ------------------------------------------------------------------
    profiles = webhooks.load_profiles(cfg.webhook_sources_file)
    webhook_findings = webhooks.evaluate(
        rows[q.A9_WEBHOOKS],
        profiles,
        store=store,
        tick=scheduled,
        period_minutes=cfg.window_minutes,
        thresholds=webhooks.Thresholds(
            cfg.webhook_new_ip_burst,
            cfg.webhook_new_ip_streak,
            cfg.webhook_new_ip_hourly,
            webhooks.REJECTED_WARNING * mult,
            webhooks.REJECTED_CRITICAL * mult,
        ),
        allowlist=cfg.allowlist,
        disabled=cfg.disabled_rules,
    )
    result.findings += len(webhook_findings)
    new_webhooks = [wf for wf in webhook_findings if state.should_alert(store, wf.ip, wf.dedupe_rule, wf.severity)]
    result.suppressed += len(webhook_findings) - len(new_webhooks)

    def mark_webhook(wf) -> None:
        state.mark_alerted(store, wf.ip, wf.dedupe_rule, wf.severity, webhooks.DEDUPE_TTL[wf.rule_id])

    for wf in new_webhooks[: cfg.max_alerts_per_run]:
        # The path is the client's: redacted like everything else that is logged.
        path = signatures.safe_path(wf.traffic.path, 60)
        summary = f"[{wf.severity}] {wf.rule_id} {path} {mask_ip(wf.ip)} n={wf.traffic.count}"
        result.messages.append(summary)
        if sender.send(build_webhook_alert(cfg, window, wf), summary):
            mark_webhook(wf)
            result.sent += 1
    more_webhooks = new_webhooks[cfg.max_alerts_per_run :]
    if more_webhooks:
        summary = f"summary: +{len(more_webhooks)} webhook callers"
        result.messages.append(summary)
        if sender.send(build_webhook_summary(cfg, window, more_webhooks), summary):
            for wf in more_webhooks[:SUMMARY_MAX]:
                mark_webhook(wf)
            result.sent += 1

    # ---- the watcher's own health ----------------------------------------------------
    if state.record_success(store, now):
        sender.send(build_recovered(cfg.environment_label), "recovered")
    due = state.record_query_health(store, list(OPTIONAL_QUERIES), failed)
    if due and sender.send(build_degraded(cfg.environment_label, due), f"degraded: {','.join(n for n, _, _ in due)}"):
        for name, _, _ in due:
            state.mark_query_alerted(store, name, now)
    runs = store.incr("stats:runs")
    alerts = store.incr("stats:alerts", result.sent)
    if state.heartbeat_due(store, now, cfg.heartbeat_hour_utc):
        failed_runs = int(store.get("stats:failedRuns") or 0)
        payload = build_heartbeat(cfg, runs, alerts, failed_runs, store.get("health:lastSuccess"))
        if sender.send(payload, "heartbeat"):
            state.mark_heartbeat(store, now)

    result.undelivered = sender.undelivered
    if result.undelivered:
        logger.error(
            "tick %s: %d message(s) could not be delivered to Slack — they are not marked as alerted and "
            "are sent again next run only if the IP is still over a threshold",
            f"{scheduled:%H:%M}Z",
            result.undelivered,
        )

    counts = " ".join(f"{name.split('_')[0]}={len(rows[name])}" for name in (*CORE_QUERIES, *OPTIONAL_QUERIES))
    logger.info(
        "tick %s ok: window %s · %s%s%s · candidates=%d · findings=%d · sent=%d · deduped=%d%s",
        f"{scheduled:%H:%M}Z",
        result.window,
        counts,
        " (A2 truncated)" if truncated else "",
        f" · DEGRADED {','.join(failed)}" if failed else "",
        len(candidates),
        result.findings,
        result.sent,
        result.suppressed,
        f" · UNDELIVERED={result.undelivered}" if result.undelivered else "",
    )
    return result


def _drop_reported_bursts(findings: list, store: state.Store, mult: float, ttl: int) -> list:
    """Drop a long-window finding whose traffic is a burst that a burst rule already reported.

    `evaluate` handles the tick in which the burst happens. On the following ticks the burst is
    still inside the long window but no longer in the short one, so the long rule would report
    the same calls again under another name. The burst totals are remembered for one long window.
    """
    bursts = {burst_id for burst_id, _ in LONG_OVERLAPS.values()}
    for f in findings:
        if f.rule.id in bursts:
            state.note_burst(store, f.ip, f.rule.id, f.value, ttl)
    kept = []
    for f in findings:
        overlap = LONG_OVERLAPS.get(f.rule.id)
        if overlap:
            burst_id = overlap[0]
            reported = state.burst_total(store, f.ip, burst_id)
            if reported and f.value - reported < warning_threshold(burst_id, mult):
                continue
        kept.append(f)
    return kept


# --- process ----------------------------------------------------------------------


def _period_minutes() -> int:
    try:
        return config.env_int("WINDOW_MINUTES", 5, minimum=1)
    except config.ConfigError:
        return 5


def _active_rules(cfg: config.Config) -> int:
    return sum(1 for r in RULES if r.id not in cfg.disabled_rules)


def _boot(store: state.Store, announce: bool) -> None:
    try:
        cfg = config.load()
    except config.ConfigError as e:
        logger.error("config invalid at boot: %s", e)
        return
    profiles = len(webhooks.load_profiles(cfg.webhook_sources_file))
    state_label = "memory"
    if cfg.state_file:
        store.put("health:boot", state.iso(datetime.now(timezone.utc)), STARTED_TTL)  # proves the file is writable
        state_label = f"memory (STATE_FILE not writable: {store.write_error})" if store.write_error else "file"
    logger.info(
        "cf-abuse-alert [%s] hosts=%s · media=%s · webhook profiles=%d · allowlist=%d entries · trusted ASNs=%d · "
        "rules=%d · window=%dm sustained=%dm lag=%dm · multiplier=%g · dry_run=%s · state=%s",
        cfg.environment_label,
        ",".join(cfg.monitor_hosts),
        ",".join(cfg.media_hosts + cfg.media_path_prefixes) if cfg.media_enabled else "off",
        profiles,
        len(cfg.allowlist),
        len(cfg.trusted_asns),
        _active_rules(cfg),
        cfg.window_minutes,
        cfg.sustained_window_minutes,
        cfg.ingest_lag_minutes,
        cfg.threshold_multiplier,
        cfg.dry_run,
        state_label,
    )
    if not announce:
        return
    state.skip_heartbeat_after_boot(store, datetime.now(timezone.utc), cfg.heartbeat_hour_utc)
    try:
        startup_message = config.env_bool("STARTUP_MESSAGE", True)
    except config.ConfigError as e:
        logger.error("config invalid at boot: %s", e)
        return
    # With STATE_FILE, a crash loop posts "started" at most once per STARTED_TTL. Without it every
    # restart posts one (Northflank backs off between restarts).
    if startup_message and store.get("health:started") is None:
        sender = Sender(cfg.slack_webhook_url, dry_run=cfg.dry_run)
        if sender.send(build_started(cfg, _active_rules(cfg), profiles), "started"):
            store.put("health:started", "1", STARTED_TTL)


def _start_health(probe: Health):
    try:
        port = config.env_int("PORT", 0, minimum=0)
    except config.ConfigError as e:
        logger.error("health endpoint disabled: %s", e)
        return None
    if not port:
        return None
    try:
        return serve_health(probe, port)
    except OSError as e:
        logger.error("health endpoint disabled: cannot bind :%d (%s)", port, e)
        return None


def next_tick(previous: datetime | None, now: datetime, period: int) -> tuple[datetime, int]:
    """(the tick to run next, windows skipped).

    Ticks follow each other without gaps: after a tick that overran, the delayed ones run at once.
    Only when more than MAX_CATCH_UP_TICKS are overdue are the oldest dropped.
    """
    upcoming = floor_to_period(now, period) + timedelta(minutes=period)
    if previous is None:
        return upcoming, 0
    step = timedelta(minutes=period)
    following = previous + step
    oldest = upcoming - step * (MAX_CATCH_UP_TICKS + 1)
    if following >= oldest:
        return min(following, upcoming), 0
    return oldest, int((oldest - following) / step)


def parse_at(raw: str) -> datetime:
    t = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _samples(send: bool) -> int:
    """--preview prints the sample alerts as JSON; --test-alert posts them to Slack."""
    import samples

    try:
        cfg = config.load(slack_only=True)
    except config.ConfigError as e:
        if send:
            logger.error("config invalid: %s", e)
            return 2
        os.environ.setdefault("SLACK_WEBHOOK_URL", "https://hooks.slack.invalid/preview")
        cfg = config.load(slack_only=True)
    payloads = samples.payloads(cfg)
    if not send:
        print(json.dumps([p for _, p in payloads], indent=2, ensure_ascii=False))
        return 0
    sender = Sender(cfg.slack_webhook_url, dry_run=False)
    ok = [sender.send(payload, name) for name, payload in payloads]
    logger.info("test alerts: %d of %d accepted by Slack", sum(ok), len(ok))
    return 0 if all(ok) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cf-abuse-alert: flag abnormal IPs from Cloudflare analytics")
    parser.add_argument("--once", action="store_true", help="run one tick and exit")
    parser.add_argument("--at", help="with --once: the tick's scheduled time (ISO, UTC)")
    parser.add_argument("--dry-run", action="store_true", help="log instead of posting to Slack")
    parser.add_argument("--test-alert", action="store_true", help="post sample alerts (made-up data) to Slack and exit")
    parser.add_argument("--preview", action="store_true", help="print the sample alerts as Slack JSON and exit")
    args = parser.parse_args(argv)

    level = config.env("LOG_LEVEL", "INFO").upper()
    known_level = level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    logging.basicConfig(
        level=level if known_level else "INFO",
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    if not known_level:
        logger.warning("LOG_LEVEL %r is not a log level, using INFO", level)
    if args.preview or args.test_alert:
        return _samples(send=args.test_alert)
    if args.dry_run:
        os.environ["DRY_RUN"] = "true"

    store = state.Store(config.env("STATE_FILE"))
    _boot(store, announce=not args.once)
    period = _period_minutes()

    if args.once:
        at = parse_at(args.at) if args.at else datetime.now(timezone.utc)
        return 0 if run_tick(floor_to_period(at, period), store=store).ok else 1

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    probe = Health(stale_after_seconds=period * 60 + HEALTH_GRACE_SECONDS)
    server = _start_health(probe)

    scheduled: datetime | None = None
    while not stop.is_set():
        probe.beat()
        now = datetime.now(timezone.utc)
        scheduled, skipped = next_tick(scheduled, now, period)
        if skipped:
            logger.error("the previous tick overran: %d window(s) of %d min were not analysed", skipped, period)
        if stop.wait(max(0.0, (scheduled - now).total_seconds())):
            break
        try:
            result = run_tick(scheduled, store=store)
        except Exception as e:  # noqa: BLE001 — last line of defence: the loop outlives any tick
            logger.error("tick %s crashed: %s", f"{scheduled:%H:%M}Z", type(e).__name__, exc_info=True)
            result = TickResult(ok=False, error=type(e).__name__)
        probe.record(result.ok and not result.undelivered, result.error or "slack delivery failed")

    if server:
        server.shutdown()
    logger.info("stopping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
