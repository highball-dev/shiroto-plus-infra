from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timezone

from dotenv import load_dotenv

import endpoints
from allowlist import Allowlist
from window import JST, parse_display_tz

# Only this folder's `.env` (or ENV_FILE). Without a path python-dotenv walks up the parent folders
# and would pick up another project's credentials.
load_dotenv(os.environ.get("ENV_FILE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

DEFAULT_ZONE_NAME = "swipedrama.com"
DEFAULT_BLOCK_ACTIONS = (
    "block,challenge,jschallenge,managed_challenge,connection_close,"
    "force_connection_close,challenge_failed,jschallenge_failed"
)
DEFAULT_RATE_LIMIT_SOURCES = "ratelimit"
DEFAULT_SENSITIVE_METHODS = "POST,PUT,PATCH,DELETE"
DEFAULT_API_PATH_PREFIXES = "/api/"
DEFAULT_WEBHOOK_SOURCES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webhook_sources.json")

DEFAULT_DASHBOARD_URL = "https://dash.cloudflare.com/?to=/:account/:zone/security/events"
ACCOUNT_DASHBOARD_URL = "https://dash.cloudflare.com/{account_id}/{zone_name}/security/events"


class ConfigError(ValueError):
    pass


def env(name: str, default: str = "", *aliases: str) -> str:
    """First non-empty value among `name` and its aliases."""
    for key in (name, *aliases):
        val = os.environ.get(key)
        if val is not None and val.strip() != "":
            return val.strip()
    return default


def env_list(name: str, default: str = "") -> list[str]:
    return [s.strip() for s in env(name, default).split(",") if s.strip()]


def env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = env(name)
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if val < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {val}")
    return val


def env_float_positive(name: str, default: float) -> float:
    raw = env(name)
    if not raw:
        return default
    try:
        val = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None
    if not val > 0:
        raise ConfigError(f"{name} must be > 0, got {val}")
    return val


def env_bool(name: str, default: bool) -> bool:
    raw = env(name).lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    # A typo must not silently mean "false": DRY_RUN=ture would post for real.
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def required(name: str, *aliases: str) -> str:
    val = env(name, "", *aliases)
    if not val:
        raise ConfigError(f"Missing required env var: {name}")
    return val


def _asns(name: str) -> frozenset[int]:
    out = set()
    for raw in env_list(name):
        digits = raw.upper().removeprefix("AS")
        if not digits.isdigit():
            raise ConfigError(f"{name} must be a list of AS numbers, got {raw!r}")
        out.add(int(digits))
    return frozenset(out)


def known_rule_ids() -> frozenset[str]:
    import rules  # imported here: rules and webhooks do not depend on config, keep it that way
    import webhooks

    return frozenset({r.id for r in rules.RULES} | {rules.SPIKE_RULE_ID} | set(webhooks.DEDUPE_TTL))


@dataclass(frozen=True)
class Config:
    cf_api_token: str
    cf_zone_tag: str
    slack_webhook_url: str

    environment_label: str
    monitor_hosts: tuple[str, ...]
    allowlist: Allowlist
    excluded_path_prefixes: tuple[str, ...]
    block_actions: frozenset[str]
    rate_limit_sources: frozenset[str]

    ingest_lag_minutes: int
    window_minutes: int
    dedupe_ttl_seconds: int
    max_alerts_per_run: int
    max_candidates: int
    threshold_multiplier: float
    dry_run: bool
    heartbeat_hour_utc: int

    dashboard_url: str
    graphql_url: str = GRAPHQL_URL
    graphql_timeout_seconds: int = 15
    state_file: str = ""
    display_tz: timezone = JST
    trusted_asns: frozenset[int] = frozenset()
    disabled_rules: frozenset[str] = frozenset()
    critical_mention: str = ""
    api_path_prefixes: tuple[str, ...] = (DEFAULT_API_PATH_PREFIXES,)
    media_hosts: tuple[str, ...] = ()
    media_path_prefixes: tuple[str, ...] = ()
    sustained_window_minutes: int = 60
    sensitive_methods: frozenset[str] = frozenset(DEFAULT_SENSITIVE_METHODS.split(","))
    webhook_sources_file: str = ""
    webhook_prefixes: tuple[str, ...] = endpoints.WEBHOOK_PREFIXES
    webhook_new_ip_burst: int = 20
    webhook_new_ip_streak: int = 3
    webhook_new_ip_hourly: int = 50

    @property
    def query_hosts(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self.monitor_hosts + self.media_hosts))

    @property
    def media_enabled(self) -> bool:
        return bool(self.media_hosts or self.media_path_prefixes)


def load(*, slack_only: bool = False) -> Config:
    """Read and validate the environment. Fails fast: a half-configured watcher is worse than none.

    `slack_only` is for `--test-alert` / `--preview`: Cloudflare settings get placeholders so the
    Slack formatting can be checked before a Cloudflare token exists.
    """
    hosts = tuple(h.lower() for h in env_list("MONITOR_HOSTS", "api.example.com" if slack_only else ""))
    if not hosts:
        raise ConfigError("MONITOR_HOSTS is empty — refusing to monitor the whole zone")

    window_minutes = env_int("WINDOW_MINUTES", 5, minimum=1)
    if 60 % window_minutes:
        # Ticks are aligned to the clock; any other value gives overlapping windows around the hour.
        raise ConfigError(f"WINDOW_MINUTES must divide 60 (1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30, 60), got {window_minutes}")
    sustained_minutes = env_int("SUSTAINED_WINDOW_MINUTES", 60, minimum=1)
    if sustained_minutes < window_minutes:
        raise ConfigError(
            f"SUSTAINED_WINDOW_MINUTES ({sustained_minutes}) must be >= WINDOW_MINUTES ({window_minutes})"
        )

    heartbeat_hour = env_int("HEARTBEAT_HOUR_UTC", 0)
    if heartbeat_hour > 23:
        raise ConfigError(f"HEARTBEAT_HOUR_UTC must be 0..23, got {heartbeat_hour}")

    try:
        display_tz = parse_display_tz(env("DISPLAY_TIMEZONE", "JST+9"))
    except ValueError as e:
        raise ConfigError(f"DISPLAY_TIMEZONE: {e}") from None

    account_id = env("CF_ACCOUNT_ID", "", "CLOUDFLARE_ACCOUNT_ID")
    zone_name = env("CF_ZONE_NAME", DEFAULT_ZONE_NAME)
    default_dash = (
        ACCOUNT_DASHBOARD_URL.format(account_id=account_id, zone_name=zone_name)
        if account_id
        else DEFAULT_DASHBOARD_URL
    )

    multiplier = env_float_positive("THRESHOLD_MULTIPLIER", 1.0)
    if not 0.1 <= multiplier <= 100:
        raise ConfigError(f"THRESHOLD_MULTIPLIER must be between 0.1 and 100, got {multiplier:g}")

    disabled = frozenset(env_list("DISABLED_RULES"))
    unknown = sorted(disabled - known_rule_ids())
    if unknown:
        raise ConfigError(f"DISABLED_RULES: unknown rule id(s) {', '.join(unknown)} (ids are lower-case, see README)")

    slack_url = required("SLACK_WEBHOOK_URL")
    # Plain http is only accepted for a local stand-in during development.
    if not slack_url.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
        raise ConfigError("SLACK_WEBHOOK_URL must be an https:// URL")

    if slack_only:
        token = env("CF_API_TOKEN", "unused", "CLOUDFLARE_API_TOKEN")
        zone = env("CF_ZONE_TAG", "unused", "CLOUDFLARE_ZONE_ID")
    else:
        token = required("CF_API_TOKEN", "CLOUDFLARE_API_TOKEN")
        zone = required("CF_ZONE_TAG", "CLOUDFLARE_ZONE_ID")

    return Config(
        cf_api_token=token,
        cf_zone_tag=zone,
        slack_webhook_url=slack_url,
        environment_label=env("ENVIRONMENT_LABEL", "NON-PROD"),
        monitor_hosts=hosts,
        allowlist=Allowlist.parse(env_list("ALLOWLIST_IPS")),
        excluded_path_prefixes=tuple(
            env_list("EXCLUDED_PATH_PREFIXES", ",".join(endpoints.DEFAULT_EXCLUDED_PATH_PREFIXES))
        ),
        block_actions=frozenset(a.lower() for a in env_list("BLOCK_ACTIONS", DEFAULT_BLOCK_ACTIONS)),
        rate_limit_sources=frozenset(
            s.lower() for s in env_list("RATE_LIMIT_SOURCES", DEFAULT_RATE_LIMIT_SOURCES)
        ),
        ingest_lag_minutes=env_int("INGEST_LAG_MINUTES", 3),
        window_minutes=window_minutes,
        dedupe_ttl_seconds=env_int("DEDUPE_TTL_SECONDS", 1800, minimum=60),
        max_alerts_per_run=env_int("MAX_ALERTS_PER_RUN", 10, minimum=1),
        max_candidates=env_int("MAX_CANDIDATES", 50, minimum=1),
        threshold_multiplier=multiplier,
        dry_run=env_bool("DRY_RUN", False),
        heartbeat_hour_utc=heartbeat_hour,
        dashboard_url=env("DASHBOARD_URL", default_dash),
        graphql_url=env("CF_GRAPHQL_URL", GRAPHQL_URL),
        graphql_timeout_seconds=env_int("GRAPHQL_TIMEOUT_SECONDS", 15, minimum=1),
        state_file=env("STATE_FILE"),
        display_tz=display_tz,
        trusted_asns=_asns("TRUSTED_ASNS"),
        disabled_rules=disabled,
        critical_mention=env("SLACK_CRITICAL_MENTION"),
        api_path_prefixes=tuple(env_list("API_PATH_PREFIXES", DEFAULT_API_PATH_PREFIXES)),
        media_hosts=tuple(h.lower() for h in env_list("MEDIA_HOSTS")),
        media_path_prefixes=tuple(env_list("MEDIA_PATH_PREFIXES")),
        sustained_window_minutes=sustained_minutes,
        sensitive_methods=frozenset(m.upper() for m in env_list("SENSITIVE_METHODS", DEFAULT_SENSITIVE_METHODS)),
        webhook_sources_file=env("WEBHOOK_SOURCES_FILE", DEFAULT_WEBHOOK_SOURCES_FILE),
        webhook_prefixes=tuple(env_list("WEBHOOK_PREFIXES", ",".join(endpoints.WEBHOOK_PREFIXES))),
        webhook_new_ip_burst=env_int("WEBHOOK_NEW_IP_BURST", 20, minimum=1),
        webhook_new_ip_streak=env_int("WEBHOOK_NEW_IP_STREAK", 3, minimum=1),
        webhook_new_ip_hourly=env_int("WEBHOOK_NEW_IP_HOURLY", 50, minimum=1),
    )
