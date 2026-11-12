"""SwipeDrama endpoint map: which API paths mean what.

Everything that depends on the server's routes lives here, so a route change in
`shiroto-plus/apps/server` is a one-file change in this service. Paths were read from the
controllers (no global prefix: each controller spells out `/api/...` itself).
"""
from __future__ import annotations

from collections import Counter

# --------------------------------------------------------------------------------------
# Sensitive write endpoints, counted per IP by the *_abuse / *_farming rules.
# Only SENSITIVE_METHODS (POST, PUT, PATCH, DELETE by default) are counted.
# --------------------------------------------------------------------------------------

SENSITIVE_GROUPS: dict[str, tuple[str, ...]] = {
    # Firebase custom token, LINE login, MCP OAuth token/registration
    "auth": ("/api/auth", "/token", "/register", "/revoke"),
    # POST /api/users creates an account, /api/users/device binds a device
    "signup": ("/api/users",),
    # points and rewards that can be farmed
    "rewards": (
        "/api/user-missions",
        "/api/user-ads",
        "/api/user-checkins",
        "/api/user-onboard-checkins",
        "/api/user-bonus",
        "/api/user-referrals",
    ),
    # spending points to unlock an episode; a burst means scripted unlocking / scraping
    "unlock": ("/api/unlock-episode",),
    # presigned upload URLs
    "upload": ("/api/s3/user/upload",),
}


def sensitive_group(path: str) -> str | None:
    for group, prefixes in SENSITIVE_GROUPS.items():
        for prefix in prefixes:
            if path == prefix or path.startswith(prefix + "/"):
                return group
    return None


def all_sensitive_prefixes() -> list[str]:
    return [p for prefixes in SENSITIVE_GROUPS.values() for p in prefixes]


# --------------------------------------------------------------------------------------
# Payment and restricted-area signals: exact endpoints, counted from one dedicated query
# so that an IP with only a dozen requests is still seen.
# --------------------------------------------------------------------------------------

# One call = one attempt to pay (Stripe, Paidy, SB Payment).
PURCHASE_PATHS = (
    "/api/payment/create-payment-intent",
    "/api/payment/purchase-with-saved-method",
    "/api/payment/create-checkout-session",
    "/api/paidy/intent",
    "/api/paidy/token",
    "/api/sbp/create-session",
    "/api/sbp/credit-card/payment-with-saved-card",
    "/api/sbp/credit-card/3ds-auth",
)
# App Store / Google Play receipt validation. A failure is a receipt the server refused.
IAP_PATHS = ("/api/iap/validate", "/api/iap/validate-transaction")
PAYMENT_PREFIXES = ("/api/payment", "/api/paidy", "/api/sbp", "/api/iap")
CARD_SETUP_PATH = "/api/payment/setup-intent"
CARD_METHODS_PREFIX = "/api/payment/payment-methods/"
# GET /api/payment/check-purchase/:name/:external_id has no auth guard.
PURCHASE_CHECK_PREFIX = "/api/payment/check-purchase/"
# Behind Cloudflare Access + Firebase roles. A 401/403 here is someone who should not be there.
RESTRICTED_PREFIXES = ("/api/admin/", "/api/test-support/", "/mcp/clients", "/mcp/register-client")
DENIED_STATUSES = (401, 403)

PURCHASES = "purchases"
PURCHASE_FAILURES = "purchase_failures"
IAP_FAILURES = "iap_failures"
RATE_LIMITED = "payment_rate_limited"
CARD_CHANGES = "card_changes"
PURCHASE_CHECKS = "purchase_checks"
RESTRICTED_DENIED = "restricted_denied"


def _failed(status: int) -> bool:
    return 400 <= status < 600 and status != 429


def signals(path: str, method: str, status: int) -> list[str]:
    """The named signals one (path, method, status) row counts towards."""
    path = (path or "/").split("?", 1)[0].rstrip("/") or "/"
    method = (method or "").upper()
    out: list[str] = []
    if method == "POST" and path in PURCHASE_PATHS:
        out.append(PURCHASES)
        if _failed(status):
            out.append(PURCHASE_FAILURES)
    if method == "POST" and path in IAP_PATHS and _failed(status):
        out.append(IAP_FAILURES)
    if status == 429 and path.startswith(PAYMENT_PREFIXES):
        out.append(RATE_LIMITED)
    if (method == "GET" and path == CARD_SETUP_PATH) or (
        method in ("DELETE", "PUT") and path.startswith(CARD_METHODS_PREFIX)
    ):
        out.append(CARD_CHANGES)
    if method == "GET" and path.startswith(PURCHASE_CHECK_PREFIX):
        out.append(PURCHASE_CHECKS)
    if status in DENIED_STATUSES and (path + "/").startswith(RESTRICTED_PREFIXES):
        out.append(RESTRICTED_DENIED)
    return out


def purchase_filters() -> list[dict]:
    return [{"clientRequestPath_in": list(PURCHASE_PATHS), "clientRequestHTTPMethodName": "POST"}]


def signal_filters() -> list[dict]:
    """Cloudflare filter (OR list) selecting every row `signals()` can classify."""
    return (
        purchase_filters()
        + [
            {"clientRequestPath_in": list(IAP_PATHS), "clientRequestHTTPMethodName": "POST"},
            {"clientRequestPath": CARD_SETUP_PATH, "clientRequestHTTPMethodName": "GET"},
            {"clientRequestPath_like": CARD_METHODS_PREFIX + "%", "clientRequestHTTPMethodName_in": ["DELETE", "PUT"]},
            {"clientRequestPath_like": PURCHASE_CHECK_PREFIX + "%", "clientRequestHTTPMethodName": "GET"},
        ]
        + [{"edgeResponseStatus": 429, "clientRequestPath_like": p + "%"} for p in PAYMENT_PREFIXES]
        + [
            {"edgeResponseStatus_in": list(DENIED_STATUSES), "clientRequestPath_like": p + "%"}
            for p in RESTRICTED_PREFIXES
        ]
    )


def counters(rows: list[dict], normalize_ip) -> dict[str, Counter]:
    out: dict[str, Counter] = {}
    for row in rows or ():
        d = row.get("dimensions") or {}
        ip = normalize_ip(d.get("clientIP", ""))
        if not ip:
            continue
        n = int(row.get("count") or 0)
        for name in signals(
            d.get("clientRequestPath") or "/",
            d.get("clientRequestHTTPMethodName") or "",
            int(d.get("edgeResponseStatus") or 0),
        ):
            out.setdefault(ip, Counter())[name] += n
    return out


# --------------------------------------------------------------------------------------
# Server-to-server endpoints: provider webhooks, ad/attribution callbacks, our own jobs.
# Never counted by the per-IP traffic rules; watched separately (webhooks.py).
# --------------------------------------------------------------------------------------

WEBHOOK_PREFIXES: tuple[str, ...] = (
    "/webhook/",  # Stripe, Apple App Store Server Notifications
    "/api/revenue-cat-webhook",
    "/api/sbp/webhook/",
    "/api/sbp/paypay/webhook/",
    "/api/sbp/carrier/webhook/",
    "/api/form-submit/tally/webhook",
    "/api/episode/update-status-webhook",  # Bunny Stream
    "/api/schedule-notifications/event-bridge-webhook",
    "/api/paidy/subscription-renew/lambda-webhook",
    "/api/payment/sbp-subscription-renew/lambda-webhook",
    "/api/episode-schedules/lambda-webhook",
    "/api/callback/adjust/",
    "/api/user-missions/skyflag-missions-rewards",
    "/api/user-missions/mychips-missions-rewards",
    "/api/user-missions/applovin-rewarded-callback",
    "/api/user-referrals/callback",
    "/api/notification/push/",  # our AWS jobs
    "/cronjob/",
)

# Also never counted: browser returns, discovery documents, health checks, SSR metadata,
# static assets of the web host.
OTHER_EXCLUDED_PREFIXES: tuple[str, ...] = (
    "/api/sbp/credit-card/callback/",
    "/.well-known/",
    "/mcp",
    "/health",
    "/api/maintenance",
    "/api/movies/sitemap",
    "/api/movies/*/metadata",
    "/_next/static/",
    "/_next/image",
    "/favicon",
)

DEFAULT_EXCLUDED_PATH_PREFIXES: tuple[str, ...] = WEBHOOK_PREFIXES + OTHER_EXCLUDED_PREFIXES

# Friendly names for alerts on webhook paths that have no source profile yet.
WEBHOOK_NAMES: tuple[tuple[str, str], ...] = (
    ("/webhook/stripe", "Stripe"),
    ("/webhook/apple-app-store-server-notifications", "Apple App Store"),
    ("/api/revenue-cat-webhook", "RevenueCat"),
    ("/api/sbp/paypay/", "SB Payment (PayPay)"),
    ("/api/sbp/carrier/", "SB Payment (carrier)"),
    ("/api/sbp/webhook/", "SB Payment"),
    ("/api/form-submit/tally/", "Tally"),
    ("/api/episode/update-status-webhook", "Bunny Stream"),
    ("/api/schedule-notifications/", "AWS EventBridge"),
    ("/api/paidy/subscription-renew/", "Paidy renew Lambda"),
    ("/api/payment/sbp-subscription-renew/", "SB Payment renew Lambda"),
    ("/api/episode-schedules/", "Episode schedule Lambda"),
    ("/api/callback/adjust/", "Adjust"),
    ("/api/user-referrals/callback", "Adjust (referral)"),
    ("/api/user-missions/skyflag", "SkyFlag"),
    ("/api/user-missions/mychips", "MyChips"),
    ("/api/user-missions/applovin", "AppLovin"),
    ("/api/notification/push/", "Push notification job"),
    ("/cronjob/", "Cron job"),
)


def webhook_name(path: str) -> str:
    for prefix, name in WEBHOOK_NAMES:
        if path.startswith(prefix):
            return name
    return "Unknown"
