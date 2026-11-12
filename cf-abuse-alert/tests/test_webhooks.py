import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import make_cfg
import slack
import state
import webhooks
from allowlist import Allowlist
from samples import webhook
from window import Window

T0 = datetime(2026, 11, 12, 2, 35, tzinfo=timezone.utc)
WINDOW = Window(T0 - timedelta(minutes=8), T0 - timedelta(minutes=3))
STRIPE_IP = "192.0.2.10"
OTHER_IP = "192.0.2.99"
STRIPE_UA = "Stripe/1.0 (+https://stripe.com/docs/webhooks)"

PROFILES = {
    "_generated": "test",
    "/webhook/stripe": {
        "name": "Stripe",
        "asns": [16509],
        "user_agents": ["Stripe/"],
        "ips": [STRIPE_IP],
    },
    "/api/revenue-cat-webhook": {
        "name": "RevenueCat",
        "asns": [16509],
        "user_agents": [""],
        "official_ips": ["192.0.2.64/28"],
        "ips": [],
        "strict": True,
    },
    "/api/episode/update-status-webhook": {"name": "Bunny Stream", "asns": [24940], "user_agents": [], "ips": "*"},
}


def profiles() -> list[webhooks.Source]:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "webhook_sources.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(PROFILES, f)
        return webhooks.load_profiles(path)


def run(rows, sources=None, store=None, tick=T0, allow=(), **kw):
    return webhooks.evaluate(
        rows,
        profiles() if sources is None else sources,
        store=state.Store() if store is None else store,  # an empty Store is falsy (it has __len__)
        tick=tick,
        period_minutes=5,
        thresholds=webhooks.Thresholds(),
        allowlist=Allowlist.parse(list(allow)),
        **kw,
    )


def ids(findings) -> list[tuple[str, str]]:
    return [(f.rule_id, f.severity) for f in findings]


class RejectedTest(unittest.TestCase):
    """`webhook_rejected` works with no profile file at all."""

    def test_repeated_rejections_alert(self):
        # Stripe answers 400 to a bad signature, RevenueCat 401, the cron guard 403.
        self.assertEqual(ids(run([webhook(OTHER_IP, "/webhook/stripe", 4, 400)], [])), [])
        self.assertEqual(
            ids(run([webhook(OTHER_IP, "/webhook/stripe", 5, 400)], [])), [("webhook_rejected", "WARNING")]
        )
        self.assertEqual(
            ids(run([webhook(OTHER_IP, "/api/revenue-cat-webhook", 6, 401)], [])), [("webhook_rejected", "WARNING")]
        )
        self.assertEqual(
            ids(run([webhook(OTHER_IP, "/cronjob/health-check-notify", 30, 403)], [])),
            [("webhook_rejected", "CRITICAL")],
        )

    def test_accepted_calls_and_other_errors_do_not(self):
        rows = [
            webhook(STRIPE_IP, "/webhook/stripe", 400, 200),
            webhook(STRIPE_IP, "/webhook/stripe", 30, 500),
            webhook(STRIPE_IP, "/webhook/stripe", 30, 404),
        ]
        self.assertEqual(run(rows, []), [])

    def test_without_profiles_no_profile_rule_fires(self):
        self.assertEqual(run([webhook(OTHER_IP, "/webhook/unknown-provider", 50, 200)], []), [])

    def test_provider_name_comes_from_the_path(self):
        f = run([webhook(OTHER_IP, "/api/sbp/paypay/webhook/subscription", 9, 401)], [])[0]
        self.assertEqual(f.provider, "SB Payment (PayPay)")
        self.assertEqual(f.dedupe_rule, "webhook_rejected:/api/sbp/paypay/webhook/subscription")

    def test_allowlist_and_disabled(self):
        rows = [webhook(OTHER_IP, "/webhook/stripe", 9, 401)]
        self.assertEqual(run(rows, [], allow=[OTHER_IP]), [])
        self.assertEqual(run(rows, [], disabled=frozenset({"webhook_rejected"})), [])


class ProfileTest(unittest.TestCase):
    def test_known_source_is_quiet(self):
        self.assertEqual(run([webhook(STRIPE_IP, "/webhook/stripe", 300, 200, ua=STRIPE_UA)]), [])

    def test_unknown_network(self):
        row = webhook(OTHER_IP, "/webhook/stripe", 3, 400, asn=14061, asn_name="DIGITALOCEAN-ASN", ua=STRIPE_UA)
        self.assertEqual(ids(run([row])), [("webhook_unknown_asn", "WARNING")])
        accepted = webhook(OTHER_IP, "/webhook/stripe", 3, 200, asn=14061, ua=STRIPE_UA)
        f = run([accepted])[0]
        self.assertEqual((f.rule_id, f.severity), ("webhook_unknown_asn", "CRITICAL"))
        self.assertIn("AS14061 is not a Stripe network", f.reason)

    def test_unexpected_user_agent(self):
        row = webhook(STRIPE_IP, "/webhook/stripe", 2, 200, ua="python-requests/2.31")
        self.assertEqual(ids(run([row])), [("webhook_unknown_ua", "CRITICAL")])

    def test_path_without_profile(self):
        row = webhook(OTHER_IP, "/webhook/apple-app-store-server-notifications", 2, 200)
        self.assertEqual(ids(run([row])), [("webhook_unknown_path", "CRITICAL")])

    def test_new_ip_needs_to_keep_sending(self):
        store = state.Store()
        row = [webhook(OTHER_IP, "/webhook/stripe", 2, 200, ua=STRIPE_UA)]
        self.assertEqual(run(row, store=store), [])
        self.assertEqual(run(row, store=store, tick=T0 + timedelta(minutes=5)), [])
        third = run(row, store=store, tick=T0 + timedelta(minutes=10))
        self.assertEqual(ids(third), [("webhook_new_ip", "WARNING")])
        self.assertEqual(third[0].history, {"window": 2, "streak": 3, "hourly": 6, "active_ticks": 3})
        self.assertEqual(third[0].looks_like, ("Stripe (same network and UA)",))

    def test_new_ip_burst_alerts_at_once(self):
        row = [webhook(OTHER_IP, "/webhook/stripe", 20, 200, ua=STRIPE_UA)]
        self.assertEqual(ids(run(row)), [("webhook_new_ip", "WARNING")])

    def test_strict_profile_alerts_on_the_first_call_outside_the_official_list(self):
        inside = [webhook("192.0.2.70", "/api/revenue-cat-webhook", 1, 200)]
        outside = [webhook("192.0.2.90", "/api/revenue-cat-webhook", 1, 200)]
        self.assertEqual(run(inside), [])
        self.assertEqual(ids(run(outside)), [("webhook_new_ip", "CRITICAL")])

    def test_rotating_pool_accepts_any_ip(self):
        row = [webhook(OTHER_IP, "/api/episode/update-status-webhook", 50, 200, asn=24940, asn_name="Hetzner")]
        self.assertEqual(run(row), [])

    def test_link_previews_are_ignored(self):
        row = [webhook(OTHER_IP, "/webhook/stripe", 3, 404, asn=14061, ua="Slackbot-LinkExpanding 1.0")]
        self.assertEqual(run(row), [])

    def test_unreadable_profile_file_turns_profile_rules_off(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not json")
            with self.assertLogs("webhooks", "ERROR"):
                self.assertEqual(webhooks.load_profiles(path), [])
        self.assertEqual(webhooks.load_profiles(""), [])
        self.assertEqual(webhooks.load_profiles("/nonexistent/webhook_sources.json"), [])


class HardeningTest(unittest.TestCase):
    def test_a_disabled_profile_rule_does_not_hide_rejections(self):
        forged = [webhook(OTHER_IP, "/webhook/stripe", 12, 400, asn=14061, ua=STRIPE_UA)]
        self.assertEqual(ids(run(forged)), [("webhook_unknown_asn", "WARNING")])
        off = frozenset({"webhook_unknown_asn"})
        self.assertEqual(ids(run(forged, disabled=off)), [("webhook_rejected", "WARNING")])
        self.assertEqual(run(forged, disabled=off | {"webhook_rejected"}), [])

    def test_a_flood_of_rejected_calls_is_critical_whatever_the_profile_says(self):
        flood = [webhook(OTHER_IP, "/webhook/stripe", 50, 400, asn=14061, ua=STRIPE_UA)]
        f = run(flood)[0]
        self.assertEqual((f.rule_id, f.severity), ("webhook_unknown_asn", "CRITICAL"))
        self.assertEqual(f.reason, "AS14061 is not a Stripe network (50 calls answered 400/401/403)")
        text = json.dumps(slack.build_webhook_alert(make_cfg(), WINDOW, f), ensure_ascii=False)
        self.assertIn("🔴 *AS14061 is not a Stripe network*", text)
        self.assertIn(">50 calls answered 400/401/403", text)
        # Without profiles the same traffic was already critical.
        self.assertEqual(ids(run(flood, [])), [("webhook_rejected", "CRITICAL")])

    def test_a_hand_edited_profile_file_cannot_stop_the_service(self):
        def load(content) -> list:
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "webhook_sources.json")
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(content, f)
                return webhooks.load_profiles(path)

        self.assertEqual(load({"/webhook/stripe": {"asns": ["AS16509", 14618]}})[0].asns, {16509, 14618})
        for broken in (["/webhook/stripe"], {"/webhook/stripe": {"asns": ["amazon"]}}, {"/webhook/stripe": {"asns": 16509}}):
            with self.assertLogs("webhooks", "ERROR"):
                self.assertEqual(load(broken), [])


class WebhookMessageTest(unittest.TestCase):
    def test_rejected_message(self):
        f = run([webhook(OTHER_IP, "/webhook/stripe", 14, 400, ua="python-requests/2.31.0")], [])[0]
        p = slack.build_webhook_alert(make_cfg(environment_label="PROD"), WINDOW, f)
        text = json.dumps(p, ensure_ascii=False)
        self.assertEqual(p["text"], "⚠️ *[PROD] WARNING — Stripe webhook: calls keep being rejected* · `192.0.2.99`")
        self.assertIn("🇺🇸 US · AS16509 AMAZON-02", text)
        self.assertIn("`/webhook/stripe`", text)
        self.assertEqual(
            p["blocks"][0]["text"]["text"], "⚠️ [PROD] WARNING · Stripe webhook: calls keep being rejected · 192.0.2.99"
        )
        self.assertIn("Stripe · `/webhook/stripe`", text)
        self.assertIn("*14* total · `400` ×14", text)
        self.assertIn("🟠 *14 calls answered 400/401/403*", text)
        self.assertIn(">Signature or secret check failed, or the WAF blocked them", text)
        self.assertIn("*User agent:*  `python-requests/2.31.0`", text)
        self.assertIn("• If the source is the real provider", text)
        self.assertIn("• If not, someone is forging calls", text)
        self.assertIn("`webhook_rejected`", text)
        self.assertIn("`python-requests/2.31.0`", text)
        self.assertIn("events are being lost", text)

    def test_profile_message_shows_what_was_expected(self):
        f = run([webhook(OTHER_IP, "/webhook/stripe", 3, 200, asn=14061, asn_name="DIGITALOCEAN-ASN", ua="<!channel>")])[0]
        text = json.dumps(slack.build_webhook_alert(make_cfg(), WINDOW, f), ensure_ascii=False)
        self.assertIn("CRITICAL — Stripe webhook: call from an unknown network", text)
        self.assertIn("🔴 *AS14061 is not a Stripe network*", text)
        self.assertIn("*Expected for Stripe:*  AS16509 · UA `Stripe/` · 1 known IPs/ranges", text)
        self.assertIn("The server *accepted* these calls (2xx)", text)
        self.assertNotIn("<!channel>", text)


if __name__ == "__main__":
    unittest.main()
