import json
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone

from tests.helpers import ALLOWLISTED_IP, HOST, SLACK_URL, TOKEN, FakePost, graphql, make_cfg
import cf_graphql as q
import config
import samples
import state
from main import OPTIONAL_QUERIES, run_tick
from samples import FARMER_IP, FORGER_IP, SCANNER_IP

T0 = datetime(2026, 11, 12, 2, 35, tzinfo=timezone.utc)


def tick(post, store, cfg=None, at=T0, now=None):
    cfg = cfg or make_cfg()
    return run_tick(at, store=store, post=post, load_config=lambda: cfg, now=lambda: now or at)


def attack() -> dict:
    return graphql(samples.scanner_scenario(), samples.farmer_scenario())


class HappyPathTest(unittest.TestCase):
    def test_one_message_per_ip_then_dedupes(self):
        post, store = FakePost(attack()), state.Store()
        r = tick(post, store)
        self.assertTrue(r.ok, r.error)
        t = post.texts()
        self.assertEqual(len(t), 2, t)

        # The scanner is further over its limits, so it comes first.
        self.assertIn("CRITICAL — Vulnerability scan from", post.slack[0]["text"])
        self.assertIn(f"`{SCANNER_IP}`", post.slack[0]["text"])
        for rule in ("scanner_paths", "attack_tool", "injection_attempts", "cf_blocked", "high_4xx_ratio"):
            self.assertIn(f"`{rule}`", t[0])
        self.assertIn("CRITICAL — Reward farming from", post.slack[1]["text"])
        self.assertIn(f"`{FARMER_IP}`", post.slack[1]["text"])
        for rule in ("reward_farming", "unlock_scraping", "server_rate_limited"):
            self.assertIn(f"`{rule}`", t[1])
        self.assertNotIn(FARMER_IP, t[0])
        self.assertNotIn(SCANNER_IP, t[1])
        for secret in (TOKEN, SLACK_URL):
            self.assertNotIn(secret, "\n".join(t))

        # Every query is scoped to the monitored host and to the lagged window.
        self.assertTrue(all(g["variables"]["filter"]["clientRequestHTTPHost_in"] == [HOST] for g in post.gql))
        f = post.sent(q.A1_TOP)[0]["variables"]["filter"]
        self.assertEqual((f["datetime_geq"], f["datetime_lt"]), ("2026-11-12T02:27:00Z", "2026-11-12T02:32:00Z"))
        long = post.sent(q.A6_SUSTAINED)[0]["variables"]["filter"]
        self.assertEqual((long["datetime_geq"], long["datetime_lt"]), ("2026-11-12T01:32:00Z", "2026-11-12T02:32:00Z"))
        self.assertEqual(post.sent(q.B_EVENTS)[0]["variables"]["filter"]["action_neq"], "skip")
        # Media is not configured, so A5 is the one query that is not sent.
        expected = {q.A1_TOP, q.B_EVENTS, q.A2_DETAILS, *OPTIONAL_QUERIES} - {q.A5_MEDIA}
        self.assertEqual({g["name"] for g in post.gql}, expected)

        post.slack.clear()
        r2 = tick(post, store, at=T0 + timedelta(minutes=5))
        self.assertEqual(post.slack, [])
        self.assertGreater(r2.suppressed, 0)

    def test_dedupe_expires(self):
        clock = [T0.timestamp()]
        store = state.Store(clock=lambda: clock[0])
        tick(FakePost(attack()), store)
        clock[0] += 1801
        post = FakePost(attack())
        tick(post, store, at=T0 + timedelta(minutes=35))
        self.assertEqual(len(post.slack), 2)

    def test_escalation_resends_and_lists_what_was_already_alerted(self):
        store = state.Store()
        calm = samples.farmer_scenario()
        calm["details"] = [
            d
            for d in calm["details"]
            if d["dimensions"]["clientRequestPath"] != "/api/user-missions/bonus-points"
            and d["dimensions"]["edgeResponseStatus"] != 429
        ]
        first = FakePost(graphql(calm))
        tick(first, store)
        self.assertIn("WARNING — Reward farming", first.slack[0]["text"])

        post = FakePost(graphql(samples.farmer_scenario()))
        tick(post, store, at=T0 + timedelta(minutes=5))
        t = post.texts()
        self.assertEqual(len(t), 1)
        self.assertIn("CRITICAL — Reward farming", post.slack[0]["text"])
        self.assertIn("🔴 *Reward farming* — *176* reward claims", t[0])
        self.assertIn("Still active — first flagged 11:35 JST. Already alerted and still over the limit:", t[0])
        self.assertIn("⚪ Episode unlock burst — 74 unlock calls", t[0])

    def test_new_rule_on_alerted_ip_does_not_extend_old_dedupe(self):
        clock = [T0.timestamp()]
        store = state.Store(clock=lambda: clock[0])
        tick(FakePost(graphql(samples.farmer_scenario())), store)
        key = state.dedupe_key(FARMER_IP, "reward_farming")
        expires = store.expires_at(key)

        clock[0] += 300
        more = samples.farmer_scenario()
        more["signals"] = [samples.signal(FARMER_IP, "/api/iap/validate", 12, 400)]
        post = FakePost(graphql(more))
        tick(post, store, at=T0 + timedelta(minutes=5))
        self.assertEqual(len(post.slack), 1)
        self.assertIn("Rejected IAP receipts from", post.slack[0]["text"])
        self.assertEqual(store.expires_at(key), expires)

    def test_nothing_abnormal_sends_nothing_and_skips_details(self):
        post = FakePost(graphql(top=[samples.talker("203.0.113.9", 40)]))
        r = tick(post, state.Store())
        self.assertTrue(r.ok)
        self.assertEqual(post.slack, [])
        self.assertEqual(post.sent(q.A2_DETAILS), [])

    def test_allowlisted_ip_is_never_looked_up_or_alerted(self):
        post = FakePost(graphql(samples.scanner_scenario(ALLOWLISTED_IP), samples.scanner_scenario()))
        tick(post, state.Store())
        self.assertEqual(post.sent(q.A2_DETAILS)[0]["variables"]["filter"]["clientIP_in"], [SCANNER_IP])
        self.assertEqual(len(post.slack), 1)
        self.assertNotIn(ALLOWLISTED_IP, post.texts()[0])

    def test_slack_failure_is_not_marked_as_alerted(self):
        store = state.Store()
        tick(FakePost(attack(), slack_status=500, slack_body=b"err"), store)
        post = FakePost(attack())
        tick(post, store, at=T0 + timedelta(minutes=5))
        self.assertEqual(len(post.slack), 2)

    def test_more_ips_than_max_alerts_are_condensed(self):
        post = FakePost(attack())
        tick(post, state.Store(), cfg=make_cfg(max_alerts_per_run=1))
        self.assertEqual(len(post.slack), 2)
        self.assertIn("1 more IPs over a threshold", post.slack[1]["text"])
        self.assertIn(FARMER_IP, post.texts()[1])
        self.assertIn("Reward farming", post.texts()[1])

    def test_dry_run_logs_masked_ips_and_posts_nothing(self):
        post = FakePost(attack())
        with self.assertLogs("slack", "INFO") as logs:
            r = tick(post, state.Store(), cfg=make_cfg(dry_run=True))
        self.assertEqual(post.slack, [])
        self.assertEqual(len(r.messages), 2)
        out = "\n".join(logs.output)
        self.assertIn("203.0.113.x", out)
        self.assertNotIn(SCANNER_IP, out)
        self.assertNotIn(FARMER_IP, out)

    def test_threshold_multiplier_raises_the_bar(self):
        post = FakePost(graphql(samples.farmer_scenario()))
        tick(post, state.Store(), cfg=make_cfg(threshold_multiplier=2.0))
        self.assertEqual(len(post.slack), 1)
        self.assertIn("WARNING — Reward farming", post.slack[0]["text"])
        self.assertNotIn("unlock_scraping", post.texts()[0])

    def test_disabled_rules_do_not_fire(self):
        cfg = make_cfg(disabled_rules=frozenset({"reward_farming", "unlock_scraping", "server_rate_limited"}))
        post = FakePost(graphql(samples.farmer_scenario()))
        tick(post, state.Store(), cfg=cfg)
        self.assertEqual(post.slack, [])

    def test_trusted_asn_is_exempt_from_volume_rules_only(self):
        ssr = "203.0.113.50"
        hetzner = {"country": "DE", "asn": 24940, "asn_name": "Hetzner Online GmbH", "ua": "node"}
        flood = {"top": [samples.talker(ssr, 4000)], "details": [samples.detail(ssr, "/api/movies", 4000, **hetzner)]}
        cfg = make_cfg(trusted_asns=frozenset({24940}))

        post = FakePost(graphql(flood))
        tick(post, state.Store(), cfg=cfg)
        self.assertEqual(post.slack, [])

        post = FakePost(graphql(flood))
        tick(post, state.Store())
        self.assertIn("API flood from", post.slack[0]["text"])

        # An attack signature from the same network still alerts.
        scan = samples.scanner_scenario(ssr)
        scan["details"] = [replace_dims(d, clientAsn=24940) for d in scan["details"]]
        post = FakePost(graphql(scan))
        tick(post, state.Store(), cfg=cfg)
        self.assertIn("Vulnerability scan from", post.slack[0]["text"])

    def test_low_volume_scanner_is_found_without_being_a_top_talker(self):
        ip = "203.0.113.66"
        rows = {
            "scanner": [samples.scanner(ip, "/.env", 12, 404), samples.scanner(ip, "/wp-login.php", 9, 404)],
            "details": [samples.detail(ip, "/.env", 12, 404), samples.detail(ip, "/wp-login.php", 9, 404)],
        }
        post = FakePost(graphql(rows))
        tick(post, state.Store())
        self.assertEqual(post.sent(q.A2_DETAILS)[0]["variables"]["filter"]["clientIP_in"], [ip])
        self.assertIn("WARNING — Vulnerability scan from", post.slack[0]["text"])

    def test_distributed_spike(self):
        details = samples.spike_details(6)
        top = [samples.talker(d["dimensions"]["clientIP"], d["count"]) for d in details]
        post = FakePost(graphql(top=top, details=details))
        tick(post, state.Store())
        self.assertEqual(len(post.slack), 1)
        self.assertIn("Distributed spike: 6 IPs each sent 500+ requests", post.slack[0]["text"])

    def test_webhook_rejections_alert_once(self):
        post, store = FakePost(graphql(webhooks=samples.forged_webhook_rows())), state.Store()
        tick(post, store)
        self.assertEqual(len(post.slack), 1)
        self.assertIn("Stripe webhook: calls keep being rejected", post.slack[0]["text"])
        self.assertIn(FORGER_IP, post.slack[0]["text"])
        tick(post, store, at=T0 + timedelta(minutes=5))
        self.assertEqual(len(post.slack), 1)

    def test_heartbeat_once_a_day(self):
        store = state.Store()
        cfg = make_cfg(heartbeat_hour_utc=0)
        post = FakePost()
        tick(post, store, cfg=cfg)
        tick(post, store, cfg=cfg, at=T0 + timedelta(minutes=5))
        self.assertEqual(len(post.slack), 1)
        self.assertIn("cf-abuse-alert is watching", post.slack[0]["text"])
        self.assertIn("1 runs · 0 failed · 0 alerts sent", post.texts()[0])
        tick(post, store, cfg=cfg, at=T0 + timedelta(days=1), now=T0 + timedelta(days=1))
        self.assertEqual(len(post.slack), 2)


def replace_dims(row: dict, **dims) -> dict:
    return {**row, "dimensions": {**row["dimensions"], **dims}}


class FailureTest(unittest.TestCase):
    def test_three_failures_alert_once_then_recover(self):
        store = state.Store()
        bad = FakePost({q.A1_TOP: {"errors": [{"message": "not authorized for that zone"}], "data": None}})
        results = [tick(bad, store, at=T0 + timedelta(minutes=5 * i)) for i in range(5)]
        self.assertFalse(any(r.ok for r in results))
        self.assertIn("not authorized", results[0].error)
        self.assertEqual(len(bad.slack), 1)
        self.assertIn("cf-abuse-alert is failing", bad.slack[0]["text"])
        self.assertIn("3 runs in a row", bad.slack[0]["text"])

        good = FakePost()
        tick(good, store, at=T0 + timedelta(minutes=30))
        self.assertIn("working again", good.slack[0]["text"])

    def test_core_query_http_error_and_timeout(self):
        for resp, kind in (((403, b'{"errors":[]}'), "GraphQL 403"), (TimeoutError("t"), "timeout")):
            r = tick(FakePost({q.B_EVENTS: resp}), state.Store())
            self.assertFalse(r.ok)
            self.assertEqual(r.error, kind)

    def test_optional_query_failure_degrades_instead_of_failing(self):
        store = state.Store()
        broken = {q.S4_INJECTION: {"errors": [{"message": "unknown field clientRequestQuery"}], "data": None}}
        posts = [FakePost(graphql(samples.scanner_scenario(), **broken)) for _ in range(4)]
        results = [tick(p, store, at=T0 + timedelta(minutes=5 * i)) for i, p in enumerate(posts)]

        # The tick still works and still alerts on what it can see.
        self.assertTrue(all(r.ok for r in results))
        self.assertEqual(list(results[0].degraded), [q.S4_INJECTION])
        self.assertIn("Vulnerability scan from", posts[0].slack[0]["text"])
        self.assertNotIn("injection_attempts", posts[0].texts()[0])

        # After three runs in a row the blind spot is reported, once.
        self.assertEqual([len(p.slack) for p in posts], [1, 0, 1, 0])
        self.assertIn("partly blind", posts[2].slack[0]["text"])
        self.assertIn("S4_InjectionPayloads", posts[2].texts()[0])
        self.assertIn("unknown field clientRequestQuery", posts[2].texts()[0])

    def test_config_error_is_a_failure(self):
        store = state.Store()

        def broken():
            raise config.ConfigError("MONITOR_HOSTS is empty — refusing to monitor the whole zone")

        post = FakePost()
        with unittest.mock.patch.dict("os.environ", {"SLACK_WEBHOOK_URL": SLACK_URL, "DRY_RUN": ""}):
            for i in range(3):
                r = run_tick(T0 + timedelta(minutes=5 * i), store=store, post=post, load_config=broken, now=lambda: T0)
        self.assertTrue(r.error.startswith("config invalid"))
        self.assertIn("MONITOR_HOSTS", post.texts()[0])

    def test_error_never_leaks_the_token(self):
        r = tick(FakePost({q.A1_TOP: (401, f"bad token {TOKEN}".encode())}), state.Store())
        self.assertEqual(r.error, "GraphQL 401")

    def test_failed_runs_show_in_the_heartbeat(self):
        store = state.Store()
        tick(FakePost({q.A1_TOP: (500, b"")}), store)
        post = FakePost()
        tick(post, store, cfg=make_cfg(heartbeat_hour_utc=0), at=T0 + timedelta(minutes=5))
        self.assertIn("1 runs · 1 failed", post.texts()[0])


class ConfigLoadTest(unittest.TestCase):
    ENV = {
        "CF_API_TOKEN": TOKEN,
        "CF_ZONE_TAG": "z",
        "SLACK_WEBHOOK_URL": SLACK_URL,
        "MONITOR_HOSTS": "API.swipedrama.com, swipedrama.com",
        "ALLOWLIST_IPS": "203.0.113.0/24,bogus",
        "THRESHOLD_MULTIPLIER": "2",
        "TRUSTED_ASNS": "AS24940, 16509",
        "DISPLAY_TIMEZONE": "ICT+7",
    }

    def load(self, **extra):
        with unittest.mock.patch.dict("os.environ", {**self.ENV, **extra}, clear=True):
            return config.load()

    def test_ok(self):
        cfg = self.load()
        self.assertEqual(cfg.monitor_hosts, ("api.swipedrama.com", "swipedrama.com"))
        self.assertEqual(len(cfg.allowlist), 1)
        self.assertEqual(cfg.threshold_multiplier, 2)
        self.assertEqual(cfg.trusted_asns, frozenset({24940, 16509}))
        self.assertEqual(cfg.display_tz.utcoffset(None), timedelta(hours=7))
        self.assertIn("/webhook/", cfg.excluded_path_prefixes)
        self.assertIn("/webhook/", cfg.webhook_prefixes)

    def test_cloudflare_names_used_by_the_metrics_proxy_are_accepted(self):
        env = {k: v for k, v in self.ENV.items() if k not in ("CF_API_TOKEN", "CF_ZONE_TAG")}
        with unittest.mock.patch.dict(
            "os.environ", {**env, "CLOUDFLARE_API_TOKEN": TOKEN, "CLOUDFLARE_ZONE_ID": "zone-x"}, clear=True
        ):
            cfg = config.load()
        self.assertEqual((cfg.cf_api_token, cfg.cf_zone_tag), (TOKEN, "zone-x"))

    def test_fail_fast(self):
        for extra in (
            {"MONITOR_HOSTS": ""},
            {"CF_API_TOKEN": ""},
            {"SLACK_WEBHOOK_URL": "hooks.slack.com/x"},
            {"THRESHOLD_MULTIPLIER": "0"},
            {"WINDOW_MINUTES": "five"},
            {"HEARTBEAT_HOUR_UTC": "24"},
            {"TRUSTED_ASNS": "hetzner"},
            {"DISPLAY_TIMEZONE": "Asia/Tokyo"},
            {"SUSTAINED_WINDOW_MINUTES": "2"},
        ):
            with self.assertRaises(config.ConfigError, msg=extra):
                self.load(**extra)

    def test_dashboard_url_with_account(self):
        self.assertIn("/acc123/swipedrama.com/security/events", self.load(CF_ACCOUNT_ID="acc123").dashboard_url)

    def test_slack_only_needs_no_cloudflare_settings(self):
        with unittest.mock.patch.dict("os.environ", {"SLACK_WEBHOOK_URL": SLACK_URL}, clear=True):
            cfg = config.load(slack_only=True)
        self.assertEqual(cfg.slack_webhook_url, SLACK_URL)


class SamplesTest(unittest.TestCase):
    def test_test_alerts_cover_every_message_kind_and_are_marked(self):
        payloads = samples.payloads(make_cfg(critical_mention="<!here>"))
        self.assertEqual(len(payloads), 4)
        for _, p in payloads:
            self.assertIn("TEST", p["text"])
            self.assertNotIn("<!here>", json.dumps(p))


if __name__ == "__main__":
    unittest.main()
