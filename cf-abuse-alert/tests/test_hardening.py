"""Things that must not break the watcher: hostile input, a failing Slack, bad configuration, overruns."""
import http.client
import os
import tempfile
import time
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone

from tests.helpers import HOST, SLACK_URL, TOKEN, FakePost, graphql, make_cfg
import cf_graphql as q
import config
import http_util
import samples
import signatures as sig
import slack
import state
from aggregate import CandidateThresholds, pick_candidates
from allowlist import Allowlist
from main import next_tick, run_tick
from rules import (
    candidate_error_threshold,
    candidate_request_threshold,
    candidate_sensitive_threshold,
    candidate_volume_threshold,
    warning_threshold,
)

T0 = datetime(2026, 11, 12, 2, 35, tzinfo=timezone.utc)
IP = "203.0.113.30"
PURCHASE = "/api/payment/create-payment-intent"


def tick(post, store, cfg=None, at=T0):
    cfg = cfg or make_cfg()
    return run_tick(at, store=store, post=post, load_config=lambda: cfg, now=lambda: at)


def seconds(fn, *args) -> float:
    start = time.perf_counter()
    fn(*args)
    return time.perf_counter() - start


class HostileInputTest(unittest.TestCase):
    """One crafted request must not be able to stall a tick."""

    def test_sql_comment_padding_is_matched_quickly(self):
        self.assertEqual(sig.injection_kind("/api/movies", "q=1'/**/UNION/**/ALL/**/SELECT/**/1"), "SQL injection")
        padded = "q=union" + "/**/" * 400 + "x+select"
        self.assertLess(seconds(sig.injection_kind, "/api/movies", padded), 0.5)
        self.assertLess(seconds(sig.injection_kind, "/api/movies", "q=" + "/*" * 5000), 0.5)

    def test_long_request_lines_are_handled_quickly(self):
        dotted = "/" + "pin." * 4000 + "php"
        self.assertLess(seconds(sig.safe_path, dotted), 0.5)
        self.assertLess(seconds(sig.scanner_kind, dotted), 0.5)
        self.assertLess(seconds(sig.injection_kind, dotted, "a=" + "'or " * 3000), 0.5)
        self.assertLess(seconds(sig.attack_tool, "sqlma" * 5000), 0.5)
        self.assertLess(seconds(sig.redact, "a@" + "b." * 6000), 0.5)

    def test_a_long_line_is_cut_without_leaving_half_a_secret(self):
        token = "tok_" + "A1b2" * 20
        cut = sig.redact("/x/" + "seg/" * 35 + token)  # the token straddles the cut
        self.assertNotIn("tok_", cut)
        self.assertTrue(cut.endswith("…"))
        self.assertNotIn("alice", sig.redact("/x/" + "seg/" * 36 + "alice.somebody@example.com"))
        # A long word that is not a secret stays readable.
        self.assertEqual(sig.safe_path("/" + "a" * 300), "/" + "a" * 78 + "…")

    def test_addresses_in_a_path_are_redacted(self):
        self.assertEqual(
            sig.safe_path("/api/callback/adjust/user@example.com/203.0.113.99"), "/api/callback/adjust/<email>/<ip>"
        )
        self.assertEqual(sig.safe_path("/api/v2.10.3/packages"), "/api/v2.10.3/packages")


class SenderTest(unittest.TestCase):
    def sender(self, post):
        return slack.Sender(SLACK_URL, dry_run=False, post=post)

    def test_temporary_failures_are_retried(self):
        for first in ((500, b"err"), (429, b"rate_limited"), TimeoutError("timeout"), OSError("network error: X")):
            calls = []

            def post(url, headers, payload, timeout, first=first, calls=calls):
                calls.append(payload)
                if len(calls) == 1:
                    if isinstance(first, Exception):
                        raise first
                    return first
                return 200, b"ok"

            sender = self.sender(post)
            with self.assertLogs("slack", "ERROR"):
                self.assertTrue(sender.send({"text": "x"}, "s"))
            self.assertEqual(len(calls), 2)
            self.assertEqual(sender.undelivered, 0)

    def test_a_refused_payload_is_not_retried(self):
        post = FakePost(slack_status=400, slack_body=b"invalid_payload")
        sender = self.sender(post)
        with self.assertLogs("slack", "ERROR"):
            self.assertFalse(sender.send({"text": "x"}, "s"))
        self.assertEqual(len(post.slack), 1)
        self.assertEqual(sender.undelivered, 1)

    def test_stops_trying_once_slack_is_clearly_down(self):
        post = FakePost(slack_status=503, slack_body=b"down")
        sender = self.sender(post)
        with self.assertLogs("slack", "ERROR") as logs:
            results = [sender.send({"text": str(i)}, f"message {i}") for i in range(5)]
        self.assertEqual(results, [False] * 5)
        self.assertEqual(len(post.slack), 2 * 3, "two messages, three attempts each, then no more posts")
        self.assertEqual(sender.undelivered, 5)
        self.assertIn("slack unavailable — not sent: message 4", "\n".join(logs.output))

    def test_never_raises_and_never_logs_what_the_exception_says(self):
        def post(*_):
            raise ValueError(f"unknown url type: {SLACK_URL!r}")

        with self.assertLogs("slack", "ERROR") as logs:
            self.assertFalse(self.sender(post).send({"text": "x"}, "s"))
        self.assertNotIn("SECRETSECRET", "\n".join(logs.output))
        self.assertIn("ValueError", "\n".join(logs.output))

    def test_post_json_reports_a_bad_url_without_repeating_it(self):
        with self.assertRaises(OSError) as raised:
            http_util.post_json("hooks.slack.test/services/T000/B000/SECRETSECRET", {}, {"text": "x"}, 1)
        self.assertEqual(str(raised.exception), "invalid URL")


class TickSurvivesTest(unittest.TestCase):
    def test_reporting_a_failure_cannot_end_the_loop(self):
        def broken():
            raise config.ConfigError("MONITOR_HOSTS is empty")

        def post(*_):
            raise RuntimeError(f"boom {SLACK_URL}")

        store = state.Store()
        with unittest.mock.patch.dict("os.environ", {"SLACK_WEBHOOK_URL": SLACK_URL, "DRY_RUN": ""}):
            with self.assertLogs(level="ERROR") as logs:
                for i in range(4):
                    r = run_tick(T0 + timedelta(minutes=5 * i), store=store, post=post, load_config=broken, now=lambda: T0)
                    self.assertFalse(r.ok)
        self.assertNotIn("SECRETSECRET", "\n".join(logs.output))

    def test_an_unreadable_dry_run_never_posts(self):
        def broken():
            raise config.ConfigError("DRY_RUN must be true or false, got 'ture'")

        post, store = FakePost(), state.Store()
        with unittest.mock.patch.dict("os.environ", {"SLACK_WEBHOOK_URL": SLACK_URL, "DRY_RUN": "ture"}):
            with self.assertLogs(level="INFO"):
                for i in range(3):
                    run_tick(T0 + timedelta(minutes=5 * i), store=store, post=post, load_config=broken, now=lambda: T0)
        self.assertEqual(post.slack, [])

    def test_an_optional_query_that_breaks_mid_response_only_degrades_the_tick(self):
        data = graphql(samples.scanner_scenario())
        data[q.S4_INJECTION] = http.client.IncompleteRead(b"")
        post, store = FakePost(data), state.Store()
        with self.assertLogs("main", "WARNING"):
            r = tick(post, store)
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.degraded, {q.S4_INJECTION: "IncompleteRead"})
        self.assertEqual(len(post.slack), 1)

    def test_undelivered_alerts_are_reported_and_sent_again_while_still_active(self):
        store = state.Store()
        down = FakePost(graphql(samples.scanner_scenario()), slack_status=503, slack_body=b"down")
        with self.assertLogs(level="ERROR") as logs:
            r = tick(down, store)
        self.assertTrue(r.ok)
        self.assertEqual((r.sent, r.undelivered), (0, 1))
        self.assertIn("1 message(s) could not be delivered to Slack", "\n".join(logs.output))

        up = FakePost(graphql(samples.scanner_scenario()))
        r = tick(up, store, at=T0 + timedelta(minutes=5))
        self.assertEqual((r.sent, r.undelivered), (1, 0))


class CountingTest(unittest.TestCase):
    def test_hourly_purchases_are_summed_across_hosts(self):
        rows = [samples.talker(IP, 40, host=HOST), samples.talker(IP, 25, host="swipedrama.com")]
        post = FakePost(graphql(purchases=rows))
        tick(post, state.Store(), make_cfg(monitor_hosts=(HOST, "swipedrama.com")))
        self.assertEqual(len(post.slack), 1)
        self.assertIn("CRITICAL — Purchasing all hour long", post.slack[0]["text"])
        self.assertIn("*65* purchase calls in the last 60 min", post.texts()[0])

    def test_a_reported_burst_is_not_reported_again_as_an_hourly_pattern(self):
        store = state.Store()
        burst = FakePost(graphql(signals=[samples.signal(IP, PURCHASE, 35, 201)], purchases=[samples.talker(IP, 35)]))
        tick(burst, store)
        self.assertEqual(len(burst.slack), 1)
        self.assertIn("Purchase burst", burst.slack[0]["text"])

        # Five minutes later the same 35 calls are still inside the hour, and nothing is new.
        after = FakePost(graphql(purchases=[samples.talker(IP, 35)]))
        tick(after, store, at=T0 + timedelta(minutes=5))
        self.assertEqual(after.slack, [])

        # 25 more calls trickle in below the 5-minute limit: that is the hourly pattern.
        slow = FakePost(graphql(purchases=[samples.talker(IP, 60)]))
        tick(slow, store, at=T0 + timedelta(minutes=30))
        self.assertEqual(len(slow.slack), 1)
        self.assertIn("Purchasing all hour long", slow.slack[0]["text"])

    def test_a_low_volume_abuser_is_not_crowded_out_by_busy_ips(self):
        busy = [samples.talker(f"198.51.100.{i}", 300) for i in range(60)]
        stats = samples.build_stats({"top": busy, "sensitive": [samples.talker(IP, 25)]})
        picked = pick_candidates(
            stats,
            CandidateThresholds(
                requests=candidate_request_threshold(1.0),
                volume=candidate_volume_threshold(1.0),
                errors=candidate_error_threshold(1.0),
                sensitive=candidate_sensitive_threshold(1.0),
                events=warning_threshold("cf_blocked", 1.0),
            ),
            allowlist=Allowlist(),
            limit=50,
        )
        self.assertEqual(picked[0], IP)
        self.assertEqual(len(picked), 50)


class OverflowTest(unittest.TestCase):
    def test_ips_the_summary_does_not_name_are_reported_on_the_next_run(self):
        ips = [f"203.0.113.{i}" for i in range(1, 46)]
        data = graphql(scanner=[samples.scanner(ip, "/.env", 20) for ip in ips])
        store = state.Store()
        first = FakePost(data)
        tick(first, store)
        self.assertEqual(len(first.slack), 11)
        self.assertIn("35 more IPs over a threshold", first.slack[-1]["text"])
        self.assertIn("… and 5 more, reported on the next run if still active", first.texts()[-1])

        second = FakePost(data)
        tick(second, store, at=T0 + timedelta(minutes=5))
        self.assertEqual(len(second.slack), 5)

    def test_webhook_alerts_are_capped_per_run(self):
        rows = [samples.webhook(f"192.0.2.{i}", "/webhook/stripe", 9 + i, 400) for i in range(1, 9)]
        store, cfg = state.Store(), make_cfg(max_alerts_per_run=3)
        first = FakePost(graphql(webhooks=rows))
        r = tick(first, store, cfg)
        self.assertEqual(len(first.slack), 4)
        self.assertIn("5 more webhook callers flagged", first.slack[-1]["text"])
        self.assertIn("`192.0.2.1`  ·  *Stripe* `/webhook/stripe`  ·  10 calls  ·  calls keep being rejected", first.texts()[-1])
        self.assertEqual(r.sent, 4)

        second = FakePost(graphql(webhooks=rows))
        tick(second, store, cfg, at=T0 + timedelta(minutes=5))
        self.assertEqual(second.slack, [])


class StateTest(unittest.TestCase):
    def test_a_second_outage_within_the_hour_is_reported(self):
        store = state.Store()
        for _ in range(3):
            failures = state.record_failure(store)
        self.assertTrue(state.failure_alert_due(store, failures))
        state.mark_failure_alerted(store, T0)
        self.assertFalse(state.failure_alert_due(store, state.record_failure(store)))
        self.assertTrue(state.record_success(store, T0))
        for _ in range(3):
            failures = state.record_failure(store)
        self.assertTrue(state.failure_alert_due(store, failures))

    def test_a_fresh_start_after_the_heartbeat_hour_does_not_post_a_heartbeat(self):
        afternoon = T0.replace(hour=14)
        fresh = state.Store()
        state.skip_heartbeat_after_boot(fresh, afternoon, 0)
        self.assertFalse(state.heartbeat_due(fresh, afternoon, 0))
        self.assertTrue(state.heartbeat_due(fresh, afternoon + timedelta(days=1), 0))

        restored = state.Store()
        restored.put("stats:runs", 120)
        state.skip_heartbeat_after_boot(restored, afternoon, 0)
        self.assertTrue(state.heartbeat_due(restored, afternoon, 0), "a restored store still owes today's heartbeat")

    def test_an_unwritable_state_file_falls_back_to_memory_and_says_so_once(self):
        with tempfile.TemporaryDirectory() as d:
            blocker = os.path.join(d, "not-a-folder")
            with open(blocker, "w", encoding="utf-8") as f:
                f.write("x")
            store = state.Store(os.path.join(blocker, "state.json"))
            with self.assertLogs("state", "WARNING") as logs:
                store.put("a", 1)
                store.put("b", 2)
            self.assertEqual(len(logs.output), 1)
            self.assertTrue(store.write_error)
            self.assertEqual((store.get("a"), store.get("b")), (1, 2))


class ScheduleTest(unittest.TestCase):
    def at(self, hour, minute, second=0):
        return datetime(2026, 11, 12, hour, minute, second, tzinfo=timezone.utc)

    def test_ticks_follow_the_clock(self):
        self.assertEqual(next_tick(None, self.at(2, 31, 40), 5), (self.at(2, 35), 0))
        self.assertEqual(next_tick(self.at(2, 35), self.at(2, 35, 20), 5), (self.at(2, 40), 0))

    def test_a_tick_that_overran_is_followed_by_the_windows_it_delayed(self):
        # The 02:35 tick finished at 02:47: 02:40 and 02:45 are overdue and run at once.
        self.assertEqual(next_tick(self.at(2, 35), self.at(2, 47), 5), (self.at(2, 40), 0))
        self.assertEqual(next_tick(self.at(2, 40), self.at(2, 47, 30), 5), (self.at(2, 45), 0))
        self.assertEqual(next_tick(self.at(2, 45), self.at(2, 48), 5), (self.at(2, 50), 0))

    def test_a_long_stall_drops_the_oldest_windows_and_says_how_many(self):
        self.assertEqual(next_tick(self.at(2, 35), self.at(3, 31), 5), (self.at(3, 20), 8))


class ConfigTest(unittest.TestCase):
    ENV = {"CF_API_TOKEN": TOKEN, "CF_ZONE_TAG": "zone-x", "SLACK_WEBHOOK_URL": SLACK_URL, "MONITOR_HOSTS": HOST}

    def load(self, **extra):
        with unittest.mock.patch.dict("os.environ", {**self.ENV, **extra}, clear=True):
            return config.load()

    def test_values_that_used_to_be_accepted_silently(self):
        cases = {
            "DRY_RUN": ("ture", "DRY_RUN must be true or false"),
            "THRESHOLD_MULTIPLIER": ("0.001", "THRESHOLD_MULTIPLIER must be between 0.1 and 100"),
            "DISABLED_RULES": ("scanner_paths,Reward_Farming,nope", "unknown rule id(s) Reward_Farming, nope"),
            "WINDOW_MINUTES": ("7", "WINDOW_MINUTES must divide 60"),
        }
        for name, (value, message) in cases.items():
            with self.assertRaises(config.ConfigError) as raised:
                self.load(**{name: value})
            self.assertIn(message, str(raised.exception), name)

    def test_valid_values(self):
        cfg = self.load(
            DRY_RUN="off", THRESHOLD_MULTIPLIER="2", DISABLED_RULES="scanner_paths,distributed_spike,webhook_new_ip"
        )
        self.assertFalse(cfg.dry_run)
        self.assertEqual(cfg.threshold_multiplier, 2.0)
        self.assertEqual(cfg.disabled_rules, {"scanner_paths", "distributed_spike", "webhook_new_ip"})
        self.assertTrue(self.load(DRY_RUN="TRUE").dry_run)

    def test_only_this_folders_env_file_is_loaded(self):
        import inspect

        source = inspect.getsource(config)
        self.assertIn('os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")', source)
        self.assertNotIn("or None)", source)


if __name__ == "__main__":
    unittest.main()
