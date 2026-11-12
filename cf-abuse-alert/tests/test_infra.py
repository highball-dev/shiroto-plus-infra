"""State store, window maths, allowlist and the health endpoint."""
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from tests import helpers  # noqa: F401
import state
from allowlist import Allowlist
from health import Health, serve
from window import Window, compute_window, floor_to_period, parse_display_tz

T0 = datetime(2026, 11, 12, 2, 35, tzinfo=timezone.utc)


class StoreTest(unittest.TestCase):
    def test_ttl(self):
        clock = [1000.0]
        store = state.Store(clock=lambda: clock[0])
        store.put("a", 1, ttl=60)
        store.put("b", 2)
        clock[0] += 59
        self.assertEqual(store.get("a"), 1)
        clock[0] += 2
        self.assertIsNone(store.get("a"))
        self.assertEqual(store.get("b"), 2)
        self.assertEqual(store.incr("n"), 1)
        self.assertEqual(store.incr("n", 4), 5)
        store.delete("b")
        self.assertIsNone(store.get("b"))

    def test_file_survives_a_restart_and_drops_expired_keys(self):
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nested", "state.json")
            store = state.Store(path, clock=lambda: clock[0])
            store.put("keep", "x", ttl=600)
            store.put("gone", "y", ttl=10)
            clock[0] += 60
            again = state.Store(path, clock=lambda: clock[0])
            self.assertEqual(again.get("keep"), "x")
            self.assertIsNone(again.get("gone"))
            self.assertEqual(os.listdir(os.path.dirname(path)), ["state.json"])

    def test_corrupt_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            for content in ("{not json", "[1, 2]", '{"a": "not-a-pair"}'):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                store = state.Store(path)
                self.assertIsNone(store.get("a"))
                store.put("b", 1)
                with open(path, encoding="utf-8") as f:
                    self.assertEqual(json.load(f)["b"][0], 1)


class DedupeTest(unittest.TestCase):
    def test_same_severity_is_suppressed_escalation_is_not(self):
        store = state.Store()
        ip, rule = "203.0.113.1", "scanner_paths"
        self.assertTrue(state.should_alert(store, ip, rule, "WARNING"))
        state.mark_alerted(store, ip, rule, "WARNING", 1800)
        self.assertFalse(state.should_alert(store, ip, rule, "WARNING"))
        self.assertTrue(state.should_alert(store, ip, rule, "CRITICAL"))
        state.mark_alerted(store, ip, rule, "CRITICAL", 1800)
        self.assertFalse(state.should_alert(store, ip, rule, "CRITICAL"))
        # A later WARNING never downgrades what was recorded.
        state.mark_alerted(store, ip, rule, "WARNING", 1800)
        self.assertFalse(state.should_alert(store, ip, rule, "CRITICAL"))
        self.assertTrue(state.should_alert(store, ip, "attack_tool", "WARNING"))
        self.assertTrue(state.should_alert(store, "203.0.113.2", rule, "WARNING"))

    def test_ipv6_keys_ignore_case(self):
        store = state.Store()
        state.mark_alerted(store, "2001:DB8::5", "r", "WARNING", 60)
        self.assertFalse(state.should_alert(store, "2001:db8::5", "r", "WARNING"))

    def test_first_seen_slides(self):
        clock = [T0.timestamp()]
        store = state.Store(clock=lambda: clock[0])
        self.assertIsNone(state.peek_first_seen(store, "203.0.113.1"))
        first = state.first_seen(store, "203.0.113.1", T0, 7200)
        clock[0] += 3600
        self.assertEqual(state.first_seen(store, "203.0.113.1", T0 + timedelta(hours=1), 7200), first)
        clock[0] += 7000
        self.assertEqual(state.peek_first_seen(store, "203.0.113.1"), first)
        clock[0] += 300
        self.assertIsNone(state.peek_first_seen(store, "203.0.113.1"))


class HealthStateTest(unittest.TestCase):
    def test_failure_alert_once_per_hour_then_recovery(self):
        store = state.Store()
        self.assertFalse(state.failure_alert_due(store, state.record_failure(store)))
        self.assertFalse(state.failure_alert_due(store, state.record_failure(store)))
        self.assertTrue(state.failure_alert_due(store, state.record_failure(store)))
        state.mark_failure_alerted(store, T0)
        self.assertFalse(state.failure_alert_due(store, state.record_failure(store)))
        self.assertTrue(state.record_success(store, T0))
        self.assertFalse(state.record_success(store, T0))

    def test_query_health_reports_after_three_in_a_row(self):
        store = state.Store()
        names = ["S2", "S4"]
        self.assertEqual(state.record_query_health(store, names, {"S4": "boom"}), [])
        self.assertEqual(state.record_query_health(store, names, {"S4": "boom"}), [])
        self.assertEqual(state.record_query_health(store, names, {"S4": "boom"}), [("S4", "boom", 3)])
        state.mark_query_alerted(store, "S4", T0)
        self.assertEqual(state.record_query_health(store, names, {"S4": "boom"}), [])
        # A success resets the streak.
        self.assertEqual(state.record_query_health(store, names, {}), [])
        self.assertEqual(state.record_query_health(store, names, {"S4": "boom", "S2": "x"}), [])

    def test_heartbeat_once_per_day_after_the_hour(self):
        store = state.Store()
        self.assertFalse(state.heartbeat_due(store, T0, 3))
        self.assertTrue(state.heartbeat_due(store, T0, 2))
        store.put("stats:runs", 7)
        state.mark_heartbeat(store, T0)
        self.assertFalse(state.heartbeat_due(store, T0 + timedelta(hours=5), 2))
        self.assertTrue(state.heartbeat_due(store, T0 + timedelta(days=1), 2))
        self.assertEqual(store.get("stats:runs"), 0)


class WindowTest(unittest.TestCase):
    def test_window_ends_lag_minutes_before_the_tick(self):
        w = compute_window(T0.replace(second=41), lag_minutes=3, window_minutes=5)
        self.assertEqual(w.iso(), ("2026-11-12T02:27:00Z", "2026-11-12T02:32:00Z"))
        self.assertEqual(w.minutes, 5)

    def test_consecutive_ticks_do_not_overlap_or_leave_gaps(self):
        a = compute_window(T0, lag_minutes=3, window_minutes=5)
        b = compute_window(T0 + timedelta(minutes=5), lag_minutes=3, window_minutes=5)
        self.assertEqual(a.end, b.start)

    def test_floor_to_period(self):
        self.assertEqual(floor_to_period(T0.replace(minute=39, second=59), 5), T0)
        self.assertEqual(floor_to_period(T0, 5), T0)
        self.assertEqual(floor_to_period(T0.replace(minute=59), 15), T0.replace(minute=45))

    def test_labels(self):
        w = Window(T0 - timedelta(minutes=5), T0)
        self.assertEqual(w.label(), "11:30–11:35 JST (02:30–02:35 UTC)")
        self.assertEqual(w.label(parse_display_tz("ICT+7")), "09:30–09:35 ICT (02:30–02:35 UTC)")
        self.assertEqual(w.label(parse_display_tz("UTC+0")), "02:30–02:35 UTC")
        self.assertEqual(w.label(parse_display_tz("IST+5:30")), "08:00–08:05 IST (02:30–02:35 UTC)")
        self.assertEqual(w.label(parse_display_tz("pst-8")), "18:30–18:35 PST (02:30–02:35 UTC)")

    def test_bad_timezone_specs(self):
        for spec in ("", "Asia/Tokyo", "JST", "+9", "JST+15", "JST+9:75"):
            with self.assertRaises(ValueError, msg=spec):
                parse_display_tz(spec)


class AllowlistTest(unittest.TestCase):
    def test_ipv4_ipv6_and_cidr(self):
        with self.assertLogs("allowlist", "WARNING"):
            allow = Allowlist.parse(["203.0.113.5", "198.51.100.0/24", "2001:db8::/32", "nope", " "])
        self.assertEqual(len(allow), 3)
        for ip in ("203.0.113.5", "198.51.100.77", "2001:db8::1", " 2001:DB8:ffff::1 "):
            self.assertTrue(allow.contains(ip), ip)
        for ip in ("203.0.113.6", "198.51.101.1", "2001:db9::1", "not-an-ip", ""):
            self.assertFalse(allow.contains(ip), ip)


class HealthEndpointTest(unittest.TestCase):
    def test_liveness_and_readiness(self):
        clock = [1000.0]
        h = Health(stale_after_seconds=900, clock=lambda: clock[0])
        self.assertTrue(h.live() and h.ready())
        for _ in range(3):
            h.record(False, "GraphQL 403")
        self.assertTrue(h.live())  # failing ticks are not a reason to restart the container
        self.assertFalse(h.ready())
        h.record(True)
        self.assertTrue(h.ready())
        clock[0] += 901
        self.assertFalse(h.live())  # the loop is stuck
        h.beat()
        self.assertTrue(h.live())

    def test_http(self):
        h = Health(stale_after_seconds=900)
        server = serve(h, 0, host="127.0.0.1")
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=5) as resp:
                body = json.load(resp)
            self.assertEqual((resp.status, body["status"]), (200, "ok"))
            self.assertEqual(
                set(body),
                {"status", "uptime_seconds", "seconds_since_beat", "stale_after_seconds", "last_tick", "last_success",
                 "consecutive_failures", "last_error"},
            )
            for _ in range(3):
                h.record(False, "timeout")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"{base}/readyz", timeout=5)
            self.assertEqual(ctx.exception.code, 503)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"{base}/anything-else", timeout=5)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()


class PostJsonTest(unittest.TestCase):
    """The real HTTP layer, against a local server."""

    @classmethod
    def setUpClass(cls):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        cls.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                cls.received.append((self.path, dict(self.headers), json.loads(body)))
                status, data = (500, b"upstream broke") if self.path == "/fail" else (200, b"ok")
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_):
                return

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_json_body_and_headers(self):
        from http_util import post_json

        status, body = post_json(f"{self.base}/ok", {"Authorization": "Bearer t"}, {"text": "héllo 🚨"}, 5)
        self.assertEqual((status, body), (200, b"ok"))
        path, headers, payload = self.received[-1]
        self.assertEqual(payload, {"text": "héllo 🚨"})
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Authorization"], "Bearer t")

    def test_http_errors_are_returned_not_raised(self):
        from http_util import post_json

        self.assertEqual(post_json(f"{self.base}/fail", {}, {}, 5), (500, b"upstream broke"))

    def test_network_errors_never_contain_the_url(self):
        from http_util import post_json

        with self.assertRaises(OSError) as ctx:
            post_json("http://127.0.0.1:1/services/SECRET", {}, {}, 2)
        self.assertNotIn("SECRET", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
