"""Aggregation, endpoint signals and rules: does traffic X raise finding Y, and nothing else."""
import unittest

from tests import helpers  # noqa: F401
import endpoints
import samples
from aggregate import (
    CandidateThresholds,
    add_details,
    collect,
    is_excluded,
    normalize_ip,
    normalize_path,
    pick_candidates,
)
from allowlist import Allowlist
from rules import (
    RULES,
    RULES_BY_ID,
    candidate_error_threshold,
    candidate_request_threshold,
    candidate_sensitive_threshold,
    early_score,
    evaluate,
    evaluate_spike,
    headline,
)
from samples import detail, event, signal

IP = "203.0.113.20"
EXCLUDED = endpoints.DEFAULT_EXCLUDED_PATH_PREFIXES
THRESHOLDS = CandidateThresholds(requests=100, errors=30, sensitive=10, events=50)


def stats_of(rows=(), **sources):
    stats = collect(
        excluded_prefixes=EXCLUDED,
        block_actions=samples.BLOCK_ACTIONS,
        rate_limit_sources=samples.RATE_LIMIT_SOURCES,
        **sources,
    )
    return add_details(
        stats, list(rows), excluded_prefixes=EXCLUDED, sensitive_methods=frozenset({"POST", "PUT", "PATCH", "DELETE"})
    )


def fired(stats, **kw) -> dict[str, str]:
    return {f.rule.id: f.severity for f in evaluate(stats, kw.pop("multiplier", 1.0), **kw)}


class PathTest(unittest.TestCase):
    def test_normalize_path(self):
        cases = {
            "/api/movies/8231/episodes/15": "/api/movies/:id/episodes/:id",
            "/api/users/3f2b9c0d-1e3a-4b6c-8d7e-9f0012345678": "/api/users/:id",
            "/api/payment/check-purchase/monthly/ord_9f8e7d6c5b4a39281f0e": "/api/payment/check-purchase/monthly/:id",
            "/img/0123456789abcdef0123456789abcdef.JPG": "/img/:id.jpg",
            "/api/movies?page=2": "/api/movies",
            "/api/v2/packages": "/api/v2/packages",
            "": "/",
        }
        for raw, norm in cases.items():
            self.assertEqual(normalize_path(raw), norm, raw)

    def test_excluded_prefixes(self):
        for path in (
            "/webhook/stripe",
            "/api/revenue-cat-webhook",
            "/api/movies/some-slug/metadata",
            "/cronjob/health-check-notify",
            "/.well-known/assetlinks.json",
            "/mcp",
            "/health/ready",
            "/api/user-missions/skyflag-missions-rewards",
        ):
            self.assertTrue(is_excluded(path, EXCLUDED), path)
        for path in ("/api/movies", "/api/user-missions", "/api/users", "/api/payment/create-payment-intent", "/token"):
            self.assertFalse(is_excluded(path, EXCLUDED), path)


class AggregateTest(unittest.TestCase):
    def test_breakdown(self):
        rows = [
            detail(IP, "/api/movies/1", 30),
            detail(IP, "/api/movies/2", 20),
            detail(IP, "/api/movies/3", 10, 404),
            detail(IP, "/api/users", 8, 401, method="POST"),
            detail(IP, "/ja/watch/x", 5, 403),
            detail(IP, "/webhook/stripe", 500),  # excluded: never counted
        ]
        s = stats_of(rows)[IP]
        self.assertTrue(s.detailed)
        self.assertEqual(s.total_requests, 73)
        self.assertEqual(s.api_requests, 68)
        self.assertEqual(s.status_4xx, 23)
        self.assertEqual(s.paths["/api/movies/:id"], 60)
        self.assertEqual(s.path_status("/api/movies/:id"), 200)
        self.assertEqual(s.id_sweep, 3)
        self.assertEqual(s.id_sweep_path, "/api/movies/:id")
        self.assertEqual(s.distinct_not_found, 1)
        self.assertEqual(s.sensitive_hits["signup"], 8)
        self.assertEqual((s.country, s.asn, s.asn_name), ("SG", 14061, "DIGITALOCEAN-ASN"))
        self.assertEqual(s.methods["GET"], 65)

    def test_reads_of_sensitive_endpoints_are_not_counted(self):
        s = stats_of([detail(IP, "/api/users", 300, method="GET"), detail(IP, "/api/user-missions", 200, method="GET")])[IP]
        self.assertEqual(sum(s.sensitive_hits.values()), 0)

    def test_edge_blocks_are_not_counted_as_origin_denials(self):
        rows = [detail(IP, "/api/x", 100, 403), detail(IP, "/api/y", 40, 401), detail(IP, "/api/z", 60, 429)]
        events = [event(IP, "/api/x") for _ in range(90)] + [
            event(IP, "/api/z", action="block", source="ratelimit") for _ in range(50)
        ]
        s = stats_of(rows, events=events)[IP]
        self.assertEqual(s.cf_blocked, 140)
        self.assertEqual(s.cf_rate_limited, 50)
        self.assertEqual(s.denied, 40)  # 401s only: the 403s were Cloudflare's
        self.assertEqual(s.server_rate_limited, 10)
        self.assertAlmostEqual(s.blocked_share, 0.7)

    def test_events_on_excluded_paths_and_skips_are_ignored(self):
        events = [event(IP, "/webhook/stripe"), event(IP, "/api/x", action="skip"), event(IP, "/api/x", action="log")]
        s = stats_of(events=events)[IP]
        self.assertEqual((s.cf_events, s.cf_blocked), (1, 0))

    def test_signals_only_count_confirmed_rows(self):
        stats = stats_of(
            scanner_rows=[samples.scanner(IP, "/.env", 5), samples.scanner(IP, "/api/environment.php5x", 7)],
            tool_rows=[samples.tool(IP, "sqlmap/1.7", 3), samples.tool(IP, "Mozilla/5.0 fuzzy-browser", 9)],
            injection_rows=[
                samples.injection(IP, "/api/movies", "?q=1+union+select+1", 4),
                samples.injection(IP, "/api/movies", "?q=union+station", 6),
                samples.injection(IP, "/api/user-missions/skyflag-missions-rewards", "?uid=<script>", 8),
            ],
        )
        s = stats[IP]
        self.assertEqual((s.scanner_hits, s.tool_hits, s.injection_hits), (5, 3, 4))
        self.assertEqual(dict(s.tools), {"sqlmap": 3})
        self.assertEqual(dict(s.injection_kinds), {"SQL injection": 4})

    def test_candidates_are_ranked_by_excess_not_volume(self):
        stats = stats_of(
            top_rows=[samples.talker("203.0.113.1", 5000), samples.talker("203.0.113.2", 150), samples.talker("203.0.113.3", 90)],
            error_rows=[samples.talker("203.0.113.4", 45)],
            sensitive_rows=[samples.talker("203.0.113.5", 900)],
            events=[event("203.0.113.6", "/api/x")],
        )
        picked = pick_candidates(stats, THRESHOLDS, allowlist=Allowlist(), limit=10)
        self.assertEqual(picked, ["203.0.113.5", "203.0.113.1", "203.0.113.2", "203.0.113.4", "203.0.113.6"])
        self.assertEqual(pick_candidates(stats, THRESHOLDS, allowlist=Allowlist(), limit=2), picked[:2])
        allow = Allowlist.parse(["203.0.113.5/32"])
        self.assertNotIn("203.0.113.5", pick_candidates(stats, THRESHOLDS, allowlist=allow, limit=10))

    def test_ip_case_and_whitespace(self):
        self.assertEqual(normalize_ip(" 2001:DB8::5 "), "2001:db8::5")


class EndpointSignalTest(unittest.TestCase):
    def test_classification(self):
        cases = [
            ("/api/payment/create-payment-intent", "POST", 201, ["purchases"]),
            ("/api/payment/create-payment-intent", "POST", 402, ["purchases", "purchase_failures"]),
            ("/api/sbp/create-session", "POST", 429, ["purchases", "payment_rate_limited"]),
            ("/api/paidy/intent/", "POST", 500, ["purchases", "purchase_failures"]),
            ("/api/payment/create-payment-intent", "GET", 404, []),
            ("/api/iap/validate", "POST", 200, []),
            ("/api/iap/validate", "POST", 400, ["iap_failures"]),
            ("/api/iap/validate-transaction", "POST", 422, ["iap_failures"]),
            ("/api/payment/setup-intent", "GET", 200, ["card_changes"]),
            ("/api/payment/payment-methods/pm_1", "DELETE", 200, ["card_changes"]),
            ("/api/payment/payment-methods/update/pm_2", "PUT", 200, ["card_changes"]),
            ("/api/payment/payment-methods", "GET", 200, []),
            ("/api/payment/check-purchase/monthly/ord_1", "GET", 200, ["purchase_checks"]),
            ("/api/admin/users", "GET", 403, ["restricted_denied"]),
            ("/api/admin", "GET", 401, ["restricted_denied"]),
            ("/api/admin/users", "GET", 200, []),
            ("/api/test-support/reset", "POST", 401, ["restricted_denied"]),
            ("/mcp/clients", "GET", 403, ["restricted_denied"]),
            ("/api/administrator", "GET", 403, []),
            ("/api/movies", "GET", 403, []),
        ]
        for path, method, status, expected in cases:
            self.assertEqual(endpoints.signals(path, method, status), expected, (path, method, status))

    def test_every_filter_row_is_classifiable(self):
        # The Cloudflare filter and the classifier must describe the same endpoints.
        for f in endpoints.signal_filters():
            self.assertTrue(
                {"clientRequestPath", "clientRequestPath_in", "clientRequestPath_like"} & set(f), f
            )
        paths = [p for f in endpoints.signal_filters() for p in f.get("clientRequestPath_in", [])]
        self.assertEqual(set(paths), set(endpoints.PURCHASE_PATHS) | set(endpoints.IAP_PATHS))

    def test_webhook_names(self):
        self.assertEqual(endpoints.webhook_name("/webhook/stripe"), "Stripe")
        self.assertEqual(endpoints.webhook_name("/api/sbp/paypay/webhook/subscription"), "SB Payment (PayPay)")
        self.assertEqual(endpoints.webhook_name("/cronjob/health-check-notify"), "Cron job")
        self.assertEqual(endpoints.webhook_name("/api/other"), "Unknown")


class RuleTest(unittest.TestCase):
    def test_rule_table_is_consistent(self):
        ids = [r.id for r in RULES]
        self.assertEqual(len(ids), len(set(ids)))
        for r in RULES:
            self.assertLess(r.warning, r.critical, r.id)
            self.assertTrue(r.title and r.meaning and r.advice and r.noun, r.id)

    def test_scanner_scenario(self):
        got = fired(samples.build_stats(samples.scanner_scenario()))
        self.assertEqual(
            got,
            {
                "scanner_paths": "CRITICAL",
                "attack_tool": "CRITICAL",
                "high_4xx_ratio": "CRITICAL",
                "cf_blocked": "CRITICAL",
                "injection_attempts": "WARNING",
            },
        )

    def test_farmer_scenario(self):
        got = fired(samples.build_stats(samples.farmer_scenario()))
        self.assertEqual(
            got, {"reward_farming": "CRITICAL", "unlock_scraping": "WARNING", "server_rate_limited": "WARNING"}
        )

    def test_ordinary_app_user_raises_nothing(self):
        kw = {"country": "JP", "asn": 2516, "asn_name": "KDDI", "ua": "SWIPEDRAMA/412 CFNetwork/1568 Darwin/24.1.0"}
        rows = [
            detail(IP, "/api/movies", 30, **kw),
            detail(IP, "/api/episode/8812", 12, **kw),
            detail(IP, "/api/episode/8813", 12, **kw),
            detail(IP, "/api/unlock-episode", 6, 201, method="POST", **kw),
            detail(IP, "/api/user-ads/get-point", 5, 201, method="POST", **kw),
            detail(IP, "/api/user-checkins/checkin", 1, 201, method="POST", **kw),
            detail(IP, "/api/users", 9, 401, **kw),
            detail(IP, "/api/payment/create-payment-intent", 2, 201, method="POST", **kw),
            detail(IP, "/api/missing", 3, 404, **kw),
        ]
        stats = stats_of(rows, signal_counts=endpoints.counters([signal(IP, "/api/payment/create-payment-intent", 2, 201)], normalize_ip))
        self.assertEqual(fired(stats), {})

    def test_each_request_rule(self):
        cases = {
            "not_found_sweep": [detail(IP, f"/admin{i}", 1, 404) for i in range(45)],
            "id_enumeration": [detail(IP, f"/api/movies/{i}", 1) for i in range(160)],
            "denied_requests": [detail(IP, "/api/users", 70, 401)],
            "auth_abuse": [detail(IP, "/api/auth/custom-token", 25, 401, method="POST")],
            "account_farming": [detail(IP, "/api/users", 12, 201, method="POST")],
            "upload_abuse": [detail(IP, "/api/s3/user/upload/sign", 22, 201, method="POST")],
            "high_api_requests": [detail(IP, "/api/movies", 1100)],
        }
        for rule_id, rows in cases.items():
            self.assertIn(rule_id, fired(stats_of(rows)), rule_id)

    def test_each_signal_rule(self):
        cases = {
            "purchase_failures": [signal(IP, "/api/payment/create-payment-intent", 16, 402)],
            "iap_validation_failures": [signal(IP, "/api/iap/validate", 11, 400)],
            "purchase_attempts": [signal(IP, "/api/sbp/create-session", 21, 201)],
            "card_churn": [signal(IP, "/api/payment/setup-intent", 13, 200, "GET")],
            "purchase_check_enumeration": [signal(IP, f"/api/payment/check-purchase/m/{i}", 1, 200, "GET") for i in range(31)],
            "payment_rate_limited": [signal(IP, "/api/paidy/token", 6, 429)],
            "restricted_denied": [signal(IP, "/api/admin/users", 11, 403, "GET")],
        }
        for rule_id, rows in cases.items():
            stats = stats_of(signal_counts=endpoints.counters(rows, normalize_ip))
            self.assertIn(rule_id, fired(stats), rule_id)
            # No detailed breakdown is needed: the signal alone makes the IP a candidate.
            self.assertGreaterEqual(early_score(stats[IP], 1.0), 1.0, rule_id)

    def test_ratio_rule_needs_a_minimum_sample(self):
        self.assertEqual(fired(stats_of([detail(IP, "/x", 99, 404)])), {})
        self.assertEqual(fired(stats_of([detail(IP, "/x", 100, 404)])), {"high_4xx_ratio": "CRITICAL"})
        # The multiplier scales the sample size of a ratio rule, not the ratio.
        self.assertEqual(fired(stats_of([detail(IP, "/x", 150, 404)]), multiplier=2.0), {})
        self.assertEqual(RULES_BY_ID["high_4xx_ratio"].thresholds(2.0), (0.5, 0.8, 200))

    def test_long_window_rule_does_not_repeat_its_burst(self):
        burst = endpoints.counters([signal(IP, "/api/sbp/create-session", 35, 201)], normalize_ip)
        self.assertEqual(fired(stats_of(signal_counts=burst, purchases_1h={IP: 36})), {"purchase_attempts": "WARNING"})
        got = fired(stats_of(signal_counts=burst, purchases_1h={IP: 70}))
        self.assertEqual(got, {"purchase_attempts": "WARNING", "purchase_attempts_1h": "CRITICAL"})
        self.assertEqual(fired(stats_of(purchases_1h={IP: 31})), {"purchase_attempts_1h": "WARNING"})

    def test_headline_is_the_most_severe_then_most_specific(self):
        findings = evaluate(samples.build_stats(samples.scanner_scenario()), 1.0)
        self.assertEqual(headline(findings).rule.id, "scanner_paths")
        warnings = [f for f in findings if f.severity == "WARNING"]
        self.assertEqual(headline(warnings).rule.id, "injection_attempts")

    def test_candidate_thresholds_follow_the_lowest_rule(self):
        self.assertEqual(candidate_request_threshold(1.0), 100)
        self.assertEqual(candidate_request_threshold(2.0), 200)
        self.assertEqual(candidate_error_threshold(1.0), 30)
        self.assertEqual(candidate_sensitive_threshold(1.0), 10)

    def test_spike(self):
        stats = add_details({}, samples.spike_details(4), excluded_prefixes=())
        self.assertIsNone(evaluate_spike(stats, 1.0))
        stats = add_details({}, samples.spike_details(5), excluded_prefixes=())
        spike = evaluate_spike(stats, 1.0)
        self.assertEqual((spike.severity, spike.ip_count), ("WARNING", 5))
        self.assertEqual(spike.ips[0].ip, "203.0.113.100")
        self.assertIsNone(evaluate_spike(stats, 1.0, Allowlist.parse(["203.0.113.100"])))


if __name__ == "__main__":
    unittest.main()
