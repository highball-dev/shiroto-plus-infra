import json
import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import SLACK_URL, FakePost, make_cfg
import samples
import slack
from rules import evaluate, evaluate_spike
from samples import detail
from aggregate import add_details
from window import Window

END = datetime(2026, 11, 12, 2, 32, tzinfo=timezone.utc)
WINDOW = Window(END - timedelta(minutes=5), END)
IP = "203.0.113.30"


def alert(scenario: dict, cfg=None, **kw) -> dict:
    findings = evaluate(samples.build_stats(scenario), 1.0)
    return slack.build_ip_alert(cfg or make_cfg(), WINDOW, findings, **kw)


def blocks(payload: dict) -> list[dict]:
    return payload["attachments"][0]["blocks"]


def header(payload: dict) -> str:
    return payload["blocks"][0]["text"]["text"]


def section(payload: dict, title: str) -> str:
    """Text of the titled section, e.g. "Why it was flagged"."""
    found = [
        b["text"]["text"]
        for b in blocks(payload)
        if b["type"] == "section" and title in b.get("text", {}).get("text", "")
    ]
    return "\n".join(found)


def all_text(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False)


class HelpersTest(unittest.TestCase):
    def test_mask_ip(self):
        self.assertEqual(slack.mask_ip("203.0.113.10"), "203.0.113.x")
        self.assertEqual(slack.mask_ip("2001:db8::5"), "2001:db8:…")
        self.assertEqual(slack.mask_ip("garbage"), "ip?")

    def test_flag(self):
        self.assertEqual(slack.flag("JP"), "🇯🇵")
        self.assertEqual(slack.flag("sg"), "🇸🇬")
        for unknown in (None, "", "XX", "T1", "Japan", "1A"):
            self.assertEqual(slack.flag(unknown), "🌐")

    def test_numbers(self):
        self.assertEqual(slack.num(1234567), "1,234,567")
        self.assertEqual(slack.fmt_bytes(512), "512 B")
        self.assertEqual(slack.fmt_bytes(3 * 1024**3), "3.0 GB")
        self.assertEqual(slack.pct(1, 0), "0%")

    def test_network_leaves_out_unknown_parts(self):
        self.assertEqual(slack.network("JP", 17676, "SoftBank Corp."), "🇯🇵 JP · AS17676 SoftBank Corp.")
        self.assertEqual(slack.network(None, 16509, "AMAZON-02"), "AS16509 AMAZON-02")
        self.assertEqual(slack.network("JP", None), "🇯🇵 JP")
        self.assertEqual(slack.network(None, None), "unknown")


class LayoutHelpersTest(unittest.TestCase):
    def test_table_has_a_header_row_and_right_aligned_numbers(self):
        got = slack.table(("REQS", "STATUS", "PATH"), [("1,204", 200, "/api/movies"), ("7", "-", "/a`b\n<!here>")])
        self.assertEqual(
            got.split("\n"),
            ["```", " REQS  STATUS  PATH", "1,204     200  /api/movies", "    7       -  /a'b &lt;!here&gt;", "```"],
        )

    def test_table_truncates_the_last_column_only(self):
        got = slack.table(("REQS", "PATH"), [("5", "/" + "a" * 200)])
        self.assertIn("   5  /" + "a" * 62 + "…", got)

    def test_status_codes(self):
        from collections import Counter

        self.assertEqual(slack.status_codes(Counter({403: 287, 404: 54, 0: 9})), "`403` ×287 · `404` ×54")
        many = Counter({200 + i: 10 - i for i in range(7)})
        self.assertTrue(slack.status_codes(many).endswith("· +2 more"))
        self.assertEqual(slack.status_codes(Counter()), "n/a")

    def test_steps_are_one_sentence_each(self):
        self.assertEqual(
            slack.steps("Check /payments/error-codes for this window. Many cards from one IP is card testing: block it."),
            ["Check /payments/error-codes for this window.", "Many cards from one IP is card testing: block it."],
        )
        self.assertEqual(slack.bullets(["Only one."]), "Only one.")
        self.assertEqual(slack.bullets(["A.", "B."]), "• A.\n• B.")

    def test_every_rule_gives_clean_steps(self):
        from rules import RULES

        for rule in RULES:
            got = slack.steps(rule.advice)
            self.assertTrue(got, rule.id)
            for step in got:
                self.assertRegex(step, r"^[A-Z].*[.!?]$", f"{rule.id}: {step!r}")
                self.assertNotRegex(step, r"[a-z]\.[A-Z]", f"{rule.id}: two sentences glued together")

    def test_waf_expression(self):
        self.assertEqual(
            slack.waf_expression("203.0.113.7", {"api.swipedrama.com"}),
            '(ip.src eq 203.0.113.7 and http.host eq "api.swipedrama.com")',
        )
        self.assertEqual(
            slack.waf_expression("2001:db8::5", {"swipedrama.com", "api.swipedrama.com"}),
            '(ip.src eq 2001:db8::5 and http.host in {"api.swipedrama.com" "swipedrama.com"})',
        )
        self.assertEqual(slack.waf_expression("203.0.113.7", set()), "(ip.src eq 203.0.113.7)")
        # A host that is not a plain hostname is left out; a value that is not an IP gives no expression.
        self.assertEqual(slack.waf_expression("203.0.113.7", {'x" or true'}), "(ip.src eq 203.0.113.7)")
        self.assertEqual(slack.waf_expression("203.0.113.7 or true", {"a.test"}), "")

    def test_long_sections_continue_in_a_new_block_without_cutting_a_line(self):
        lines = [f"line {i} " + "x" * 400 for i in range(20)]
        got = slack._sections("TITLE", lines)
        self.assertGreater(len(got), 1)
        joined = "\n".join(b["text"]["text"] for b in got)
        self.assertEqual(joined.split("\n"), ["TITLE", *lines])
        for b in got:
            self.assertLessEqual(len(b["text"]["text"]), 3000)


class IpAlertTest(unittest.TestCase):
    def test_the_first_line_says_who_what_and_how_bad(self):
        p = alert(samples.scanner_scenario(), make_cfg(environment_label="PROD"))
        self.assertEqual(p["text"], "🚨 *[PROD] CRITICAL — Vulnerability scan from* `203.0.113.7`")
        self.assertEqual(header(p), "🚨 [PROD] CRITICAL · Vulnerability scan · 203.0.113.7")
        self.assertEqual(p["blocks"][0]["type"], "header")
        self.assertEqual(p["attachments"][0]["color"], slack.COLOR["CRITICAL"])
        self.assertTrue(header(alert(samples.scanner_scenario(), test=True)).startswith("🧪 TEST · 🚨 [NON-PROD] CRITICAL"))

    def test_sections_come_in_a_fixed_order_with_dividers_between(self):
        shape = []
        for b in blocks(alert(samples.scanner_scenario())):
            text = b.get("text", {}).get("text", "")
            titled = [t for t in (slack.WHY, slack.SENT, slack.TODO) if text.startswith(t)]
            shape.append("fields" if "fields" in b else titled[0] if titled else b["type"])
        self.assertEqual(
            shape,
            [
                "fields",
                "divider",
                slack.WHY,
                "divider",
                slack.SENT,
                "section",  # the path table
                "divider",
                slack.TODO,
                "section",  # the WAF expression
                "context",
                "context",
            ],
        )

    def test_facts(self):
        facts = {f["text"].split("\n")[0]: f["text"].split("\n")[1] for f in blocks(alert(samples.scanner_scenario()))[0]["fields"]}
        self.assertEqual(facts["*IP address*"], "`203.0.113.7`")
        self.assertEqual(facts["*Network*"], "🇸🇬 SG · AS14061 DIGITALOCEAN-ASN")
        self.assertEqual(facts["*Host*"], "api.swipedrama.com")
        self.assertEqual(facts["*Time window (5 min)*"], "11:27–11:32 JST (02:27–02:32 UTC)")
        self.assertEqual(facts["*Requests*"], "*383* total · 355 errors (93%)")
        self.assertEqual(facts["*Cloudflare*"], "🛡 Blocked *303* of 383 (79%)")

    def test_rules_are_listed_most_important_first_with_evidence(self):
        p = alert(samples.scanner_scenario())
        why = section(p, "Why it was flagged")
        lines = why.split("\n")
        self.assertEqual(lines[0], "🚩 *Why it was flagged*  ·  Suspicious requests  ·  4 critical · 1 warning")
        self.assertEqual(lines[1], "🔴 *Vulnerability scan* — *332* probe requests · limit 60")
        self.assertEqual(lines[2], ">secrets / dotfiles ×188, WordPress ×58, PHP / ASP / JSP files ×41")
        titles = [line.split("*")[1] for line in lines[1::2]]
        self.assertEqual(
            titles,
            ["Vulnerability scan", "Attack tool detected", "Mostly failing requests", "Blocked by Cloudflare", "Injection attempts"],
        )
        self.assertIn("🟠 *Injection attempts* — *16* requests with a payload · limit 5", why)
        self.assertIn(">SQL injection ×9, XSS ×4, path traversal ×3", why)
        self.assertIn("*93%* of requests are 4xx · limit 80%", why)
        # Rule ids (for DISABLED_RULES and tuning) sit in the small print, in the same order.
        self.assertIn(
            "Rules: `scanner_paths` `attack_tool` `high_4xx_ratio` `cf_blocked` `injection_attempts`",
            blocks(p)[-1]["elements"][0]["text"],
        )

    def test_what_it_did_and_what_to_do(self):
        p = alert(samples.scanner_scenario())
        text = all_text(p)
        sent = section(p, "What it sent")
        self.assertIn("*Status codes:*  `403` ×287 · `404` ×54 · `200` ×28 · `401` ×14", sent)
        self.assertIn("*Methods:*  GET 100%", sent)
        self.assertIn("*User agent:*  `Nuclei - Open-source project (github.com/projectdiscovery/nuclei)`", sent)
        table = [b["text"]["text"] for b in blocks(p) if "REQS" in b.get("text", {}).get("text", "")][0]
        self.assertEqual(
            table.split("\n")[:5],
            [
                "*Top paths*  _(status = the most frequent answer)_",
                "```",
                "REQS  STATUS  PATH",
                "  96     403  /.env",
                "  64     403  /.git/config",
            ],
        )
        self.assertEqual(
            section(p, "What to do").split("\n"),
            [
                "💡 *What to do*",
                "• Confirm in the top paths that no probe path answered 200.",
                "• Block this IP with a WAF custom rule scoped to the host (expression below).",
                "• Do not use Managed Challenge on the API host: the app and webhooks cannot solve it.",
            ],
        )
        expression = [b["text"]["text"] for b in blocks(p) if "WAF expression" in b.get("text", {}).get("text", "")][0]
        self.assertTrue(expression.endswith('```\n(ip.src eq 203.0.113.7 and http.host eq "api.swipedrama.com")\n```'))
        self.assertIn("https://www.abuseipdb.com/check/203.0.113.7", text)
        self.assertIn("counts are sampled estimates", text)

    def test_payload_query_strings_never_reach_slack(self):
        text = all_text(alert(samples.scanner_scenario()))
        for fragment in ("UNION", "version()", "alert(1)", "etc/passwd", "%27"):
            self.assertNotIn(fragment, text)

    def test_user_behaviour_alert(self):
        p = alert(samples.farmer_scenario())
        text = all_text(p)
        self.assertIn("Reward farming from", p["text"])
        self.assertEqual(header(p), "🚨 [NON-PROD] CRITICAL · Reward farming · 198.51.100.24")
        self.assertIn("🚩 *Why it was flagged*  ·  Abnormal user behaviour  ·  1 critical · 2 warnings", text)
        self.assertIn("🇯🇵 JP · AS17676 SoftBank Corp.", text)
        self.assertIn("No action taken", text)
        self.assertIn(" 127     201  /api/user-ads/get-point", text)
        self.assertIn("*Methods:*  POST 78% · GET 22%", text)
        # A single piece of advice is a plain sentence, not a list.
        self.assertEqual(
            section(p, "What to do").split("\n")[1],
            "Check the accounts behind this IP in /fraud/cohorts before blocking; consider freezing their points.",
        )

    def test_attacker_controlled_strings_cannot_inject_slack_markup(self):
        evil_ua = "<!channel> <https://evil.test|click> `x` & *bold*"
        evil_path = "/<!here>/```/<@U123>"
        rows = [detail(IP, evil_path, 150, 404, ua=evil_ua, asn_name="<!everyone> Hosting")]
        text = all_text(slack.build_ip_alert(make_cfg(), WINDOW, evaluate(samples.build_stats({"details": rows}), 1.0)))
        for raw in ("<!channel>", "<!here>", "<!everyone>", "<@U123>", "<https://evil.test"):
            self.assertNotIn(raw, text)
        self.assertIn("&lt;!channel&gt;", text)
        self.assertIn("&amp; *bold*", text)
        self.assertIn("/&lt;!here&gt;/'''/&lt;@U123&gt;", text)

    def test_long_values_are_truncated(self):
        rows = [detail(IP, "/" + "a" * 500, 150, 404, ua="B" * 900)]
        p = slack.build_ip_alert(make_cfg(), WINDOW, evaluate(samples.build_stats({"details": rows}), 1.0))
        self.assertNotIn("a" * 70, all_text(p))
        self.assertNotIn("B" * 170, all_text(p))

    def test_every_message_is_valid_block_kit(self):
        cfg = make_cfg(critical_mention="<!here>")
        many_rules = evaluate(samples.build_stats(samples.scanner_scenario()), 0.01)
        payloads = [p for _, p in samples.payloads(cfg)] + [
            alert(samples.scanner_scenario(), cfg),
            slack.build_ip_alert(cfg, WINDOW, many_rules),
            slack.build_summary(cfg, WINDOW, [many_rules] * 40),
            slack.build_failure("PROD", "x" * 900, 3, None),
            slack.build_degraded("PROD", [("S4_InjectionPayloads", "e" * 900, 3)] * 14),
            slack.build_recovered("PROD"),
            slack.build_heartbeat(cfg, 288, 4, 1, None),
            slack.build_started(cfg, 28, 0),
        ]
        for p in payloads:
            self.assertTrue(p["text"])
            top = p.get("blocks", [])
            if top:
                self.assertEqual(top[0]["type"], "header")
                self.assertEqual(top[0]["text"]["type"], "plain_text")
                self.assertLessEqual(len(top[0]["text"]["text"]), 150)
                self.assertNotRegex(top[0]["text"]["text"], r"[*`_<>]")
            self.assertEqual(len(p["attachments"]), 1)
            card = blocks(p)
            self.assertTrue(card, "an attachment without blocks is rejected by Slack")
            self.assertLessEqual(len(top) + len(card), 50)
            for b in top + card:
                self.assertIn(b["type"], ("header", "section", "divider", "context"))
                if b["type"] == "section" and "text" in b:
                    self.assertTrue(b["text"]["text"].strip())
                    self.assertLessEqual(len(b["text"]["text"]), 3000)
                    self.assertEqual(b["text"]["text"].count("```") % 2, 0, "a code block was cut in half")
                for f in b.get("fields", []):
                    self.assertLessEqual(len(f["text"]), 2000)
                self.assertLessEqual(len(b.get("fields", [])), 10)
                for e in b.get("elements", []):
                    self.assertTrue(e["text"].strip())
                    self.assertLessEqual(len(e["text"]), 2000)

    def test_an_ip_that_trips_many_rules_keeps_every_rule(self):
        findings = evaluate(samples.build_stats(samples.scanner_scenario()), 0.01)
        self.assertGreater(len(findings), 8)
        why = section(slack.build_ip_alert(make_cfg(), WINDOW, findings), "*Why it was flagged*")
        for f in findings:
            self.assertIn(f"*{f.rule.title}* — ", why)

    def test_critical_mention_only_on_critical(self):
        cfg = make_cfg(critical_mention="<!here>")
        p = alert(samples.scanner_scenario(), cfg)
        self.assertTrue(p["text"].endswith("<!here>"))
        # `text` only feeds notifications once there is a header, so the mention is also a visible block.
        self.assertEqual(p["blocks"][1]["text"]["text"], "<!here>")
        self.assertEqual(len(alert(samples.scanner_scenario())["blocks"]), 1)
        warning_only = {"details": [detail(IP, "/api/users", 12, 201, method="POST")]}
        self.assertNotIn("<!here>", all_text(alert(warning_only, cfg)))
        self.assertNotIn("<!here>", all_text(alert(samples.scanner_scenario(), cfg, test=True)))

    def test_already_alerted_rules_are_dimmed_and_first_seen_is_shown(self):
        findings = evaluate(samples.build_stats(samples.farmer_scenario()), 1.0)
        fresh = [f for f in findings if f.rule.id == "server_rate_limited"]
        p = slack.build_ip_alert(make_cfg(), WINDOW, findings, fresh=fresh, first_seen="2026-11-12T02:05:00Z")
        text = all_text(p)
        # The header keeps the worst severity of the IP, the title names what is new.
        self.assertIn("CRITICAL — API rate limit hit from", p["text"])
        self.assertIn("🟠 *API rate limit hit*", text)
        self.assertEqual(header(p), "🚨 [NON-PROD] CRITICAL · API rate limit hit · 198.51.100.24")
        why = section(p, "Why it was flagged").split("\n")
        self.assertEqual(why[1], "🟠 *API rate limit hit* — *35* 429 responses · limit 30")
        self.assertEqual(why[3], "⏱ _Still active — first flagged 11:05 JST. Already alerted and still over the limit:_")
        self.assertEqual(why[4:], ["⚪ Reward farming — 176 reward claims", "⚪ Episode unlock burst — 74 unlock calls"])

    def test_ip_without_detailed_breakdown(self):
        stats = samples.build_stats({"scanner": [samples.scanner(IP, "/.env", 20), samples.scanner(IP, "/.git/config", 5)]})
        text = all_text(slack.build_ip_alert(make_cfg(), WINDOW, evaluate(stats, 1.0)))
        self.assertIn("_not in the detailed sample_", text)
        self.assertIn("*Probe paths*", text)
        self.assertIn("REQS  STATUS  PATH\\n  20       -  /.env", text)
        self.assertNotIn("Status codes", text)

    def test_display_timezone(self):
        cfg = make_cfg(display_tz=timezone(timedelta(hours=7), "ICT"))
        self.assertIn("09:27–09:32 ICT (02:27–02:32 UTC)", all_text(alert(samples.scanner_scenario(), cfg)))

    def test_bytes_rule(self):
        gib = 1024**3
        rows = {"bytes": [samples.talker(IP, 40, 3 * gib)], "details": [detail(IP, "/api/export", 40, nbytes=3 * gib)]}
        text = all_text(alert(rows))
        self.assertIn("Heavy download from", text)
        self.assertIn("*3.0 GB* downloaded · limit 2.0 GB", text)
        self.assertIn("*Downloaded:*  3.0 GB in 5 min, 76.8 MB/request", text)


class OtherMessagesTest(unittest.TestCase):
    def test_summary(self):
        groups = [
            evaluate(samples.build_stats(samples.scanner_scenario()), 1.0),
            evaluate(samples.build_stats(samples.farmer_scenario()), 1.0),
        ]
        p = slack.build_summary(make_cfg(), WINDOW, groups)
        text = all_text(p)
        self.assertIn("2 more IPs over a threshold", p["text"])
        self.assertEqual(header(p), "🚨 [NON-PROD] 2 more IPs over a threshold")
        self.assertIn("🔴 `203.0.113.7`  ·  *Vulnerability scan* +4 more  ·  🇸🇬 SG · AS14061", text)
        self.assertIn("*2*  ·  2 critical", text)
        self.assertIn("`198.51.100.24`", text)

    def test_spike(self):
        stats = add_details({}, samples.spike_details(8), excluded_prefixes=())
        p = slack.build_spike(make_cfg(), WINDOW, evaluate_spike(stats, 1.0))
        text = all_text(p)
        self.assertIn("WARNING — Distributed spike: 8 IPs each sent 500+ requests", p["text"])
        self.assertEqual(header(p), "⚠️ [NON-PROD] WARNING · Distributed spike · 8 IPs")
        self.assertIn("*8* IPs with 500+ requests each · limit 5 IPs", text)
        self.assertIn("REQS  FROM  IP\\n 900    BR  203.0.113.100", text)
        self.assertIn("• Check Cloudflare's own DDoS alerts", text)
        self.assertIn("🇧🇷 BR ×2", text)

    def test_status_messages(self):
        cfg = make_cfg(environment_label="PROD")
        failure = slack.build_failure("PROD", "GraphQL 403", 3, "2026-11-12T02:30:00Z")
        self.assertIn("cf-abuse-alert is failing* — 3 runs in a row", failure["text"])
        self.assertIn("`GraphQL 403`", all_text(failure))
        degraded = slack.build_degraded("PROD", [("S4_InjectionPayloads", "GraphQL errors (1): unknown field", 3)])
        self.assertIn("partly blind", degraded["text"])
        self.assertIn("`S4_InjectionPayloads`", all_text(degraded))
        self.assertIn("working again", slack.build_recovered("PROD")["text"])
        beat = all_text(slack.build_heartbeat(cfg, 288, 4, 1, "2026-11-12T02:30:00Z"))
        self.assertIn("288 runs · 1 failed · 4 alerts sent", beat)
        self.assertIn("11:30 JST", beat)
        started = all_text(slack.build_started(cfg, 28, 0))
        self.assertIn("cf-abuse-alert started", started)
        self.assertIn("every 5 min · data lag 3 min", started)
        for p in (failure, degraded, slack.build_recovered("PROD")):
            self.assertTrue(p["attachments"][0]["blocks"], "an attachment without blocks is rejected by Slack")


class SenderTest(unittest.TestCase):
    def test_send(self):
        post = FakePost()
        self.assertTrue(slack.Sender(SLACK_URL, dry_run=False, post=post).send({"text": "x"}, "s"))
        self.assertEqual(post.slack, [{"text": "x"}])

    def test_dry_run_posts_nothing(self):
        post = FakePost()
        with self.assertLogs("slack", "INFO"):
            self.assertTrue(slack.Sender(SLACK_URL, dry_run=True, post=post).send({"text": "x"}, "s"))
        self.assertEqual(post.slack, [])

    def test_failures_return_false_and_never_log_the_url(self):
        def boom(*_):
            raise OSError("network error: gaierror")

        cases = (FakePost(slack_status=500, slack_body=b"err"), FakePost(slack_body=b"invalid_payload"), boom)
        for post in cases:
            with self.assertLogs("slack", "ERROR") as logs:
                self.assertFalse(slack.Sender(SLACK_URL, dry_run=False, post=post).send({"text": "x"}, "s"))
            self.assertNotIn("SECRETSECRET", "\n".join(logs.output))
        with self.assertLogs("slack", "ERROR"):
            self.assertFalse(slack.Sender("", dry_run=False, post=FakePost()).send({"text": "x"}, "s"))


if __name__ == "__main__":
    unittest.main()
