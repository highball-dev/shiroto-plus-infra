import unittest

from tests import helpers  # noqa: F401
import signatures as sig


class ScannerPathTest(unittest.TestCase):
    def test_probe_paths_are_classified(self):
        cases = {
            "/.env": "secrets / dotfiles",
            "/api/.env.production": "secrets / dotfiles",
            "/.git/config": "secrets / dotfiles",
            "/.aws/credentials": "secrets / dotfiles",
            "/wp-login.php": "WordPress",
            "/blog/wp-admin/setup-config.php": "WordPress",
            "/xmlrpc.php": "WordPress",
            "/index.php": "PHP / ASP / JSP files",
            "/shell.jsp": "PHP / ASP / JSP files",
            "/phpMyAdmin/": "admin panels",
            "/actuator/env": "debug endpoints",
            "/server-status": "debug endpoints",
            "/cgi-bin/luci": "appliance / middleware exploits",
            "/backup.sql": "backups / dumps",
        }
        for path, kind in cases.items():
            self.assertEqual(sig.scanner_kind(path), kind, path)

    def test_real_paths_are_not_probes(self):
        for path in (
            "/",
            "/api/users",
            "/api/movies/123/metadata",
            "/.well-known/apple-app-site-association",
            "/.well-known/assetlinks.json",
            "/api/environment",
            "/api/admin/users",
            "/ja/watch/some-drama",
            "/api/phpish",
            "/health",
            "/favicon.ico",
            "/_next/static/chunks/main.js",
        ):
            self.assertIsNone(sig.scanner_kind(path), path)

    def test_query_string_is_ignored(self):
        self.assertIsNone(sig.scanner_kind("/api/movies?file=/.env"))

    def test_every_like_pattern_selects_paths_the_regexes_confirm(self):
        # A LIKE pattern the regexes never confirm would only waste rows of the query limit.
        unconfirmed = []
        for like in sig.SCANNER_PATH_LIKES:
            body = like.strip("%")
            path = ("/x" if like.startswith("%") and not body.startswith("/") else "") + body
            if like.endswith("%") and not body.endswith("/"):
                path += "" if "." in body.rsplit("/", 1)[-1] else "/x"
            if sig.scanner_kind(path) is None:
                unconfirmed.append((like, path))
        self.assertEqual(unconfirmed, [])


class AttackToolTest(unittest.TestCase):
    def test_tools(self):
        cases = {
            "sqlmap/1.7.2#stable (https://sqlmap.org)": "sqlmap",
            "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)": "nuclei",
            "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)": "nikto",
            "Fuzz Faster U Fool v2.1.0": "ffuf",
            "gobuster/3.6": "gobuster",
            "feroxbuster/2.10.1": "feroxbuster",
            "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)": "wpscan",
            "Mozilla/5.0 zgrab/0.x": "zgrab",
            "masscan/1.3 (https://github.com/robertdavidgraham/masscan)": "masscan",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)": "nmap",
            "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)": "censys",
            "Mozilla/5.0 (X11; Linux) OWASP ZAP/2.14": "OWASP ZAP",
        }
        for ua, tool in cases.items():
            self.assertEqual(sig.attack_tool(ua), tool, ua)

    def test_real_clients_are_not_tools(self):
        for ua in (
            "SWIPEDRAMA/412 CFNetwork/1568.200.51 Darwin/24.1.0",
            "okhttp/4.12.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
            "python-httpx/0.27.0",
            "python-requests/2.31.0",
            "Go-http-client/2.0",
            "node",
            "Stripe/1.0 (+https://stripe.com/docs/webhooks)",
            "curl/8.5.0",
            "",
        ):
            self.assertIsNone(sig.attack_tool(ua), ua)

    def test_every_like_pattern_selects_agents_the_regexes_confirm(self):
        known = {
            "%uclei%": "Nuclei", "%ikto%": "Nikto/2.5", "%obuster%": "gobuster/3.6", "%irbuster%": "dirbuster",
            "%irBuster%": "DirBuster-1.0", "%eroxbuster%": "feroxbuster/2", "%fuzz/%": "Wfuzz/3.1",
            "%cunetix%": "Acunetix", "%essus%": "Nessus", "%penVAS%": "OpenVAS", "%penvas%": "openvas",
            "%ydra%": "Hydra", "%rachni%": "Arachni/v1", "%etsparker%": "Netsparker", "%ZAP%": "OWASP ZAP/2",
            "%asscan%": "masscan/1.3", "%map Scripting%": "Nmap Scripting Engine", "%Fuzz Faster%": "Fuzz Faster U Fool",
        }
        for like in sig.TOOL_UA_LIKES:
            ua = known.get(like, like.strip("%"))
            self.assertIsNotNone(sig.attack_tool(ua), (like, ua))


class InjectionTest(unittest.TestCase):
    def test_payloads(self):
        cases = [
            ("/api/movies", "?q=1' UNION SELECT null,version()--", "SQL injection"),
            ("/api/movies", "?q=1%27%20UNION%20SELECT%20null--", "SQL injection"),
            ("/api/movies", "?id=1+or+1=1", "SQL injection"),
            ("/api/movies", "?id=1;SELECT%20pg_sleep(5)", "SQL injection"),
            ("/api/movies", "?q=%3Cscript%3Ealert(1)%3C/script%3E", "XSS"),
            ("/api/movies", "?q=%253Cscript%253E", "XSS"),  # double-encoded
            ("/api/movies", "?next=javascript:alert(1)", "XSS"),
            ("/api/v2/packages", "?id=../../../../etc/passwd", "path traversal"),
            ("/api/..%2f..%2f..%2fetc/passwd", "", "path traversal"),
            ("/api/movies", "?q=${jndi:ldap://x.test/a}", "Log4Shell / JNDI"),
            ("/api/movies", "?q={{7*7}}", "template injection"),
            ("/api/users", "?__proto__[admin]=true", "prototype pollution"),
            ("/api/users", "?constructor[prototype][admin]=true", "prototype pollution"),
            ("/api/users", "?email[$ne]=x", "NoSQL operator injection"),
            ("/api/movies", "?q=;cat /etc/hostname", "command injection"),
            ("/api/movies", "?url=http://169.254.169.254/latest/meta-data/", "cloud metadata SSRF"),
        ]
        for path, query, kind in cases:
            self.assertEqual(sig.injection_kind(path, query), kind, (path, query))

    def test_ordinary_requests_carry_no_payload(self):
        cases = [
            ("/api/movies", "?q=love+story&page=2"),
            ("/api/movies", "?description=a+script+for+a+drama"),
            ("/api/movies", "?sort=created_at&order=desc"),
            ("/api/movies", "?q=select+your+plan"),
            ("/api/movies", "?q=union+station"),
            ("/api/user-missions/skyflag-missions-rewards", "?uid=abc123&point=10"),
            ("/api/payment/check-purchase/monthly/ord_1", ""),
            ("/ja/watch/rock-and-roll", "?utm_source=line&utm_medium=social"),
            ("/api/movies", '?filter={"genre":"romance"}'),
            ("/api/movies", "?price=100$&cur=jpy"),
            ("/api/movies", "?redirect=https://swipedrama.com/ja/watch/x"),
            ("/api/movies", ""),
        ]
        for path, query in cases:
            self.assertIsNone(sig.injection_kind(path, query), (path, query))


class RedactionTest(unittest.TestCase):
    def test_secrets_and_personal_data_are_removed(self):
        self.assertEqual(sig.redact("token=abc123&x=1"), "token=<redacted>&x=1")
        self.assertEqual(
            sig.redact("access_token=abc&password=hunter2"), "access_token=<redacted>&password=<redacted>"
        )
        self.assertEqual(sig.redact("mail to a.user+x@example.co.jp now"), "mail to <email> now")
        self.assertIn("<token>", sig.redact("/reset/9f8e7d6c5b4a39281f0e9d8c7b6a5f4e3d2c1b0a"))
        self.assertIn("<number>", sig.redact("card 4242 4242 4242 4242"))

    def test_safe_path_drops_the_query_and_truncates(self):
        self.assertEqual(sig.safe_path("/api/x?uid=secret-user"), "/api/x")
        self.assertEqual(sig.safe_path("/a%20b/%2e%2e/c"), "/a b/../c")
        long = sig.safe_path("/" + "a" * 300)
        self.assertEqual(len(long), 80)
        self.assertTrue(long.endswith("…"))
        self.assertEqual(sig.safe_path("/x\n/y"), "/x /y")


if __name__ == "__main__":
    unittest.main()
