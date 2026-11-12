# cf-abuse-alert (SwipeDrama)

Every 5 minutes this service reads the **Cloudflare GraphQL Analytics API** for the `swipedrama.com`
zone, groups traffic and security events by **client IP**, and posts the IPs that look like an attack
to **Slack**: vulnerability scans, attack tools, injection payloads, brute force, reward farming,
payment abuse, floods, crawlers and forged webhook calls.

It is the edge part of [SD-1178](https://linear.app/highballwb/issue/SD-1178) (detector + 24/7 runner +
alerting). It is adapted from `xfans-infra/cf-abuse-alert` and runs the same way: one small Python
service on Northflank, no database, two small dependencies (`python-dotenv`, `certifi`).

What it does **not** cover (other phases of the SD-1178 plan): server-side `security_event` logs,
per-user detection (Cloudflare sees IPs, not accounts), Neon/Redis/Northflank resource alerts, and
vendor alerts (Cloudflare Notifications, Sentry, AWS).

## Quick start

```bash
cd cf-abuse-alert
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m unittest discover -s tests -t .          # 162 tests, no token needed

cp env.example .env                                # in this folder; fill in the three secrets and MONITOR_HOSTS
python main.py --test-alert                        # posts 4 sample alerts to Slack (only needs SLACK_WEBHOOK_URL)
python cf_probe.py --minutes 60                    # checks the token, the zone and every query
python main.py --once --dry-run                    # one tick, log only (IPs masked), nothing sent
python main.py --once                              # one tick, posts to Slack
python main.py --once --at 2026-11-12T02:35:00Z    # replay a past tick (Cloudflare keeps ~30 days)
python main.py                                     # the loop, as on Northflank
```

`python main.py --preview` prints the sample alerts as Slack JSON; paste one into
[Block Kit Builder](https://app.slack.com/block-kit-builder) to see it without a webhook.

## What an alert looks like

One message per IP. Every alert has the same sections in the same order:

```
🚨 [PROD] CRITICAL · Vulnerability scan · 203.0.113.7                ← large header
┃ IP address              Network
┃ 203.0.113.7             🇸🇬 SG · AS14061 DIGITALOCEAN-ASN
┃ Host                    Time window (5 min)
┃ api.swipedrama.com      11:27–11:32 JST (02:27–02:32 UTC)
┃ Requests                Cloudflare
┃ 383 total · 355 errors (93%)      🛡 Blocked 303 of 383 (79%)
┃ ──────────────────────────────────────────────────────────────
┃ 🚩 Why it was flagged  ·  Suspicious requests  ·  4 critical · 1 warning
┃ 🔴 Vulnerability scan — 332 probe requests · limit 60
┃ ▏ secrets / dotfiles ×188, WordPress ×58, PHP / ASP / JSP files ×41
┃ 🔴 Attack tool detected — 395 requests from the tool · limit 100
┃ ▏ nuclei ×395
┃ 🟠 Injection attempts — 16 requests with a payload · limit 5
┃ ▏ SQL injection ×9, XSS ×4, path traversal ×3
┃ ──────────────────────────────────────────────────────────────
┃ 📊 What it sent
┃ Status codes:  403 ×287 · 404 ×54 · 200 ×28 · 401 ×14
┃ Methods:  GET 100%
┃ User agent:  Nuclei - Open-source project (github.com/projectdiscovery/nuclei)
┃ Top paths  (status = the most frequent answer)
┃   REQS  STATUS  PATH
┃     96     403  /.env
┃     64     403  /.git/config
┃     58     403  /wp-login.php
┃ ──────────────────────────────────────────────────────────────
┃ 💡 What to do
┃ • Confirm in the top paths that no probe path answered 200.
┃ • Block this IP with a WAF custom rule scoped to the host (expression below).
┃ • Do not use Managed Challenge on the API host: the app and webhooks cannot solve it.
┃ WAF expression for this IP  (if you decide to block)
┃   (ip.src eq 203.0.113.7 and http.host eq "api.swipedrama.com")
┃ 🔎 Cloudflare Security Events · AbuseIPDB · ipinfo
┃ Rules: scanner_paths attack_tool high_4xx_ratio cf_blocked injection_attempts  ·  ℹ️ counts are sampled estimates
```

- **Header**: environment, severity (the worst rule of that IP), what it is (the most severe, most
  specific rule) and the IP. The same line, as text, is what Slack shows in notifications.
  `SLACK_CRITICAL_MENTION` is added on its own line under the header on CRITICAL.
- **Facts** (two columns): who (IP, country, network), where (host), when (window in
  `DISPLAY_TIMEZONE` and UTC), how much, and how much Cloudflare already stopped.
- **🚩 Why it was flagged**: one entry per rule: the measured value and the limit it crossed, then
  the evidence as a quote (which probes, which tool, which WAF rule). 🔴 critical, 🟠 warning. Rules
  already alerted for this IP come last under `⏱ Still active — first flagged HH:MM`, one ⚪ line each.
- **📊 What it sent**: one `Label:  value` per line (status codes, methods, user agent, download
  size, payments), then a table of the top paths with a header row.
- **💡 What to do**: the advice of the headline rule, one bullet per step, and a Cloudflare custom-rule
  expression for this IP and host, ready to paste. It is offered for every IP; the bullets say when
  to look at the accounts first instead of blocking.
- **Small print**: links, the ids of the rules that fired (the names to use in `DISABLED_RULES` and
  [rules.py](rules.py)), and data caveats.

The webhook, spike and overflow messages use the same header, facts grid, titled sections and small
print.

Other messages: `N more IPs over a threshold` (overflow of `MAX_ALERTS_PER_RUN`), `Distributed spike`,
`<Provider> webhook: …`, and the service's own status (`started`, daily `is watching`, `is failing`,
`is partly blind`, `is working again`).

Query strings are **never** shown: third-party callbacks (SkyFlag, MyChips, Adjust) put user ids in
them. The service reads a query string only in memory, to name the kind of payload it carries. Paths,
user agents and network names are attacker-controlled and are escaped (a `<!channel>` in a
User-Agent cannot ping the channel) and redacted (tokens, emails, long ids).

## Rules

Thresholds are **per IP per 5 minutes** (60 minutes where noted), before `THRESHOLD_MULTIPLIER`. They
live in [rules.py](rules.py). They are **starting values, not derived from SwipeDrama traffic**: see
[Rollout and tuning](#rollout-and-tuning).

**Suspicious requests**

| Rule | Alert title | What is counted | WARNING | CRITICAL |
|---|---|---|---|---|
| `scanner_paths` | Vulnerability scan | Requests for files this stack never serves (`/.env`, `/.git`, `wp-login.php`, `*.php`, `/actuator` …) | 15 | 60 |
| `attack_tool` | Attack tool detected | Requests whose User-Agent names a tool (sqlmap, nuclei, nikto, ffuf, gobuster, masscan, zgrab …) | 10 | 100 |
| `injection_attempts` | Injection attempts | SQLi / XSS / traversal / template / JNDI / prototype-pollution payloads in the path or query | 5 | 30 |
| `restricted_denied` | Admin area probing | 401/403 on `/api/admin`, `/api/test-support`, MCP client management | 10 | 40 |
| `not_found_sweep` | Path enumeration | Distinct paths answered 404 (directory brute force) | 40 | 150 |
| `denied_requests` | Access-denied burst | 401s plus the 403s the origin answered | 60 | 200 |
| `high_4xx_ratio` | Mostly failing requests | Share of 4xx, only when the IP sent ≥ 100 requests | 50% | 80% |

**Abnormal user behaviour**

| Rule | Alert title | What is counted | WARNING | CRITICAL |
|---|---|---|---|---|
| `auth_abuse` | Login / token abuse | Writes² to `/api/auth/*`, `/token`, `/register`, `/revoke` | 20 | 60 |
| `account_farming` | Account farming | Writes² to `/api/users`, `/api/users/device` | 10 | 30 |
| `reward_farming` | Reward farming | Writes² to `/api/user-missions`, `/api/user-ads`, `/api/user-checkins`, `/api/user-onboard-checkins`, `/api/user-bonus`, `/api/user-referrals` | 40 | 120 |
| `unlock_scraping` | Episode unlock burst | `POST /api/unlock-episode` | 60 | 200 |
| `upload_abuse` | Upload abuse | `POST /api/s3/user/upload/sign` | 20 | 60 |
| `purchase_attempts` | Purchase burst | Payment attempts: Stripe intent / checkout / saved method, Paidy intent / token, SBP session / saved card / 3DS | 20 | 40 |
| `purchase_attempts_1h` | Purchasing all hour long | Same, over **60 min** | 30 | 60 |
| `purchase_failures` | Failed purchases | Those calls answered 4xx/5xx (not 429) | 15 | 30 |
| `iap_validation_failures` | Rejected IAP receipts | `POST /api/iap/validate*` answered 4xx/5xx | 10 | 30 |
| `card_churn` | Card add/remove churn | `GET /api/payment/setup-intent`, `DELETE`/`PUT /api/payment/payment-methods/*` | 12 | 25 |
| `purchase_check_enumeration` | Purchase-check enumeration | `GET /api/payment/check-purchase/:name/:external_id` (no auth guard) | 30 | 100 |
| `payment_rate_limited` | Payment rate limit hit | 429 on `/api/payment`, `/api/paidy`, `/api/sbp`, `/api/iap` | 5 | 20 |

**Scanning / infrastructure**

| Rule | Alert title | What is counted | WARNING | CRITICAL |
|---|---|---|---|---|
| `id_enumeration`¹ | ID enumeration | Distinct IDs requested on one endpoint (`/api/movies/:id`) | 150 | 500 |
| `high_api_requests`¹ | API flood | Requests to `/api/*` | 1,000 | 3,000 |
| `high_total_requests`¹ | Request flood | All requests | 1,500 | 5,000 |
| `server_rate_limited` | API rate limit hit | 429 from the API's own throttler | 30 | 150 |
| `cf_blocked` | Blocked by Cloudflare | Requests blocked or challenged by Cloudflare | 50 | 300 |
| `cf_rate_limited` | Cloudflare rate limit hit | Requests stopped by a Cloudflare rate-limiting rule | 20 | 100 |
| `high_bytes`¹ | Heavy download | Bytes downloaded | 2 GB | 10 GB |
| `media_requests`¹ | Media crawling | Requests to `MEDIA_HOSTS` / `MEDIA_PATH_PREFIXES` (off unless set) | 600 | 2,000 |
| `sustained_requests`¹ | Slow, sustained crawl | All requests over **60 min** | 10,000 | 30,000 |
| `distributed_spike` | Distributed spike | Number of IPs that each sent ≥ 500 requests | 5 IPs | 20 IPs |

¹ Volume rule: skipped for IPs in `TRUSTED_ASNS` (our own SSR). Attack-signature rules are never skipped.
The network of an IP is only known when it has traffic in the current 5-minute window, so the
60-minute rules can still alert for a trusted network's IP that has just gone quiet; `ALLOWLIST_IPS`
has no such gap.
² `SENSITIVE_METHODS`, default `POST,PUT,PATCH,DELETE`. Reads are not counted.

**Webhooks and callbacks** (Stripe, Apple, RevenueCat, SB Payment, Paidy, Bunny, Tally, Adjust, SkyFlag,
MyChips, AppLovin, our Lambdas and `/cronjob/*`) are excluded from every rule above and checked
separately:

| Rule | When | Severity |
|---|---|---|
| `webhook_rejected` | One IP gets ≥ 5 answers 400/401/403 on a webhook path in a window (400 is what Stripe and MyChips answer to a bad signature). Needs no setup | WARNING, CRITICAL from 30 |
| `webhook_unknown_path` | A path under `WEBHOOK_PREFIXES` with no profile | CRITICAL if answered 2xx, else WARNING |
| `webhook_unknown_asn` | Caller's network is not in the path's profile | CRITICAL if answered 2xx, else WARNING |
| `webhook_unknown_ua` | Right network, user agent does not match | CRITICAL if answered 2xx, else WARNING |
| `webhook_new_ip` | Right network and UA, unknown IP that keeps sending (≥ 20 in a window, 3 windows in a row, or ≥ 50 in 60 min); immediately if the profile is `strict` | WARNING / CRITICAL |

The last four need `webhook_sources.json` (who really calls each webhook). Build it from 30 days of
Cloudflare history, review it, commit it:

```bash
python cf_webhook_baseline.py --days 30
```

Only IPs that got a 2xx are recorded as known. `official_ips`, `strict` and `name` added by hand survive
a regeneration. `"ips": "*"` turns the new-IP check off for rotating pools. The profile is a monitoring
layer only; the real protection is each provider's signature check on the server.

### Dedupe

- Per **(IP, rule)**, 30 minutes (60 for the 60-minute rules, 1–6 hours for webhook rules).
- A message is sent when an IP has a **new** rule or a rule **escalated** to CRITICAL. It also lists the
  IP's other active rules as _already alerted_; those do not get their dedupe window extended.
- More than `MAX_ALERTS_PER_RUN` (10) IPs in one tick: the rest go into one summary message of up to
  30 lines. IPs beyond those 30 are not marked as alerted and are reported on the next run if they are
  still active. Webhook alerts have the same cap and their own summary.
- A burst that a burst rule reported is not reported again by its 60-minute rule
  (`purchase_attempts` → `purchase_attempts_1h`) unless more calls follow it.

### When Slack does not answer

- A post that fails on something temporary (timeout, network error, 429, 5xx) is tried three times
  within the tick (after 1 s and 3 s). A refused payload (4xx) is not retried.
- After two messages in a row could not be delivered, the rest of that tick's messages are not
  attempted, so a Slack outage cannot make a tick overrun.
- An undelivered alert is **not** marked as alerted. It is sent on the next run **only if the IP is
  still over a threshold then**; an event that lasted a single window is lost, and the log says so:
  `tick HH:MMZ: N message(s) could not be delivered to Slack` and `UNDELIVERED=N` on the tick line.
  Three such ticks in a row turn `/readyz` to 503 (`last_error: slack delivery failed`). Slack cannot
  be told about its own outage, so a revoked webhook URL shows only there, in the log, and as a
  missing daily heartbeat.

## How it works

```
main.py        loop + one tick: queries → per-IP stats → candidates → breakdown → rules → dedupe → Slack
cf_graphql.py  GraphQL client and the queries (table below)
signatures.py  what a suspicious request looks like: scanner paths, attack tools, injection payloads
endpoints.py   SwipeDrama endpoint map: sensitive groups, payment signals, webhooks, excluded paths
aggregate.py   rows → IpStats, path normalisation, candidate ranking
rules.py       rules, thresholds, alert wording
webhooks.py    webhook_rejected + source profiles
slack.py       Block Kit messages and delivery
state.py       dedupe, first-seen, health counters (memory, optionally a file)
config.py      env → Config, fails fast
health.py      opt-in /healthz and /readyz
samples.py     made-up traffic for --test-alert, --preview and the tests
cf_probe.py    setup tool: runs every query against the real zone
cf_webhook_baseline.py  builds webhook_sources.json
tests/         162 tests with a fake Cloudflare and Slack
```

| Query | Purpose | If it fails |
|---|---|---|
| `A1_TopTalkers` | Top 100 IPs by requests | tick fails |
| `B_SecurityEvents` | What the WAF / rate limiting / bot protection did | tick fails |
| `A2_CandidateDetails` | Path, method, status, network, UA for up to 50 candidate IPs | tick fails |
| `A3_SensitiveTalkers` | Top IPs writing to sensitive endpoints | degraded |
| `A4_TopBytes` / `A5_MediaTalkers` / `A6_SustainedTalkers` | Top IPs by bytes / on media / over 60 min | degraded |
| `A7_EndpointSignals` / `A8_PurchaseTalkers` | Payment and restricted-area calls per IP | degraded |
| `A9_WebhookRequests` | Every webhook / callback call with its network and UA | degraded |
| `S1_ErrorTalkers` | Top IPs by 4xx (a scanner is rarely a top talker) | degraded |
| `S2_ScannerPaths` / `S3_AttackTools` / `S4_InjectionPayloads` | Requests matching the signatures | degraded |

All queries are aggregated by Cloudflare, so memory does not grow with traffic. Candidates are ranked by
**how far they exceed a threshold**, not by request count, so a scanner with 30 requests is not pushed
out by heavy ordinary users.

A failed **degraded** query does not stop the tick: the rules it feeds are blind for that run, the log
says `DEGRADED <query>`, and after 3 runs in a row Slack gets "cf-abuse-alert is partly blind".

Timing: the loop runs at :00, :05, :10 … UTC. Each tick looks at the 5 minutes that ended
`INGEST_LAG_MINUTES` (3) earlier, because Cloudflare analytics lag behind. An attack is therefore
reported **8–13 minutes** after it starts.

Each tick logs one line:

```
tick 05:40Z ok: window 14:32–14:37 JST (05:32–05:37 UTC) · A1=100 B=37 A3=12 … S4=3 · candidates=6 · findings=9 · sent=3 · deduped=0
```

## Deploy to Northflank

Each environment is **its own service** with the same image: `cf-abuse-alert-nonprod` and
`cf-abuse-alert-prod`, each with its own token, hosts and Slack channel. Run it in a project separate
from the production backend: its credentials are read-only, keep them away from the API's secrets.

### 0. Prerequisites

1. **Cloudflare API token** for this service only. Manage Account → Account API Tokens → Create →
   Custom token: permission **Zone → Analytics → Read**, zone resources **swipedrama.com** only. Do not
   reuse the metrics proxy's token (it can read WAF, DNS and Access).
2. **Zone ID**: zone Overview → API → Zone ID.
3. **Slack incoming webhook** for a private channel (e.g. `#sd-security-alerts`; a second one for
   non-prod). api.slack.com/apps → your app → Incoming Webhooks → Add New Webhook to Workspace.
4. This folder pushed to a Git repository that Northflank can read.

Then locally, before the first deploy: `python main.py --test-alert` and `python cf_probe.py`.

### 1. Secret group

Project → Secrets → Create secret group `cf-abuse-alert-nonprod`, type **Runtime**, restricted to the
service below: `CF_API_TOKEN`, `CF_ZONE_TAG`, `SLACK_WEBHOOK_URL`.

### 2. Service

Create service → **Combined service**:

| Setting | Value |
|---|---|
| Repository / branch | this repo / `main` |
| Build type | Dockerfile |
| Dockerfile location | `/cf-abuse-alert/Dockerfile` |
| Build context | `/cf-abuse-alert` |
| Build rules → path filter | `cf-abuse-alert/**` |
| Resources | `nf-compute-10` (0.1 vCPU / 256 MB) |
| **Instances** | **1**, no autoscaling. Two replicas would send every alert twice |
| Ports | one **private** HTTP port `8080` (health check only). Never public |
| Health check | Liveness · HTTP · `8080` · `/healthz` · initial delay 15 s · interval 60 s · timeout 5 s · failure threshold 3 |

Runtime variables (non-prod):

```
ENVIRONMENT_LABEL=NON-PROD
MONITOR_HOSTS=stg-api.swipedrama.com,stg.swipedrama.com
ALLOWLIST_IPS=<office, QA, load-test runner>
DRY_RUN=true
CF_ACCOUNT_ID=<account id, so the Slack link opens Security Events directly>
PORT=8080
```

Production differs in: `ENVIRONMENT_LABEL=PROD`, `MONITOR_HOSTS=api.swipedrama.com,swipedrama.com`,
`THRESHOLD_MULTIPLIER=2` for the first weeks, `SLACK_CRITICAL_MENTION=<!here>` (or the on-call user
group), `STATE_FILE=/data/state.json`, and `TRUSTED_ASNS=24940` or, better, the SSR egress IPs in
`ALLOWLIST_IPS`.

Do **not** use `/readyz` as the liveness probe: a Cloudflare outage or an expired token fails every
tick, and restarting the container fixes neither. Those cases reach Slack after 3 failed ticks.

### 3. Volume (recommended for prod)

Without one, every restart re-sends, once, the alerts for IPs still over a threshold. Volumes → Add
volume, 1 GB, mounted at `/data`; set `STATE_FILE=/data/state.json`.

### 4. Check

- Boot log: `cf-abuse-alert [NON-PROD] hosts=… · rules=28 · … · dry_run=True · state=memory`
- Slack: `🟢 cf-abuse-alert started` (not in dry run)
- One `tick HH:MMZ ok: …` line every 5 minutes
- A daily `💚 … is watching` message at `HEARTBEAT_HOUR_UTC` (0 UTC = 09:00 JST)

> **Why a service and not a Northflank cron job?** Dedupe, the new-IP history and the failure counter
> live in the process. A cron job starts a fresh container every run and would need Redis for that
> state. One always-on 0.1 vCPU container is simpler and cheaper to reason about.

## Rollout and tuning

| Step | Where | Move on when |
|---|---|---|
| 0 | Local: `--test-alert`, `cf_probe.py` | Sample alerts look right in Slack; every query is `OK` |
| 1 | Northflank non-prod, `DRY_RUN=true`, 1–2 days | No `failed` / `DEGRADED` lines; `findings` look reasonable |
| 2 | Non-prod, `DRY_RUN=false`, simulate (below) | Each simulation raises one alert; dedupe and heartbeat work |
| 3 | Prod service, `THRESHOLD_MULTIPLIER=2`, 1–2 weeks | False positives written down |
| 4 | Retune `rules.py`, extend the allowlist, `THRESHOLD_MULTIPLIER=1` | The channel is quiet when nothing is wrong |

Tuning target per rule: WARNING ≈ 3 × p99 and CRITICAL ≈ 5–10 × p99 of a normal IP over 5 minutes at
the JST evening peak. Rules most likely to need it on SwipeDrama:

- `denied_requests`: the web client always sends `Authorization` (even `Bearer null`), so logged-out
  browsing produces 401s.
- `reward_farming`, `unlock_scraping`, `account_farming`: carrier CGNAT puts many real phones behind one IP.
- `id_enumeration`: swiping through a feed requests many episode ids.
- `high_*_requests`: web SSR (Hetzner). Allowlist its IPs or set `TRUSTED_ASNS`.

A rule that is too noisy before it is tuned can be switched off with `DISABLED_RULES=<id>,<id>`. An
id that does not exist is a configuration error, not a silent no-op.

### Simulating on staging

Never on production. Tell the team first, run from a machine **not** in `ALLOWLIST_IPS`, and keep the
traffic going for about 7 minutes so one full window contains it.

```bash
API=https://stg-api.swipedrama.com

# scanner_paths + not_found_sweep (+ cf_blocked if the WAF stops it)
for p in .env .git/config wp-login.php phpmyadmin/ actuator/env backup.sql; do
  for i in $(seq 1 6); do curl -s -o /dev/null "$API/$p"; done
done

# attack_tool
for i in $(seq 1 15); do curl -s -o /dev/null -A "sqlmap/1.8 (test by $USER)" "$API/api/v2/packages"; done

# injection_attempts
for i in $(seq 1 8); do curl -s -o /dev/null "$API/api/v2/packages?q=1%27%20UNION%20SELECT%201--"; done

# webhook_rejected: an unsigned call the server must refuse
for i in $(seq 1 8); do curl -s -o /dev/null -X POST "$API/webhook/stripe" -d '{}'; done
```

Each block should raise exactly one alert 8–13 minutes later, and nothing on the following ticks.

## Runbook

1. Open **Cloudflare Security Events** from the alert and filter by the IP: paths, user agent, actions, timing.
2. Decide:
   - Our own client, a provider or the office → add the IP to `ALLOWLIST_IPS` (or the path to
     `EXCLUDED_PATH_PREFIXES`).
   - Cloudflare already blocked nearly all of it (the alert says so) → nothing to do; watch for a change of pattern.
   - Scan / tool / injection that **reached the origin** (2xx or 5xx on a probe or payload path) → check
     the server logs for that route, then block.
   - `reward_farming` / `unlock_scraping` / `account_farming` → look at the accounts behind the IP
     (`/fraud/cohorts`, `/fraud/devices` in the metrics proxy) before blocking: it may be a shared carrier IP.
   - Payment rules → `/payments/error-codes` for the window; tell the payment provider about card testing.
   - Flood → block with a WAF custom rule scoped to the host (the alert gives the expression). **Do not use Managed
     Challenge on `api.swipedrama.com`**: the app and the webhooks cannot solve it.
3. `Distributed spike` → check Cloudflare's own DDoS alerts and the origin's CPU / Neon connections.
4. `webhook_rejected` from the provider's real network → its secret or signature is out of sync, or the
   WAF is blocking it: events are being lost, fix it first.
5. `cf-abuse-alert is failing` → Northflank logs. `GraphQL 403`: token expired or wrong permission.
   `GraphQL 429`: GraphQL quota shared with another tool. `config invalid`: bad env. `timeout`:
   Cloudflare slow, usually gone by the next tick.
6. `cf-abuse-alert is partly blind` → run `python cf_probe.py`; it prints a hint for the failing query.
   If Cloudflare rejects `S2`/`S3`/`S4` as too complex, shorten the `*_LIKES` lists in `signatures.py`
   (the regexes below them decide what counts; the LIKE lists only pre-filter).

## Security

- The token only has **Analytics Read** on one zone. Secrets live in the Northflank secret group or
  `.env` (git-ignored).
- Full IPs go **only** to the private Slack channel. Logs and `DRY_RUN` always mask them (`203.0.113.x`).
- Logs never contain the token, the webhook URL, a response body or a query string.
- The health port serves uptime and tick status only; it cannot trigger a tick. Keep it private.
- Tests and samples only use documentation IP ranges.
