"""What a suspicious request looks like.

Two layers per signal:
- LIKE patterns sent to Cloudflare (`%` = any characters). They are deliberately coarse and only
  narrow down which rows Cloudflare returns.
- Regexes applied here to every returned row. They decide what actually counts.

Nothing in this file is specific to one IP or one customer; it describes requests that this stack
(NestJS API, Next.js web/admin) never serves or never receives from a real client.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

# --------------------------------------------------------------------------------------
# 1. Scanner paths: files and panels a vulnerability scanner asks for.
# --------------------------------------------------------------------------------------

SCANNER_PATH_LIKES: tuple[str, ...] = (
    # secrets and VCS metadata
    "%/.env%", "%/.git/%", "%/.gitconfig%", "%/.aws/%", "%/.ssh/%", "%/.svn/%", "%/.hg/%",
    "%/.DS_Store%", "%/.htaccess%", "%/.htpasswd%", "%/.npmrc%", "%/.dockerenv%", "%/.vscode/%",
    # other stacks
    "%.php", "%.php/%", "%.asp", "%.aspx", "%.jsp", "%.cgi",
    "%/wp-admin%", "%/wp-content%", "%/wp-includes%", "%/wp-json%", "%/wordpress%",
    # panels and debug endpoints
    "%/phpmyadmin%", "%/phpMyAdmin%", "%/adminer%", "%/actuator%", "%/server-status%",
    "%/server-info%", "%/_profiler%", "%/telescope%", "%/_ignition%",
    # appliances and middleware
    "%/cgi-bin/%", "%/solr/%", "%/jenkins%", "%/manager/html%", "%/boaform%", "%/HNAP1%",
    "%/owa/%", "%/autodiscover%",
    # dumps
    "%.sql", "%.bak", "%/vendor/phpunit%",
)

_SCANNER_RULES: tuple[tuple[str, re.Pattern], ...] = (
    (
        "secrets / dotfiles",
        re.compile(
            r"(^|/)\.(env|git|gitconfig|aws|ssh|svn|hg|ds_store|htaccess|htpasswd|npmrc|dockerenv|"
            r"vscode|idea|bash_history)(\.[\w-]+)*(/|$)",
            re.I,
        ),
    ),
    ("WordPress", re.compile(r"(^|/)(wp-(admin|login|content|includes|json|config)|xmlrpc\.php|wordpress)", re.I)),
    ("PHP / ASP / JSP files", re.compile(r"\.(php\d?|phtml|asp|aspx|jsp|jspx|cgi)(/|$)", re.I)),
    ("admin panels", re.compile(r"(^|/)(phpmyadmin|pma|adminer|phpinfo|mysqladmin|myadmin)", re.I)),
    (
        "debug endpoints",
        re.compile(r"(^|/)(actuator|server-status|server-info|_profiler|telescope|_ignition|elmah\.axd|trace\.axd)(/|$)", re.I),
    ),
    (
        "appliance / middleware exploits",
        re.compile(r"(^|/)(cgi-bin|solr|jenkins|manager/html|owa|ecp|autodiscover|boaform|hnap1|gponform|jmx-console)(/|$)", re.I),
    ),
    ("backups / dumps", re.compile(r"\.(sql|bak|swp)$|(^|/)(backup|dump|database|db)\.(zip|sql|tar|gz|tgz|rar|7z)$", re.I)),
    ("PHPUnit RCE", re.compile(r"(^|/)vendor/phpunit|eval-stdin\.php", re.I)),
)


# Every string matched here is chosen by the client. The regexes run on a bounded prefix so a
# crafted request line cannot make one tick spend minutes backtracking.
MAX_PATH = 1024
MAX_QUERY = 2048
MAX_UA = 512
MAX_DISPLAY = 160


def scanner_kind(path: str) -> str | None:
    """The family of scanner probe this path belongs to, or None for a normal path."""
    path = (path or "/").split("?", 1)[0][:MAX_PATH]
    for kind, rx in _SCANNER_RULES:
        if rx.search(path):
            return kind
    return None


# --------------------------------------------------------------------------------------
# 2. Attack tools announcing themselves in the User-Agent.
# --------------------------------------------------------------------------------------

# First letters are dropped where the casing varies between versions (Nuclei / nuclei).
TOOL_UA_LIKES: tuple[str, ...] = (
    "%sqlmap%", "%uclei%", "%ikto%", "%Fuzz Faster%", "%ffuf%", "%obuster%", "%irbuster%",
    "%irBuster%", "%eroxbuster%", "%fuzz/%", "%WPScan%", "%wpscan%", "%cunetix%", "%essus%",
    "%penVAS%", "%penvas%", "%ydra%", "%commix%", "%XSStrike%", "%dalfox%", "%rachni%",
    "%w3af%", "%etsparker%", "%ZAP%", "%zaproxy%", "%whatweb%", "%WhatWeb%",
    "%asscan%", "%zgrab%", "%map Scripting%", "%CensysInspect%", "%l9explore%", "%l9tcpid%",
)

_ATTACK_TOOLS = re.compile(
    r"\b(sqlmap|nuclei|nikto|ffuf|fuzz faster u fool|gobuster|dirbuster|feroxbuster|wfuzz|wpscan|"
    r"acunetix|nessus|openvas|hydra|commix|xsstrike|dalfox|arachni|w3af|skipfish|netsparker|"
    r"owasp[ _-]?zap|zaproxy|zap/\d|havij|jaeles|whatweb|joomscan)\b",
    re.I,
)
_MASS_SCANNERS = re.compile(
    r"(masscan|zgrab|nmap scripting engine|censysinspect|l9explore|l9tcpid)",
    re.I,
)
_TOOL_NAMES = {
    "fuzz faster u fool": "ffuf",
    "nmap scripting engine": "nmap",
    "censysinspect": "censys",
    "zaproxy": "OWASP ZAP",
}


def attack_tool(user_agent: str) -> str | None:
    """Name of the attack tool or mass scanner in this User-Agent, or None."""
    ua = (user_agent or "")[:MAX_UA]
    m = _ATTACK_TOOLS.search(ua) or _MASS_SCANNERS.search(ua)
    if not m:
        return None
    name = m.group(1).lower()
    if "zap" in name:
        return "OWASP ZAP"
    return _TOOL_NAMES.get(name, name)


# --------------------------------------------------------------------------------------
# 3. Injection payloads in the path or query string.
# --------------------------------------------------------------------------------------

INJECTION_QUERY_LIKES: tuple[str, ...] = (
    # SQL injection
    "%union%select%", "%UNION%SELECT%", "%sleep(%", "%SLEEP(%", "%sleep%28%", "%information_schema%",
    "%xp_cmdshell%", "%or%1=1%", "%OR%1=1%",
    # XSS
    "%<script%", "%3Cscript%", "%3cscript%", "%onerror=%", "%onerror%3D%", "%javascript:%",
    # path traversal / file read
    "%../..%", "%..%2F..%", "%..%2f..%", "%/etc/passwd%", "%etc%2Fpasswd%", "%etc%2fpasswd%",
    # template injection / Log4Shell
    # (no percent-encoded `{{`: it would match every JSON value sent in a query string)
    "%{{%}}%", "%${%}%", "%jndi:%", "%jndi%3A%", "%jndi%3a%",
    # prototype pollution / NoSQL operators
    "%__proto__%", "%constructor%prototype%", "%[$ne]%", "%[$gt]%", "%[$regex]%", "%5B%24ne%5D%",
    # command injection / cloud metadata
    "%whoami%", "%/bin/sh%", "%/bin/bash%", "%169.254.169.254%",
)
INJECTION_PATH_LIKES: tuple[str, ...] = (
    "%../..%", "%..%2F..%", "%..%2f..%", "%/etc/passwd%", "%<script%", "%3Cscript%",
    "%{{%}}%", "%jndi:%", "%__proto__%",
)

_INJECTION_RULES: tuple[tuple[str, re.Pattern], ...] = (
    (
        "SQL injection",
        re.compile(
            # SQL comments are turned into spaces before matching (see `injection_kind`).
            r"\bunion\s+(all\s+)?select\b|\b(sleep|benchmark|pg_sleep)\s*\(\s*\d|waitfor\s+delay|"
            r"\binformation_schema\b|\bxp_cmdshell\b|\bload_file\s*\(|\binto\s+(out|dump)file\b|"
            r"['\"]\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d|\b(or|and)\s+1\s*=\s*1\b|"
            r";\s*(drop|truncate)\s+table\b",
            re.I,
        ),
    ),
    (
        "XSS",
        re.compile(
            r"<\s*(script|svg|iframe|img|body|object|embed|details)\b|\bon(error|load|click|mouseover|focus|toggle)\s*=|"
            r"javascript\s*:",
            re.I,
        ),
    ),
    (
        "path traversal",
        re.compile(
            r"(\.\.[/\\]){2,}|/etc/(passwd|shadow)\b|/proc/self/environ|\bboot\.ini\b|c:[/\\]windows|"
            r"\b(php|file|expect|zip)://",
            re.I,
        ),
    ),
    ("Log4Shell / JNDI", re.compile(r"\$\{\s*(jndi|lower|upper|env|sys|java)\s*:", re.I)),
    ("template injection", re.compile(r"\{\{[^{}]{1,80}\}\}|\$\{[^{}]{1,80}\}|<%=|#\{[^{}]{1,80}\}")),
    (
        "prototype pollution",
        re.compile(r"__proto__|constructor\s*(\[|\.)\s*['\"]?prototype", re.I),
    ),
    (
        "NoSQL operator injection",
        re.compile(r"\[\$(ne|gt|gte|lt|lte|regex|where|in|nin|or|exists)\]|\"\$(ne|gt|where|regex)\"\s*:", re.I),
    ),
    (
        "command injection",
        re.compile(
            r"[;|&`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping|sleep)\b|\$\(\s*(id|whoami|cat|curl|wget|uname)\b|"
            r"/bin/(ba)?sh\b",
            re.I,
        ),
    ),
    ("cloud metadata SSRF", re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.I)),
)


def _decode(raw: str) -> str:
    """Percent-decode up to twice: scanners double-encode to slip past filters."""
    out = raw or ""
    for _ in range(2):
        decoded = unquote_plus(out)
        if decoded == out:
            break
        out = decoded
    return out


_SQL_COMMENT = re.compile(r"/\*[^*]*\*+(?:[^/*][^*]*\*+)*/")


def injection_kind(path: str, query: str = "") -> str | None:
    """The kind of injection payload carried by this request line, or None."""
    text = _decode((path or "")[:MAX_PATH])
    if query:
        text += "?" + _decode(query.lstrip("?")[:MAX_QUERY])
    # `union/**/select`: comments are the usual way to hide the keyword boundary.
    text = _SQL_COMMENT.sub(" ", text)
    for kind, rx in _INJECTION_RULES:
        if rx.search(text):
            return kind
    return None


# --------------------------------------------------------------------------------------
# Safe display of attacker-controlled request lines.
# --------------------------------------------------------------------------------------

_SECRET_PARAM = re.compile(
    r"(?i)\b([\w.\-\[\]]*(token|secret|password|passwd|pwd|authorization|api[_-]?key|apikey|session|"
    r"signature|sig|otp|pin|cvv|card)[\w.\-\[\]]*)=([^&\s]*)"
)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
_LONG_TOKEN = re.compile(r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{32,}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_CUT_WORD = re.compile(r"[A-Za-z0-9_\-.@]+$")


def redact(text: str) -> str:
    """Remove anything that could be a credential or personal data before it reaches Slack or a log.

    Only the first MAX_DISPLAY characters are kept: nothing longer is ever shown, and the patterns
    below get slow on long input. The word cut by that limit is dropped when the patterns could no
    longer recognise it: the start of a token shorter than a token, or an address without its domain.
    """
    if len(text) > MAX_DISPLAY:
        text = text[:MAX_DISPLAY]
        cut = _CUT_WORD.search(text)
        if cut and (len(cut.group()) < 32 or "@" in cut.group()):
            text = text[: cut.start()]
        text += "…"
    text = _SECRET_PARAM.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _EMAIL.sub("<email>", text)
    text = _IPV4.sub("<ip>", text)
    text = _CARD.sub("<number>", text)
    return _LONG_TOKEN.sub("<token>", text)


def safe_path(path: str, limit: int = 80) -> str:
    """A decoded, redacted, single-line path that is safe to show in an alert.

    Query strings are never shown: third-party callbacks put user ids in them. The query is only
    read in memory to name the kind of payload (`injection_kind`).
    """
    line = redact(" ".join(_decode((path or "/").split("?", 1)[0][:MAX_PATH]).split())) or "/"
    return line if len(line) <= limit else line[: limit - 1] + "…"
