"""
Division 2 — Web Injection
============================
50 agents covering every major injection class: SQL injection by database,
XSS by context, template injection, command injection, NoSQL injection,
and protocol-level injections (LDAP, XPath, CRLF, HPP).
"""

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


# ═══════════════════════════════════════════════════════════════════════
# SQL Injection — per database (12)
# ═══════════════════════════════════════════════════════════════════════

_sqli = [
    _s("sqli-error-mysql", "MySQL Error-Based SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS},
       description="Exploits MySQL error messages (extractvalue, updatexml, double-query) for data exfiltration",
       attack_types=("sqli",), target_technologies=("mysql", "mariadb"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("sqli/mysql_error.txt",),
       detection_patterns=(r"SQL syntax.*MySQL", r"mysql_fetch", r"You have an error in your SQL"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "mysql", "error-based")),

    _s("sqli-blind-mysql", "MySQL Blind SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.BLIND_INJECTION, Cap.BOOLEAN_INFERENCE, Cap.TIME_BASED},
       description="Boolean and time-based blind extraction against MySQL using SLEEP and conditional responses",
       attack_types=("sqli",), target_technologies=("mysql", "mariadb"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=500, timeout=600,
       payloads=("sqli/mysql_blind.txt",),
       detection_patterns=(r"sleep\(\d+\)", r"benchmark\("),
       cwe_ids=("CWE-89",),
       tags=("sqli", "mysql", "blind", "time-based")),

    _s("sqli-error-postgres", "PostgreSQL Error-Based SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS},
       description="Leverages PostgreSQL verbose error messages and CAST-based extraction for data leakage",
       attack_types=("sqli",), target_technologies=("postgresql", "postgres"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("sqli/postgres_error.txt",),
       detection_patterns=(r"pg_query", r"PSQLException", r"ERROR:\s+syntax error at or near"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "postgresql", "error-based")),

    _s("sqli-blind-postgres", "PostgreSQL Blind SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.BLIND_INJECTION, Cap.TIME_BASED},
       description="Blind SQLi against PostgreSQL using pg_sleep and conditional bit extraction",
       attack_types=("sqli",), target_technologies=("postgresql", "postgres"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=500, timeout=600,
       payloads=("sqli/postgres_blind.txt",),
       detection_patterns=(r"pg_sleep",),
       cwe_ids=("CWE-89",),
       tags=("sqli", "postgresql", "blind")),

    _s("sqli-error-mssql", "MSSQL Error-Based SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS},
       description="Exploits MSSQL error conversion and CONVERT/CAST tricks for data extraction",
       attack_types=("sqli",), target_technologies=("mssql", "sqlserver"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("sqli/mssql_error.txt",),
       detection_patterns=(r"Microsoft SQL Server", r"Unclosed quotation mark", r"mssql_query"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "mssql", "error-based")),

    _s("sqli-stacked-mssql", "MSSQL Stacked Query Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS, Cap.OOB_CALLBACK},
       description="Tests stacked queries on MSSQL for xp_cmdshell, sp_OACreate, and OOB data exfil via DNS",
       attack_types=("sqli",), target_technologies=("mssql", "sqlserver"),
       min_mode=Mode.REDTEAM, priority=Pri.HIGH, max_requests=100, timeout=300,
       payloads=("sqli/mssql_stacked.txt",),
       detection_patterns=(r"xp_cmdshell", r"sp_OACreate"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "mssql", "stacked", "rce")),

    _s("sqli-error-oracle", "Oracle Error-Based SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS},
       description="Exploits Oracle-specific functions (UTL_INADDR, CTXSYS, DBMS_XMLGEN) for error-based extraction",
       attack_types=("sqli",), target_technologies=("oracle",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("sqli/oracle_error.txt",),
       detection_patterns=(r"ORA-\d{5}", r"oracle\.jdbc", r"PLS-\d{5}"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "oracle", "error-based")),

    _s("sqli-blind-oracle", "Oracle Blind SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.BLIND_INJECTION, Cap.TIME_BASED},
       description="Time-based and boolean blind extraction on Oracle using DBMS_PIPE.RECEIVE_MESSAGE and conditional UTL_HTTP",
       attack_types=("sqli",), target_technologies=("oracle",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=500, timeout=600,
       payloads=("sqli/oracle_blind.txt",),
       detection_patterns=(r"DBMS_PIPE", r"UTL_HTTP"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "oracle", "blind")),

    _s("sqli-error-sqlite", "SQLite Error-Based SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS},
       description="SQLite-specific injection via GLOB, typeof, and sqlite_version extraction",
       attack_types=("sqli",), target_technologies=("sqlite",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=200, timeout=300,
       payloads=("sqli/sqlite_error.txt",),
       detection_patterns=(r"SQLite", r"sqlite3", r"SQLITE_ERROR", r"no such table"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "sqlite", "error-based")),

    _s("sqli-union", "UNION-Based SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS, Cap.BOOLEAN_INFERENCE},
       description="Column-count detection and UNION SELECT extraction across all SQL database flavors",
       attack_types=("sqli",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=600,
       payloads=("sqli/union_generic.txt",),
       detection_patterns=(r"UNION.*SELECT", r"ORDER BY \d+"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "union", "generic")),

    _s("sqli-oob", "Out-of-Band SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
       description="OOB data exfiltration via DNS lookups (xp_dirtree, UTL_HTTP, LOAD_FILE) and HTTP callbacks",
       attack_types=("sqli",),
       min_mode=Mode.REDTEAM, priority=Pri.HIGH, max_requests=100, timeout=300,
       payloads=("sqli/oob_all.txt",),
       detection_patterns=(r"xp_dirtree", r"UTL_HTTP", r"LOAD_FILE"),
       cwe_ids=("CWE-89",),
       tags=("sqli", "oob", "dns-exfil")),

    _s("sqli-secondorder", "Second-Order SQLi Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.BLIND_INJECTION, Cap.PATTERN_MATCHING},
       description="Detects stored SQL payloads that trigger on subsequent queries (registration, profile update, logs)",
       attack_types=("sqli",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=200, timeout=600,
       payloads=("sqli/secondorder.txt",),
       cwe_ids=("CWE-89",),
       tags=("sqli", "second-order", "stored")),
]

# ═══════════════════════════════════════════════════════════════════════
# XSS — by context (10)
# ═══════════════════════════════════════════════════════════════════════

_xss = [
    _s("xss-reflected-html", "Reflected XSS in HTML Context", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING, Cap.BROWSER_AUTOMATION},
       description="Tests tag injection in HTML body contexts with event handler and script tag payloads",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=300,
       payloads=("xss/reflected_html.txt",),
       detection_patterns=(r"<script>", r"onerror\s*=", r"onload\s*="),
       tags=("xss", "reflected", "html")),

    _s("xss-reflected-attr", "Reflected XSS in Attribute Context", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Breaks out of HTML attribute values using quote escaping and event handler injection",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=300,
       payloads=("xss/reflected_attr.txt",),
       detection_patterns=(r'"\s*on\w+\s*=', r"'\s*on\w+\s*=", r"autofocus\s+onfocus"),
       tags=("xss", "reflected", "attribute")),

    _s("xss-reflected-js", "Reflected XSS in JavaScript Context", 2,
       {Cap.PAYLOAD_INJECTION, Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING},
       description="Escapes JavaScript string/template literals and injects into inline script blocks",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=300,
       payloads=("xss/reflected_js.txt",),
       detection_patterns=(r"</script>", r"\\x3c/script", r"alert\("),
       tags=("xss", "reflected", "javascript")),

    _s("xss-stored", "Stored XSS Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.BROWSER_AUTOMATION, Cap.PATTERN_MATCHING},
       description="Tests persistent XSS via form submissions, comments, profiles, and file uploads that render unsanitized",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=600,
       payloads=("xss/stored.txt",),
       detection_patterns=(r"<script>", r"<img\s+src=x\s+onerror="),
       tags=("xss", "stored", "persistent")),

    _s("xss-dom", "DOM-Based XSS Specialist", 2,
       {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.PATTERN_MATCHING},
       description="Identifies DOM XSS via innerHTML/eval sinks fed by location.hash, postMessage, or URL fragment sources",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("xss/dom.txt",),
       detection_patterns=(r"innerHTML\s*=", r"eval\(", r"location\.hash", r"\.postMessage\("),
       tags=("xss", "dom", "client-side")),

    _s("xss-mutation", "Mutation XSS Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.BROWSER_AUTOMATION, Cap.PATTERN_MATCHING},
       description="Bypasses DOMPurify and browser sanitizers with mutation payloads that re-form after DOM parsing",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=200, timeout=300,
       payloads=("xss/mutation.txt",),
       detection_patterns=(r"mXSS", r"<svg>", r"<math>"),
       tags=("xss", "mutation", "mxss", "dompurify")),

    _s("xss-csp-bypass", "XSS CSP Bypass Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING},
       description="Circumvents Content-Security-Policy via JSONP endpoints, base-tag injection, and whitelisted CDN gadgets",
       attack_types=("xss", "csp-bypass"), cwe_ids=("CWE-79", "CWE-693"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("xss/csp_bypass.txt",),
       detection_patterns=(r"<base\s+href", r"callback=", r"jsonp"),
       depends_on=("recon-header-csp",),
       tags=("xss", "csp", "bypass")),

    _s("xss-polyglot", "XSS Polyglot Generator", 2,
       {Cap.PAYLOAD_INJECTION, Cap.ENCODING_MUTATION, Cap.PATTERN_MATCHING},
       description="Generates and tests polyglot payloads that work across HTML, attribute, JS, and URL contexts simultaneously",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       payloads=("xss/polyglot.txt",),
       tags=("xss", "polyglot", "universal")),

    _s("xss-svg-xml", "SVG/XML XSS Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Injects XSS through SVG file uploads, XML namespaces, and XHTML contexts",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       payloads=("xss/svg_xml.txt",),
       detection_patterns=(r"<svg\s+onload", r"xmlns:xlink", r"<foreignObject>"),
       tags=("xss", "svg", "xml", "upload")),

    _s("xss-waf-bypass", "XSS WAF Evasion Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.WAF_BYPASS, Cap.ENCODING_MUTATION},
       description="Evades WAF signature rules using case mutation, encoding chains, comment injection, and tag obfuscation",
       attack_types=("xss",), cwe_ids=("CWE-79",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=300,
       payloads=("xss/waf_bypass.txt",),
       depends_on=("recon-fp-waf",),
       tags=("xss", "waf", "evasion", "bypass")),
]

# ═══════════════════════════════════════════════════════════════════════
# Template Injection — by language (6)
# ═══════════════════════════════════════════════════════════════════════

_ssti = [
    _s("ssti-jinja2", "Jinja2/Twig SSTI Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests Jinja2 and Twig template injection via curly-brace probes and MRO chain exploitation",
       attack_types=("ssti",), target_technologies=("python", "flask", "django", "twig", "php"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("ssti/jinja2_twig.txt",),
       detection_patterns=(r"49", r"__class__", r"__mro__", r"__subclasses__"),
       cwe_ids=("CWE-1336",),
       tags=("ssti", "jinja2", "twig", "python")),

    _s("ssti-freemarker", "FreeMarker SSTI Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Exploits FreeMarker template injection with built-in Execute, ObjectConstructor, and JythonRuntime gadgets",
       attack_types=("ssti",), target_technologies=("java", "freemarker"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=150, timeout=300,
       payloads=("ssti/freemarker.txt",),
       detection_patterns=(r"freemarker\.template", r"FreeMarker"),
       cwe_ids=("CWE-1336",),
       tags=("ssti", "freemarker", "java")),

    _s("ssti-velocity", "Velocity SSTI Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests Apache Velocity template injection via set directives and Runtime getRuntime chains",
       attack_types=("ssti",), target_technologies=("java", "velocity"),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("ssti/velocity.txt",),
       detection_patterns=(r"org\.apache\.velocity", r"#set\s*\("),
       cwe_ids=("CWE-1336",),
       tags=("ssti", "velocity", "java")),

    _s("ssti-erb", "ERB/Slim SSTI Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Exploits Ruby ERB template injection via embedded Ruby tag injection and Kernel system calls",
       attack_types=("ssti",), target_technologies=("ruby", "rails"),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("ssti/erb.txt",),
       detection_patterns=(r"<%=.*%>", r"ERB", r"Kernel"),
       cwe_ids=("CWE-1336",),
       tags=("ssti", "erb", "ruby")),

    _s("ssti-pebble", "Pebble/Thymeleaf SSTI Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests Pebble and Thymeleaf template engines for expression injection and Spring EL exploitation",
       attack_types=("ssti",), target_technologies=("java", "spring", "pebble", "thymeleaf"),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("ssti/pebble_thymeleaf.txt",),
       detection_patterns=(r"org\.springframework", r"T\(java\.lang"),
       cwe_ids=("CWE-1336",),
       tags=("ssti", "pebble", "thymeleaf", "spring")),

    _s("ssti-handlebars", "Handlebars/Mustache SSTI Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests Handlebars and Mustache for prototype pollution and helper-based RCE via with-block lookups",
       attack_types=("ssti",), target_technologies=("nodejs", "handlebars", "mustache"),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("ssti/handlebars.txt",),
       detection_patterns=(r"\{\{#with", r"constructor\.constructor"),
       cwe_ids=("CWE-1336",),
       tags=("ssti", "handlebars", "mustache", "nodejs")),
]

# ═══════════════════════════════════════════════════════════════════════
# Command Injection (6)
# ═══════════════════════════════════════════════════════════════════════

_cmdi = [
    _s("cmdi-os-unix", "Unix Command Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING, Cap.OOB_CALLBACK},
       description="Tests for OS command injection on Linux/macOS via pipe, semicolon, backtick, and dollar-paren substitution",
       attack_types=("cmdi",), target_technologies=("linux", "unix", "macos"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("cmdi/unix.txt",),
       detection_patterns=(r"root:x:0:0", r"uid=\d+", r"bin/(bash|sh)"),
       cwe_ids=("CWE-78",),
       tags=("cmdi", "unix", "linux")),

    _s("cmdi-os-windows", "Windows Command Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING, Cap.OOB_CALLBACK},
       description="Tests for OS command injection on Windows via ampersand, pipe, and PowerShell substitution",
       attack_types=("cmdi",), target_technologies=("windows", "iis", "aspnet"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("cmdi/windows.txt",),
       detection_patterns=(r"Windows NT", r"Volume Serial Number", r"Directory of"),
       cwe_ids=("CWE-78",),
       tags=("cmdi", "windows", "powershell")),

    _s("cmdi-blind-time", "Blind Command Injection (Time-Based)", 2,
       {Cap.PAYLOAD_INJECTION, Cap.BLIND_INJECTION, Cap.TIME_BASED},
       description="Detects command injection via sleep/ping timing delays when output is not reflected",
       attack_types=("cmdi",), cwe_ids=("CWE-78",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=600,
       payloads=("cmdi/blind_time.txt",),
       tags=("cmdi", "blind", "time-based")),

    _s("cmdi-blind-oob", "Blind Command Injection (OOB)", 2,
       {Cap.PAYLOAD_INJECTION, Cap.BLIND_INJECTION, Cap.OOB_CALLBACK},
       description="Exfiltrates command output via DNS queries (nslookup/dig) and HTTP callbacks (curl/wget)",
       attack_types=("cmdi",), cwe_ids=("CWE-78",),
       min_mode=Mode.REDTEAM, priority=Pri.HIGH, max_requests=100, timeout=300,
       payloads=("cmdi/blind_oob.txt",),
       tags=("cmdi", "blind", "oob", "dns")),

    _s("cmdi-argument-injection", "Argument Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Injects additional arguments into CLI commands (e.g., --output, -o, wildcards) without full command escape",
       attack_types=("cmdi",), cwe_ids=("CWE-88",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("cmdi/argument_injection.txt",),
       tags=("cmdi", "argument", "parameter-injection")),

    _s("cmdi-code-injection", "Server-Side Code Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests eval/assert injection in PHP, Python, Ruby, and Node.js server-side code evaluation sinks",
       attack_types=("code-injection",), cwe_ids=("CWE-94",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("cmdi/code_injection.txt",),
       detection_patterns=(r"phpinfo\b", r"__import__", r"Kernel\.exit"),
       tags=("code-injection", "eval", "rce")),
]

# ═══════════════════════════════════════════════════════════════════════
# NoSQL Injection (4)
# ═══════════════════════════════════════════════════════════════════════

_nosqli = [
    _s("nosqli-mongo", "MongoDB NoSQL Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING, Cap.BOOLEAN_INFERENCE},
       description="Tests MongoDB operator injection ($gt, $ne, $regex, $where) in JSON and query string parameters",
       attack_types=("nosqli",), target_technologies=("mongodb", "mongoose"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("nosqli/mongodb.txt",),
       detection_patterns=(r"\$gt", r"\$ne", r"\$regex", r"MongoError"),
       cwe_ids=("CWE-943",),
       tags=("nosqli", "mongodb", "operator-injection")),

    _s("nosqli-mongo-js", "MongoDB JavaScript Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.JS_ANALYSIS},
       description="Exploits $where and mapReduce with server-side JavaScript evaluation in MongoDB",
       attack_types=("nosqli",), target_technologies=("mongodb",),
       min_mode=Mode.REDTEAM, priority=Pri.HIGH, max_requests=100, timeout=300,
       payloads=("nosqli/mongodb_js.txt",),
       detection_patterns=(r"\$where", r"mapReduce"),
       cwe_ids=("CWE-943",),
       tags=("nosqli", "mongodb", "javascript", "ssjs")),

    _s("nosqli-redis", "Redis Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests for CRLF-based Redis command injection via unsanitized inputs in RESP protocol",
       attack_types=("nosqli",), target_technologies=("redis",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       payloads=("nosqli/redis.txt",),
       detection_patterns=(r"WRONGTYPE", r"ERR unknown command", r"\+OK"),
       cwe_ids=("CWE-943",),
       tags=("nosqli", "redis", "crlf")),

    _s("nosqli-couch", "CouchDB Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING, Cap.API_INTERACTION},
       description="Tests CouchDB Mango query injection and view abuse for unauthorized data access",
       attack_types=("nosqli",), target_technologies=("couchdb",),
       min_mode=Mode.AUDIT, priority=Pri.LOW, max_requests=100, timeout=300,
       payloads=("nosqli/couchdb.txt",),
       detection_patterns=(r"\"error\":\"not_found\"", r"\"reason\":"),
       cwe_ids=("CWE-943",),
       tags=("nosqli", "couchdb", "mango")),
]

# ═══════════════════════════════════════════════════════════════════════
# LDAP, XPath, CRLF, HPP (6)
# ═══════════════════════════════════════════════════════════════════════

_protocol_inject = [
    _s("inject-ldap", "LDAP Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests LDAP filter injection via wildcard, OR/AND abuse, and attribute extraction in login/search forms",
       attack_types=("ldap-injection",), cwe_ids=("CWE-90",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("inject/ldap.txt",),
       detection_patterns=(r"LDAP error", r"Invalid DN syntax", r"javax\.naming"),
       tags=("ldap", "injection", "directory")),

    _s("inject-xpath", "XPath Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING, Cap.BOOLEAN_INFERENCE},
       description="Exploits XPath query injection for authentication bypass and XML data extraction",
       attack_types=("xpath-injection",), cwe_ids=("CWE-643",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("inject/xpath.txt",),
       detection_patterns=(r"XPathException", r"XPATH syntax error", r"xmlXPathEval"),
       tags=("xpath", "injection", "xml")),

    _s("inject-crlf", "CRLF Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.HEADER_MANIPULATION, Cap.PATTERN_MATCHING},
       description="Injects CR/LF characters into HTTP headers for header splitting, response splitting, and log poisoning",
       attack_types=("crlf-injection",), cwe_ids=("CWE-113",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("inject/crlf.txt",),
       detection_patterns=(r"Set-Cookie:.*injected", r"\r\nX-Injected:"),
       tags=("crlf", "header-splitting", "injection")),

    _s("inject-hpp", "HTTP Parameter Pollution Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests parameter precedence and duplicate parameter handling across web servers and frameworks",
       attack_types=("hpp",), cwe_ids=("CWE-235",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=150, timeout=300,
       payloads=("inject/hpp.txt",),
       tags=("hpp", "parameter-pollution")),

    _s("inject-ssi", "Server-Side Include Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests for SSI directive injection in legacy Apache/IIS environments that process server-side includes",
       attack_types=("ssi-injection",), cwe_ids=("CWE-97",),
       min_mode=Mode.AUDIT, priority=Pri.LOW, max_requests=100, timeout=300,
       payloads=("inject/ssi.txt",),
       detection_patterns=(r"<!--#", r"fsize", r"flastmod"),
       tags=("ssi", "injection", "legacy")),

    _s("inject-expression", "Expression Language Injection Specialist", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests Java EL, Spring SpEL, and OGNL expression injection in server-side evaluation contexts",
       attack_types=("el-injection",), target_technologies=("java", "spring", "struts"),
       cwe_ids=("CWE-917",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("inject/expression.txt",),
       detection_patterns=(r"\$\{.*\}", r"#\{.*\}", r"%\{.*\}"),
       tags=("el", "spel", "ognl", "injection")),
]

# ═══════════════════════════════════════════════════════════════════════
# Meta-Agents (6)
# ═══════════════════════════════════════════════════════════════════════

_meta = [
    _s("inject-commander", "Injection Division Commander", 2,
       {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
       description="Coordinates all Division 2 injection agents, deduplicates findings, and manages WAF evasion strategy",
       attack_types=(),
       min_mode=Mode.AUDIT, priority=Pri.CRITICAL, max_requests=0, timeout=3600,
       tags=("commander", "coordination", "division-2")),

    _s("inject-waf-adaptor", "WAF Evasion Coordinator", 2,
       {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.KNOWLEDGE_SHARING},
       description="Detects WAF presence and distributes encoding/mutation strategies to all injection agents",
       attack_types=(), cwe_ids=("CWE-693",),
       min_mode=Mode.AUDIT, priority=Pri.CRITICAL, max_requests=50, timeout=600,
       depends_on=("recon-fp-waf",),
       tags=("waf", "evasion", "coordinator")),

    _s("inject-fuzzer", "Injection Point Fuzzer", 2,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING, Cap.RESPONSE_DIFF},
       description="Baseline-and-diff fuzzer that identifies injectable parameters before handing off to specialists",
       attack_types=("fuzzing",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=500, timeout=600,
       payloads=("inject/fuzz_special_chars.txt",),
       tags=("fuzzer", "injection-point", "triage")),

    _s("inject-encoder", "Payload Encoder/Mutator", 2,
       {Cap.ENCODING_MUTATION, Cap.WAF_BYPASS},
       description="Generates URL-encoded, double-encoded, Unicode, hex, and base64 payload variants for WAF bypass",
       attack_types=(),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=0, timeout=600,
       tags=("encoder", "mutation", "evasion")),

    _s("inject-verifier", "Injection Finding Verifier", 2,
       {Cap.CONSENSUS_VOTING, Cap.PATTERN_MATCHING, Cap.PROOF_GENERATION},
       description="Re-tests and verifies injection findings from other agents to reduce false positives through independent confirmation",
       attack_types=(),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=600,
       tags=("verifier", "consensus", "false-positive")),

    _s("inject-chainer", "Injection Chain Builder", 2,
       {Cap.CHAIN_BUILDING, Cap.PAYLOAD_INJECTION, Cap.PROOF_GENERATION},
       description="Combines multiple low-severity injection findings into high-impact exploit chains (e.g., SQLi to RCE)",
       attack_types=("chaining",), cwe_ids=("CWE-89", "CWE-78"),
       min_mode=Mode.REDTEAM, priority=Pri.HIGH, max_requests=100, timeout=600,
       tags=("chaining", "escalation", "exploit")),
]


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def agents() -> list[AgentSpec]:
    """Return all 50 Division 2 (Web Injection) agents."""
    all_agents = _sqli + _xss + _ssti + _cmdi + _nosqli + _protocol_inject + _meta
    assert len(all_agents) == 50, f"Division 2 must have exactly 50 agents, got {len(all_agents)}"
    return all_agents
