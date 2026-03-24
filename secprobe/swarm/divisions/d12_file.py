"""
Division 12 — File & Data Handling Vulnerability Agents (25 agents).

Targets file upload bypass, upload-to-RCE, local file inclusion, XML external
entity attacks, insecure deserialization per language, path traversal, and
injection via generated documents (CSV, PDF).
"""

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


def agents() -> list[AgentSpec]:
    """Return all 25 Division 12 agents."""
    return [
        # ── Upload Bypass (5) ────────────────────────────────────────
        _s(
            "file-upload-ext-bypass", "File Extension Bypass Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Bypasses file extension whitelists/blacklists using double "
                        "extensions (.php.jpg), null bytes (file.php%00.jpg), case "
                        "variation (.pHp), and alternative extensions (.phtml, .php5).",
            attack_types=("file-upload", "extension-bypass"),
            cwe_ids=("CWE-434",),
            detection_patterns=(
                r"upload.*success", r"file.*saved", r"stored.*at",
            ),
            payloads=("upload_ext_bypass.txt",),
            priority=Pri.HIGH,
            max_requests=120,
            tags=("upload", "extension", "bypass"),
        ),
        _s(
            "file-upload-mime-bypass", "MIME Type Validation Bypass Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Bypasses Content-Type validation by sending malicious files "
                        "with spoofed MIME types, polyglot file headers that satisfy "
                        "magic-byte checks, and multipart boundary manipulation.",
            attack_types=("file-upload", "mime-bypass"),
            cwe_ids=("CWE-434",),
            detection_patterns=(
                r"upload.*success", r"file.*accepted", r"content.*type.*valid",
            ),
            payloads=("upload_mime_bypass.txt",),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("upload", "mime", "content-type"),
        ),
        _s(
            "file-upload-size-bypass", "File Size Limit Bypass Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Bypasses file size restrictions via chunked transfer encoding, "
                        "compressed payloads that expand post-validation (zip bombs), "
                        "and Content-Length header manipulation.",
            attack_types=("file-upload", "size-bypass"),
            cwe_ids=("CWE-434", "CWE-400"),
            detection_patterns=(
                r"upload.*success", r"file.*too.*large",
            ),
            priority=Pri.NORMAL,
            max_requests=60,
            tags=("upload", "size", "zip-bomb"),
        ),
        _s(
            "file-upload-path-override", "Upload Path Override Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Manipulates upload destination by injecting path traversal "
                        "sequences in filename fields, overriding storage directory via "
                        "hidden form fields, and exploiting Content-Disposition parsing.",
            attack_types=("file-upload", "path-override"),
            cwe_ids=("CWE-434", "CWE-22"),
            detection_patterns=(
                r"stored.*at", r"path.*\.\.", r"file.*saved",
            ),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("upload", "path", "traversal"),
        ),
        _s(
            "file-upload-race", "Upload Race Condition Specialist", 12,
            {Cap.HTTP_PROBE, Cap.TIME_BASED, Cap.PAYLOAD_INJECTION},
            description="Exploits race conditions between file upload and antivirus/validation "
                        "scanning by uploading malicious files and accessing them before "
                        "the async security check completes.",
            attack_types=("file-upload", "race-condition"),
            cwe_ids=("CWE-434", "CWE-367"),
            detection_patterns=(
                r"upload.*success", r"<\?php", r"<%",
            ),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("upload", "race", "async-scan"),
        ),

        # ── Upload RCE (2) ───────────────────────────────────────────
        _s(
            "file-upload-webshell", "Upload-to-Webshell Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PROOF_GENERATION},
            description="Chains file upload vulnerabilities into remote code execution "
                        "by uploading web shells in PHP, ASP, JSP, and Python formats, "
                        "then confirming execution by requesting the uploaded file.",
            attack_types=("file-upload", "rce", "webshell"),
            cwe_ids=("CWE-434", "CWE-94"),
            detection_patterns=(
                r"uid=\d+", r"www-data", r"COMPUTERNAME",
                r"os\.name", r"Runtime\.getRuntime",
            ),
            min_mode=Mode.REDTEAM,
            payloads=("webshells_minimal.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("upload", "webshell", "rce"),
        ),
        _s(
            "file-upload-polyglot", "Polyglot File RCE Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PROOF_GENERATION},
            description="Creates polyglot files that are simultaneously valid images "
                        "and executable scripts (GIFAR, PNG+PHP, JPEG+JSP) to bypass "
                        "content-type validation while achieving code execution.",
            attack_types=("file-upload", "polyglot", "rce"),
            cwe_ids=("CWE-434", "CWE-94"),
            detection_patterns=(
                r"uid=\d+", r"GIF89a.*<\?", r"PNG.*<%",
            ),
            min_mode=Mode.REDTEAM,
            payloads=("polyglot_files.txt",),
            priority=Pri.HIGH,
            max_requests=60,
            tags=("upload", "polyglot", "rce"),
        ),

        # ── LFI Variants (5) ────────────────────────────────────────
        _s(
            "file-lfi-basic", "Basic LFI Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS},
            description="Tests for local file inclusion using standard directory traversal "
                        "sequences (../), absolute paths (/etc/passwd), and common "
                        "LFI targets across Linux and Windows systems.",
            attack_types=("lfi",),
            cwe_ids=("CWE-98",),
            detection_patterns=(
                r"root:.*:0:0", r"\[boot\s*loader\]", r"\[extensions\]",
                r"mysql:.*:/bin", r"www-data",
            ),
            payloads=("lfi_basic.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("lfi", "traversal", "file-read"),
        ),
        _s(
            "file-lfi-filter-bypass", "LFI Filter Bypass Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.ENCODING_MUTATION},
            description="Bypasses LFI input filters using URL encoding (..%2f), double "
                        "encoding (..%252f), null bytes, path normalization tricks "
                        "(..;/), and Unicode normalization (..%c0%af).",
            attack_types=("lfi", "filter-bypass"),
            cwe_ids=("CWE-98", "CWE-22"),
            detection_patterns=(
                r"root:.*:0:0", r"\[boot\s*loader\]",
            ),
            payloads=("lfi_filter_bypass.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("lfi", "filter", "encoding"),
        ),
        _s(
            "file-lfi-php-wrappers", "PHP Wrapper LFI Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Exploits PHP stream wrappers for LFI escalation: "
                        "php://filter for base64 source disclosure, php://input for "
                        "code injection, data:// for inline payloads, and expect:// "
                        "for command execution.",
            attack_types=("lfi", "php-wrappers"),
            target_technologies=("php", "laravel", "wordpress"),
            cwe_ids=("CWE-98", "CWE-94"),
            detection_patterns=(
                r"PD9waHA", r"base64", r"<\?php",
            ),
            payloads=("lfi_php_wrappers.txt",),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("lfi", "php", "wrappers", "stream"),
        ),
        _s(
            "file-lfi-log-poison", "Log Poisoning via LFI Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Achieves code execution through LFI by poisoning server logs "
                        "(access, error, mail, SSH) with executable payloads, then "
                        "including the log file via the LFI vulnerability.",
            attack_types=("lfi", "log-poisoning"),
            cwe_ids=("CWE-98", "CWE-94"),
            detection_patterns=(
                r"uid=\d+", r"www-data", r"apache.*log",
            ),
            min_mode=Mode.AUDIT,
            payloads=("lfi_log_poison.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("lfi", "log", "poisoning", "rce"),
        ),
        _s(
            "file-lfi-proc-environ", "LFI via /proc Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.DATA_EXTRACTION},
            description="Exploits LFI to read sensitive data from /proc filesystem "
                        "including /proc/self/environ for environment variables, "
                        "/proc/self/cmdline, /proc/net/tcp for network info, and "
                        "/proc/self/fd/ for open file descriptors.",
            attack_types=("lfi", "proc-read"),
            cwe_ids=("CWE-98", "CWE-200"),
            detection_patterns=(
                r"PATH=", r"HOME=", r"SERVER_SOFTWARE",
                r"DOCUMENT_ROOT", r"HTTP_HOST",
            ),
            payloads=("lfi_proc.txt",),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("lfi", "proc", "environ", "linux"),
        ),

        # ── XXE Variants (3) ────────────────────────────────────────
        _s(
            "file-xxe-classic", "Classic XXE Injection Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Tests for XML External Entity injection via inline DTD "
                        "declarations, external entity file reads (file:///etc/passwd), "
                        "and parameter entity expansion in XML-accepting endpoints "
                        "(SOAP, SAML, SVG upload, DOCX/XLSX).",
            attack_types=("xxe",),
            cwe_ids=("CWE-611",),
            detection_patterns=(
                r"root:.*:0:0", r"ENTITY", r"SYSTEM",
            ),
            payloads=("xxe_classic.txt",),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("xxe", "xml", "entity", "dtd"),
        ),
        _s(
            "file-xxe-oob", "Out-of-Band XXE Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Exploits blind XXE via out-of-band data exfiltration using "
                        "external DTDs hosted on attacker infrastructure, FTP-based "
                        "extraction, and DNS-based data channels when HTTP is blocked.",
            attack_types=("xxe", "oob"),
            cwe_ids=("CWE-611",),
            detection_patterns=(
                r"callback.*received", r"dns.*query",
            ),
            payloads=("xxe_oob.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("xxe", "oob", "blind", "exfiltration"),
        ),
        _s(
            "file-xxe-ssrf", "XXE-to-SSRF Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Chains XXE into SSRF by using external entity URLs pointing "
                        "to internal services (http://169.254.169.254, http://localhost), "
                        "cloud metadata endpoints, and internal network scanning via "
                        "response time analysis.",
            attack_types=("xxe", "ssrf"),
            cwe_ids=("CWE-611", "CWE-918"),
            detection_patterns=(
                r"ami-id", r"instance-id", r"local-ipv4",
                r"metadata", r"169\.254\.169\.254",
            ),
            payloads=("xxe_ssrf.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("xxe", "ssrf", "cloud", "metadata"),
        ),

        # ── Deserialization per Language (5) ─────────────────────────
        _s(
            "file-deser-java", "Java Deserialization Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Detects Java insecure deserialization via gadget chains "
                        "(Commons Collections, Spring, Hibernate), targeting "
                        "ObjectInputStream, XMLDecoder, and Kryo endpoints identified "
                        "by aced0005 magic bytes or base64-encoded serialized objects.",
            attack_types=("deserialization", "java"),
            target_technologies=("java", "spring", "tomcat", "jboss", "weblogic"),
            cwe_ids=("CWE-502",),
            detection_patterns=(
                r"java\.lang\.Runtime", r"aced0005", r"rO0AB",
                r"ClassNotFoundException", r"InvalidClassException",
            ),
            payloads=("deser_java.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("deserialization", "java", "gadget"),
        ),
        _s(
            "file-deser-python", "Python Deserialization Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Tests for insecure deserialization in Python applications "
                        "by injecting crafted serialized bytecode and YAML object "
                        "instantiation payloads into endpoints accepting serialized "
                        "Python data structures. Targets unsafe unmarshalling in "
                        "Django, Flask, and FastAPI applications.",
            attack_types=("deserialization", "python"),
            target_technologies=("python", "django", "flask", "fastapi"),
            cwe_ids=("CWE-502",),
            detection_patterns=(
                r"Unpickler", r"__reduce__",
                r"yaml\.load", r"!!python",
            ),
            payloads=("deser_python.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("deserialization", "python", "marshalling", "yaml"),
        ),
        _s(
            "file-deser-php", "PHP Deserialization Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Exploits PHP unserialize() vulnerabilities using POP chains, "
                        "targeting __wakeup, __destruct, and __toString magic methods "
                        "in frameworks like Laravel, Symfony, and WordPress.",
            attack_types=("deserialization", "php"),
            target_technologies=("php", "laravel", "wordpress", "symfony"),
            cwe_ids=("CWE-502",),
            detection_patterns=(
                r"O:\d+:\"", r"unserialize\(\)", r"__wakeup",
                r"__destruct", r"POP chain",
            ),
            payloads=("deser_php.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("deserialization", "php", "pop-chain"),
        ),
        _s(
            "file-deser-dotnet", ".NET Deserialization Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Tests .NET deserialization via BinaryFormatter, "
                        "ObjectStateFormatter, LosFormatter, and JSON.NET TypeNameHandling "
                        "using ysoserial.net gadget chains targeting ViewState, SOAP, "
                        "and remoting endpoints.",
            attack_types=("deserialization", "dotnet"),
            target_technologies=("aspnet", "iis", "dotnet"),
            cwe_ids=("CWE-502",),
            detection_patterns=(
                r"System\.Runtime", r"BinaryFormatter",
                r"ObjectStateFormatter", r"__VIEWSTATE",
            ),
            payloads=("deser_dotnet.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("deserialization", "dotnet", "viewstate"),
        ),
        _s(
            "file-deser-ruby", "Ruby Deserialization Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Exploits Ruby Marshal.load and YAML.load deserialization "
                        "using ERB template injection gadgets and universal RCE chains "
                        "targeting Rails, Sinatra, and Ruby applications with exposed "
                        "serialized cookie data.",
            attack_types=("deserialization", "ruby"),
            target_technologies=("ruby", "rails", "sinatra"),
            cwe_ids=("CWE-502",),
            detection_patterns=(
                r"Marshal\.load", r"YAML\.load", r"ERB",
                r"ruby.*object", r"\\x04\\x08",
            ),
            payloads=("deser_ruby.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("deserialization", "ruby", "marshal"),
        ),

        # ── Path Traversal (2) ──────────────────────────────────────
        _s(
            "file-path-traversal-read", "Path Traversal Read Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.DATA_EXTRACTION},
            description="Reads arbitrary files via path traversal in download endpoints, "
                        "file preview APIs, template selection parameters, and static "
                        "resource handlers using ../ sequences and encoding variants.",
            attack_types=("path-traversal", "arbitrary-read"),
            cwe_ids=("CWE-22",),
            detection_patterns=(
                r"root:.*:0:0", r"\[boot\s*loader\]", r"BEGIN.*PRIVATE",
                r"DB_PASSWORD", r"SECRET_KEY",
            ),
            payloads=("path_traversal_read.txt",),
            priority=Pri.HIGH,
            max_requests=120,
            tags=("path-traversal", "file-read", "download"),
        ),
        _s(
            "file-path-traversal-write", "Path Traversal Write Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PROOF_GENERATION},
            description="Tests for arbitrary file write via path traversal in upload, "
                        "configuration save, log export, and template editing endpoints "
                        "to overwrite critical files like .htaccess, web.config, or crontab.",
            attack_types=("path-traversal", "arbitrary-write"),
            cwe_ids=("CWE-22", "CWE-73"),
            detection_patterns=(
                r"file.*written", r"saved.*success", r"config.*updated",
            ),
            min_mode=Mode.REDTEAM,
            payloads=("path_traversal_write.txt",),
            priority=Pri.HIGH,
            max_requests=60,
            tags=("path-traversal", "file-write", "overwrite"),
        ),

        # ── CSV / PDF Injection (2) ─────────────────────────────────
        _s(
            "file-csv-injection", "CSV Formula Injection Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Injects spreadsheet formulas (=CMD, +HYPERLINK, -IMPORTXML, "
                        "@SUM) into user-controlled fields that appear in CSV/Excel "
                        "exports, enabling DDE command execution and data exfiltration "
                        "when victims open exported files.",
            attack_types=("csv-injection",),
            cwe_ids=("CWE-1236",),
            detection_patterns=(
                r"export.*ready", r"download.*csv", r"=CMD",
            ),
            payloads=("csv_injection.txt",),
            priority=Pri.NORMAL,
            max_requests=60,
            tags=("csv", "formula", "injection", "dde"),
        ),
        _s(
            "file-pdf-injection", "PDF/Report Injection Specialist", 12,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Injects malicious content into server-side PDF generation "
                        "via HTML-to-PDF converters (wkhtmltopdf, Puppeteer, Prince) "
                        "using embedded scripts, SSRF via link/image tags, and "
                        "local file read through file:// protocol in generated PDFs.",
            attack_types=("pdf-injection", "ssrf"),
            cwe_ids=("CWE-74", "CWE-918"),
            detection_patterns=(
                r"pdf.*generated", r"report.*ready", r"%PDF",
            ),
            payloads=("pdf_injection.txt",),
            priority=Pri.NORMAL,
            max_requests=60,
            tags=("pdf", "injection", "ssrf", "html2pdf"),
        ),

        # ── Commander (1) ────────────────────────────────────────────
        _s(
            "file-commander", "Division 12 File & Data Handling Commander", 12,
            {Cap.COORDINATION, Cap.CONSENSUS_VOTING, Cap.KNOWLEDGE_SHARING},
            description="Coordinates Division 12 agents, prioritizes file-handling tests "
                        "based on detected upload endpoints and XML parsers, manages "
                        "polyglot file generation, and chains upload findings into RCE "
                        "escalation paths.",
            attack_types=("file-handling",),
            cwe_ids=(),
            priority=Pri.CRITICAL,
            max_requests=50,
            tags=("commander", "coordinator", "file"),
        ),
    ]
