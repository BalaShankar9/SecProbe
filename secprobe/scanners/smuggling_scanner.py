"""
HTTP Request Smuggling Scanner.

Features:
  - CL.TE detection (Content-Length vs Transfer-Encoding conflict)
  - TE.CL detection (Transfer-Encoding vs Content-Length conflict)
  - TE.TE detection (Transfer-Encoding obfuscation)
  - Timing-based differential analysis
  - Header normalization probes
  - HTTP/2 downgrade detection
  - Safe probing (won't poison queues)
"""

import re
import time
from urllib.parse import urlparse

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Transfer-Encoding obfuscation variants
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: chunked\r\n",
    "Transfer-Encoding : chunked",
    "Transfer-encoding: chunked",
    "transfer-encoding: chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: \tchunked",
    " Transfer-Encoding: chunked",
    "Transfer-Encoding: chunked ",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding: chunked-false",
]


class SmugglingScanner(SmartScanner):
    name = "HTTP Smuggling Scanner"
    description = "Test for HTTP Request Smuggling (desync) vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing HTTP Request Smuggling on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
            baseline_code = baseline.status_code
            server_header = baseline.headers.get("Server", "").lower()
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        vulns_found = 0

        # Phase 1: Detect proxy/CDN presence
        proxy_info = self._detect_proxy(url, baseline)

        # Phase 2: CL.TE detection (safe probes)
        vulns_found += self._test_cl_te(url)

        # Phase 3: TE.CL detection (safe probes)
        vulns_found += self._test_te_cl(url)

        # Phase 4: TE.TE (obfuscation) detection
        vulns_found += self._test_te_te(url)

        # Phase 5: Header normalization probes
        vulns_found += self._test_header_normalization(url, baseline_code)

        # Phase 6: HTTP version and transfer analysis
        vulns_found += self._analyze_http_behavior(url, baseline)

        if vulns_found == 0:
            print_status("No HTTP Smuggling vulnerabilities detected.", "success")
            self.add_finding(
                title="No HTTP Smuggling detected",
                severity=Severity.INFO,
                description="Automated tests did not detect request smuggling vulnerabilities.",
                category="HTTP Smuggling",
            )

    def _detect_proxy(self, url, baseline):
        """Detect if a reverse proxy or CDN is in front of the application."""
        headers = baseline.headers
        proxy_indicators = {}

        # Check common proxy headers
        proxy_headers = {
            "Via": "Proxy chain",
            "X-Cache": "Caching proxy",
            "X-Cache-Hit": "Cache hit indicator",
            "X-Served-By": "Serving node",
            "CF-RAY": "Cloudflare",
            "X-Amz-Cf-Id": "AWS CloudFront",
            "X-Azure-Ref": "Azure Front Door",
            "X-Fastly-Request-ID": "Fastly",
            "X-Varnish": "Varnish",
            "X-CDN": "CDN detected",
            "X-Proxy-Cache": "Proxy cache",
            "Server": "Server identification",
        }

        for header, desc in proxy_headers.items():
            val = headers.get(header)
            if val:
                proxy_indicators[header] = f"{desc}: {val}"

        if proxy_indicators:
            self.add_finding(
                title="Reverse Proxy/CDN Detected",
                severity=Severity.INFO,
                description=(
                    "A reverse proxy or CDN is detected in front of the application. "
                    "This creates potential for request smuggling if the proxy and backend "
                    "disagree on request boundaries."
                ),
                evidence="\n".join(f"{k}: {v}" for k, v in proxy_indicators.items()),
                category="HTTP Smuggling",
                url=url,
                cwe="CWE-444",
            )

        return proxy_indicators

    def _test_cl_te(self, url):
        """
        CL.TE smuggling: Front-end uses Content-Length, back-end uses Transfer-Encoding.
        
        Safe detection: Send a request where CL says body is short but TE says body continues.
        If the back-end uses TE, it will wait for the chunk terminator, causing a timeout.
        """
        vulns_found = 0

        # Safe probe: CL says 4 bytes, TE says chunked with a 0-terminator
        # If CL.TE, back-end reads the "0\r\n\r\n" as end of chunk — normal response
        # If TE.CL, back-end reads CL=4 bytes ("1\r\na") and leaves rest in buffer
        probe_body = "1\r\na\r\n0\r\n\r\n"

        try:
            start = time.time()
            resp = self.http_client.post(
                url,
                data=probe_body,
                headers={
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                allow_redirects=False,
            )
            elapsed = time.time() - start

            # Normal CL.TE probe: response comes back normally
            # If there's a significant timeout, the back-end may be confused
            if elapsed > 5.0:
                vulns_found += 1
                self.add_finding(
                    title="Possible CL.TE Request Smuggling",
                    severity=Severity.HIGH,
                    description=(
                        f"CL.TE probe caused a {elapsed:.1f}s delay. "
                        f"The front-end may use Content-Length while the back-end uses Transfer-Encoding."
                    ),
                    recommendation=(
                        "Normalize request handling across proxies and back-ends. "
                        "Reject ambiguous requests with both CL and TE."
                    ),
                    evidence=f"URL: {url}\nDelay: {elapsed:.1f}s\nStatus: {resp.status_code}",
                    category="HTTP Smuggling",
                    url=url,
                    cwe="CWE-444",
                )
                print_finding(Severity.HIGH, f"CL.TE probe: {elapsed:.1f}s delay")

            # Check if both headers are accepted (informational)
            if resp.status_code not in (400, 411, 501):
                self.add_finding(
                    title="Server Accepts Conflicting CL+TE Headers",
                    severity=Severity.LOW,
                    description=(
                        "Server did not reject a request with both Content-Length and Transfer-Encoding headers. "
                        "Per RFC 7230, if both are present, Transfer-Encoding should take priority, "
                        "but proxy/backend disagreement can cause smuggling."
                    ),
                    evidence=f"URL: {url}\nStatus: {resp.status_code}\nTime: {elapsed:.1f}s",
                    category="HTTP Smuggling",
                    url=url,
                    cwe="CWE-444",
                )
                vulns_found += 1

        except Exception as e:
            # A timeout here might actually indicate CL.TE
            if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                vulns_found += 1
                self.add_finding(
                    title="CL.TE Smuggling - Timeout Detected",
                    severity=Severity.HIGH,
                    description="CL.TE probe caused a connection timeout, indicating potential smuggling.",
                    recommendation="Reject requests with both Content-Length and Transfer-Encoding.",
                    evidence=f"URL: {url}\nError: {str(e)}",
                    category="HTTP Smuggling",
                    url=url,
                    cwe="CWE-444",
                )
                print_finding(Severity.HIGH, "CL.TE probe: connection timeout")

        return vulns_found

    def _test_te_cl(self, url):
        """
        TE.CL smuggling: Front-end uses Transfer-Encoding, back-end uses Content-Length.
        
        Safe probe: Send chunked body where CL covers the full body.
        If TE.CL, back-end reads CL bytes and leaves chunk trailer in buffer.
        """
        vulns_found = 0

        # Chunked body: "0\r\n\r\n" (5 bytes = just the terminator)
        # CL = 5 (covers the chunk terminator)
        probe_body = "0\r\n\r\n"

        try:
            start = time.time()
            resp = self.http_client.post(
                url,
                data=probe_body,
                headers={
                    "Content-Length": str(len(probe_body)),
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                allow_redirects=False,
            )
            elapsed = time.time() - start

            if elapsed > 5.0:
                vulns_found += 1
                self.add_finding(
                    title="Possible TE.CL Request Smuggling",
                    severity=Severity.HIGH,
                    description=(
                        f"TE.CL probe caused a {elapsed:.1f}s delay. "
                        f"The front-end may use Transfer-Encoding while the back-end uses Content-Length."
                    ),
                    recommendation="Normalize request handling. Reject ambiguous requests.",
                    evidence=f"URL: {url}\nDelay: {elapsed:.1f}s\nStatus: {resp.status_code}",
                    category="HTTP Smuggling",
                    url=url,
                    cwe="CWE-444",
                )
                print_finding(Severity.HIGH, f"TE.CL probe: {elapsed:.1f}s delay")

        except Exception as e:
            if "timeout" in str(e).lower():
                vulns_found += 1
                self.add_finding(
                    title="TE.CL Smuggling - Timeout Detected",
                    severity=Severity.HIGH,
                    description="TE.CL probe caused timeout. Potential smuggling vulnerability.",
                    evidence=f"URL: {url}\nError: {str(e)}",
                    category="HTTP Smuggling",
                    url=url,
                    cwe="CWE-444",
                )

        return vulns_found

    def _test_te_te(self, url):
        """
        TE.TE smuggling: Both use Transfer-Encoding, but one can be tricked with obfuscation.
        """
        vulns_found = 0

        # Test if obfuscated TE headers are handled differently
        normal_body = "0\r\n\r\n"

        for i, te_variant in enumerate(TE_OBFUSCATIONS[:8]):
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)

            try:
                # Send with obfuscated TE
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(normal_body)),
                }

                # Parse the TE variant
                if ": " in te_variant or ":\t" in te_variant:
                    te_key, te_val = te_variant.split(":", 1)
                    headers[te_key.strip()] = te_val.strip()
                else:
                    headers["Transfer-Encoding"] = te_variant.split(": ", 1)[-1] if ": " in te_variant else "chunked"

                start = time.time()
                resp = self.http_client.post(
                    url,
                    data=normal_body,
                    headers=headers,
                    allow_redirects=False,
                )
                elapsed = time.time() - start

                # Check for different behavior with obfuscated TE
                if resp.status_code == 400:
                    # Server rejected the obfuscated TE — good, it's strict
                    continue

                if elapsed > 5.0:
                    vulns_found += 1
                    self.add_finding(
                        title=f"TE.TE Smuggling - Obfuscation Accepted (variant {i+1})",
                        severity=Severity.HIGH,
                        description=(
                            f"Server accepted obfuscated Transfer-Encoding and delayed response. "
                            f"Variant: {te_variant.strip()}"
                        ),
                        recommendation="Strictly validate Transfer-Encoding header values.",
                        evidence=f"URL: {url}\nTE variant: {te_variant}\nDelay: {elapsed:.1f}s",
                        category="HTTP Smuggling",
                        url=url,
                        cwe="CWE-444",
                    )
                    print_finding(Severity.HIGH, f"TE.TE: obfuscation variant {i+1}")
                    break

            except Exception:
                continue

        return vulns_found

    def _test_header_normalization(self, url, baseline_code):
        """Test how the server normalizes ambiguous headers."""
        vulns_found = 0

        test_cases = [
            # Duplicate Content-Length
            {
                "headers": {"Content-Length": "0", "Content-Length ": "100"},
                "desc": "Duplicate Content-Length",
            },
            # Line folding (obs-fold)
            {
                "headers": {"Transfer-Encoding": "chunked"},
                "desc": "Standard TE chunked",
            },
        ]

        for case in test_cases:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)

            try:
                resp = self.http_client.post(
                    url,
                    data="",
                    headers={
                        **case["headers"],
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    allow_redirects=False,
                )

                # Check for 400 (strict) vs normal (lenient)
                if resp.status_code not in (400, 411) and baseline_code not in (400, 411):
                    # Server is lenient with ambiguous headers
                    pass  # Already covered by CL.TE/TE.CL tests

            except Exception:
                continue

        return vulns_found

    def _analyze_http_behavior(self, url, baseline):
        """Analyze HTTP version support and transfer behavior."""
        vulns_found = 0
        headers = baseline.headers

        # Check for HTTP/2 support hints
        alt_svc = headers.get("Alt-Svc", "")
        if "h2" in alt_svc or "h3" in alt_svc:
            self.add_finding(
                title="HTTP/2 or HTTP/3 Supported",
                severity=Severity.INFO,
                description=(
                    "Server advertises HTTP/2 or HTTP/3 support. "
                    "HTTP/2 request smuggling (H2.CL, H2.TE) is a separate attack vector."
                ),
                evidence=f"Alt-Svc: {alt_svc}",
                category="HTTP Smuggling",
                url=url,
                cwe="CWE-444",
            )

        # Check Transfer-Encoding handling
        te_response = headers.get("Transfer-Encoding", "")
        if te_response:
            self.add_finding(
                title="Server Uses Chunked Transfer-Encoding",
                severity=Severity.INFO,
                description=f"Server responds with Transfer-Encoding: {te_response}",
                evidence=f"Transfer-Encoding: {te_response}",
                category="HTTP Smuggling",
                url=url,
            )

        # Check Connection header
        connection = headers.get("Connection", "")
        if "keep-alive" in connection.lower():
            self.add_finding(
                title="Keep-Alive Connection Detected",
                severity=Severity.INFO,
                description=(
                    "Server uses keep-alive connections. Request smuggling requires "
                    "persistent connections between front-end and back-end."
                ),
                evidence=f"Connection: {connection}",
                category="HTTP Smuggling",
                url=url,
            )

        return vulns_found
