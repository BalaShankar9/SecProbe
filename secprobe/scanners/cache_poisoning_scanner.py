"""
Web Cache Poisoning Scanner — CWE-444 / CWE-349.

Based on PortSwigger research:
  Phase 1: Cache detection & behavior profiling
  Phase 2: Unkeyed header discovery (X-Forwarded-Host, X-Forwarded-Scheme, etc.)
  Phase 3: Unkeyed query parameter discovery (UTM params, cache busters)
  Phase 4: Fat GET request body poisoning
  Phase 5: Cache key normalization attacks (path traversal, encoded chars)
  Phase 6: Cache deception via path confusion

Detection strategy:
  1. Identify if a cache is present (Age, X-Cache, CF-Cache-Status, etc.)
  2. Send requests with a unique cache-buster parameter to isolate tests
  3. Inject canary values via unkeyed inputs
  4. Fetch the same URL without injection to check if poisoned response is served
"""

import hashlib
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Headers that may be unkeyed in caches
UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "{CANARY}"),
    ("X-Host", "{CANARY}"),
    ("X-Original-URL", "/{CANARY}"),
    ("X-Rewrite-URL", "/{CANARY}"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto", "nothttps"),
    ("X-Forwarded-Port", "1234"),
    ("X-Forwarded-Prefix", "/{CANARY}"),
    ("X-Original-Host", "{CANARY}"),
    ("Forwarded", "host={CANARY}"),
    ("X-Forwarded-Server", "{CANARY}"),
    ("X-HTTP-Method-Override", "POST"),
    ("X-Method-Override", "DELETE"),
]

# Cache indicator headers
CACHE_INDICATORS = [
    "x-cache", "x-cache-hit", "cf-cache-status", "x-varnish",
    "x-proxy-cache", "age", "x-cdn", "x-edge-cache", "x-fastly-request-id",
    "x-served-by", "x-cache-status", "x-drupal-cache", "x-rack-cache",
    "x-akamai-transformed", "cdn-cache-status",
]

# Query params often excluded from cache key
UNKEYED_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "mc_cid", "mc_eid", "_ga", "_gl",
    "callback", "jsonp", "_", "timestamp",
]


class CachePoisoningScanner(SmartScanner):
    name = "Cache Poisoning Scanner"
    description = "Test for web cache poisoning and cache deception vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing cache poisoning on {url}", "progress")

        # Phase 1: Detect cache
        print_status("Phase 1: Cache detection & profiling", "progress")
        cache_info = self._detect_cache(url)

        if not cache_info["has_cache"]:
            print_status("No caching layer detected — limited testing.", "info")

        vulns = 0

        # Phase 2: Unkeyed header discovery
        print_status("Phase 2: Unkeyed header discovery", "progress")
        vulns += self._test_unkeyed_headers(url, cache_info)

        # Phase 3: Unkeyed query parameters
        print_status("Phase 3: Unkeyed query parameter discovery", "progress")
        vulns += self._test_unkeyed_params(url, cache_info)

        # Phase 4: Fat GET
        print_status("Phase 4: Fat GET request body poisoning", "progress")
        vulns += self._test_fat_get(url, cache_info)

        # Phase 5: Cache key normalization
        print_status("Phase 5: Cache key normalization attacks", "progress")
        vulns += self._test_key_normalization(url, cache_info)

        # Phase 6: Cache deception
        print_status("Phase 6: Cache deception via path confusion", "progress")
        vulns += self._test_cache_deception(url, cache_info)

        if vulns == 0:
            self.add_finding(
                title="No cache poisoning vulnerabilities detected",
                severity=Severity.INFO,
                description="Automated tests did not find cache poisoning issues.",
                category="Cache Poisoning",
            )
            print_status("No cache poisoning vulnerabilities detected.", "success")

    # ── Phase 1: Cache detection ─────────────────────────────────────

    def _detect_cache(self, url):
        """Profile the caching layer."""
        info = {
            "has_cache": False,
            "cache_headers": {},
            "cache_type": "unknown",
            "cacheable": False,
        }

        try:
            resp = self.http_client.get(url)
        except Exception as e:
            self.result.error = str(e)
            return info

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Detect cache indicators
        for indicator in CACHE_INDICATORS:
            if indicator in headers_lower:
                info["has_cache"] = True
                info["cache_headers"][indicator] = headers_lower[indicator]

        # Identify cache type
        if "cf-cache-status" in headers_lower:
            info["cache_type"] = "cloudflare"
        elif "x-fastly-request-id" in headers_lower:
            info["cache_type"] = "fastly"
        elif "x-varnish" in headers_lower:
            info["cache_type"] = "varnish"
        elif "x-akamai-transformed" in headers_lower:
            info["cache_type"] = "akamai"
        elif "x-cache" in headers_lower:
            info["cache_type"] = "cdn/proxy"

        # Check Cache-Control
        cc = headers_lower.get("cache-control", "")
        if "no-store" not in cc and "private" not in cc:
            info["cacheable"] = True

        # Send second request to confirm caching (check Age or HIT)
        if info["has_cache"]:
            try:
                resp2 = self.http_client.get(url)
                age = resp2.headers.get("Age", "")
                cache_status = (
                    resp2.headers.get("X-Cache", "")
                    or resp2.headers.get("CF-Cache-Status", "")
                    or resp2.headers.get("X-Cache-Status", "")
                )
                if age or "HIT" in cache_status.upper():
                    info["cacheable"] = True
            except Exception:
                pass

        self.result.raw_data["cache_info"] = info

        if info["has_cache"]:
            print_status(
                f"Cache detected: {info['cache_type']} "
                f"(cacheable: {info['cacheable']})", "info"
            )
        return info

    # ── Phase 2: Unkeyed headers ─────────────────────────────────────

    def _test_unkeyed_headers(self, url, cache_info):
        """Discover headers not included in the cache key."""
        vulns = 0
        canary_base = hashlib.md5(url.encode()).hexdigest()[:8]

        for header_name, header_template in UNKEYED_HEADERS:
            canary = f"secprobe-{canary_base}-{header_name.lower()}"
            header_value = header_template.replace("{CANARY}", canary)

            # Use a unique cache buster for each test
            buster = hashlib.md5(f"{header_name}{time.time()}".encode()).hexdigest()[:8]
            test_url = f"{url}{'&' if '?' in url else '?'}cb={buster}"

            try:
                # Step 1: Poison — send request with unkeyed header
                resp1 = self.http_client.get(test_url, headers={header_name: header_value})

                # Check if canary reflected in the response
                if canary not in resp1.text and "nothttps" not in resp1.text:
                    continue

                # Step 2: Verify — fetch same URL without the header
                if cache_info["has_cache"]:
                    resp2 = self.http_client.get(test_url)
                    if canary in resp2.text or "nothttps" in resp2.text:
                        # Cache served the poisoned response!
                        vulns += 1
                        self.add_finding(
                            title=f"Cache Poisoning via {header_name}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The {header_name} header is reflected in the response AND "
                                f"the value persists in the cache. An attacker can inject "
                                f"malicious content that will be served to other users."
                            ),
                            recommendation=(
                                f"Either include {header_name} in the cache key, "
                                f"or stop using it in response generation."
                            ),
                            evidence=(
                                f"Header: {header_name}: {header_value}\n"
                                f"Canary: {canary}\n"
                                f"Cached: Yes (served without header)"
                            ),
                            category="Cache Poisoning", url=url, cwe="CWE-349",
                        )
                        print_finding(Severity.CRITICAL, f"Cache poisoning via {header_name}")
                        continue

                # Even without cache confirmation, reflection is risky
                vulns += 1
                severity = Severity.HIGH if cache_info["has_cache"] else Severity.MEDIUM
                self.add_finding(
                    title=f"Unkeyed header reflected: {header_name}",
                    severity=severity,
                    description=(
                        f"The {header_name} header value is reflected in the response. "
                        f"If a caching layer is present, this can lead to cache poisoning."
                    ),
                    recommendation=f"Do not reflect {header_name} in responses.",
                    evidence=f"Header: {header_name}: {header_value}\nReflected: Yes",
                    category="Cache Poisoning", url=url, cwe="CWE-349",
                )
                print_finding(severity, f"Unkeyed header reflected: {header_name}")

            except Exception:
                continue

        return vulns

    # ── Phase 3: Unkeyed query parameters ────────────────────────────

    def _test_unkeyed_params(self, url, cache_info):
        """Discover query parameters excluded from the cache key."""
        if not cache_info["has_cache"]:
            return 0

        vulns = 0
        canary_base = hashlib.md5(url.encode()).hexdigest()[:8]

        for param in UNKEYED_PARAMS:
            canary = f"secprobe-{canary_base}-{param}"
            buster = hashlib.md5(f"{param}{time.time()}".encode()).hexdigest()[:8]

            # Build URL with the test param + a cache buster
            test_url = f"{url}{'&' if '?' in url else '?'}cb={buster}&{param}={canary}"

            try:
                # Step 1: Send request with param
                resp1 = self.http_client.get(test_url)
                if canary not in resp1.text:
                    continue

                # Step 2: Fetch same URL without the param (keep cache buster)
                clean_url = f"{url}{'&' if '?' in url else '?'}cb={buster}"
                resp2 = self.http_client.get(clean_url)

                if canary in resp2.text:
                    vulns += 1
                    self.add_finding(
                        title=f"Cache Poisoning via unkeyed parameter: {param}",
                        severity=Severity.HIGH,
                        description=(
                            f"The '{param}' query parameter is reflected in the response "
                            f"but not included in the cache key. An attacker can poison "
                            f"cached pages by including this parameter."
                        ),
                        recommendation=f"Include '{param}' in the cache key or don't reflect it.",
                        evidence=f"Parameter: {param}={canary}\nCached: Yes",
                        category="Cache Poisoning", url=url, cwe="CWE-349",
                    )
                    print_finding(Severity.HIGH, f"Unkeyed parameter: {param}")

            except Exception:
                continue

        return vulns

    # ── Phase 4: Fat GET ─────────────────────────────────────────────

    def _test_fat_get(self, url, cache_info):
        """Test if GET request body is processed but not part of cache key."""
        vulns = 0
        canary = f"secprobe-fatget-{hashlib.md5(url.encode()).hexdigest()[:8]}"
        buster = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        test_url = f"{url}{'&' if '?' in url else '?'}cb={buster}"

        try:
            # Send GET with a body (some frameworks process this)
            resp1 = self.http_client.request(
                "GET", test_url,
                data=f"callback={canary}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ) if hasattr(self.http_client, 'request') else None

            if resp1 is None:
                return 0

            if canary in resp1.text:
                # Check if cached without body
                if cache_info["has_cache"]:
                    resp2 = self.http_client.get(test_url)
                    if canary in resp2.text:
                        vulns += 1
                        self.add_finding(
                            title="Cache Poisoning via Fat GET request",
                            severity=Severity.HIGH,
                            description=(
                                "The server processes the body of GET requests, but the cache "
                                "does not include the body in its key. An attacker can poison "
                                "the cache by sending a GET request with a body."
                            ),
                            recommendation="Reject or ignore GET request bodies. Configure cache to vary on body.",
                            evidence=f"Canary: {canary}\nCached: Yes",
                            category="Cache Poisoning", url=url, cwe="CWE-444",
                        )
                        print_finding(Severity.HIGH, "Fat GET cache poisoning")
                        return vulns

                vulns += 1
                self.add_finding(
                    title="GET request body processed",
                    severity=Severity.MEDIUM,
                    description=(
                        "The server processes the body of GET requests. "
                        "If a caching layer is added, this creates a cache poisoning vector."
                    ),
                    recommendation="Reject or ignore GET request bodies.",
                    evidence=f"Canary: {canary}\nReflected: Yes",
                    category="Cache Poisoning", url=url, cwe="CWE-444",
                )

        except Exception:
            pass

        return vulns

    # ── Phase 5: Cache key normalization ─────────────────────────────

    def _test_key_normalization(self, url, cache_info):
        """Test cache key normalization (path decoding, case sensitivity, etc.)."""
        if not cache_info["has_cache"]:
            return 0

        vulns = 0
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test case normalization
        try:
            path = parsed.path or "/"
            if path != "/":
                upper_path = path.upper()
                resp_normal = self.http_client.get(url)
                resp_upper = self.http_client.get(f"{base}{upper_path}")

                if (resp_normal.status_code == resp_upper.status_code
                        and resp_normal.status_code == 200):
                    # Same content via different case — normalization issue
                    normal_cache = resp_normal.headers.get("X-Cache", "") or resp_normal.headers.get("CF-Cache-Status", "")
                    upper_cache = resp_upper.headers.get("X-Cache", "") or resp_upper.headers.get("CF-Cache-Status", "")

                    if "HIT" in normal_cache.upper() and "MISS" in upper_cache.upper():
                        vulns += 1
                        self.add_finding(
                            title="Cache key case sensitivity mismatch",
                            severity=Severity.MEDIUM,
                            description=(
                                "The origin server treats paths case-insensitively but the cache "
                                "uses case-sensitive keys. This allows cache poisoning by sending "
                                "the same path with different casing."
                            ),
                            recommendation="Normalize path case before generating cache keys.",
                            evidence=f"Normal: {path} ({normal_cache})\nUpper: {upper_path} ({upper_cache})",
                            category="Cache Poisoning", url=url, cwe="CWE-349",
                        )
        except Exception:
            pass

        # Test encoded path normalization
        try:
            canary_path = parsed.path.replace("/", "%2F") if parsed.path and len(parsed.path) > 1 else None
            if canary_path:
                resp_encoded = self.http_client.get(f"{base}{canary_path}", allow_redirects=False)
                if resp_encoded.status_code == 200:
                    encoded_cache = (
                        resp_encoded.headers.get("X-Cache", "")
                        or resp_encoded.headers.get("CF-Cache-Status", "")
                    )
                    if "MISS" in encoded_cache.upper():
                        vulns += 1
                        self.add_finding(
                            title="Cache key path encoding inconsistency",
                            severity=Severity.LOW,
                            description=(
                                "Encoded and unencoded versions of the same path produce different "
                                "cache entries. This may enable cache poisoning."
                            ),
                            recommendation="Normalize URL encoding before generating cache keys.",
                            evidence=f"Normal: {parsed.path}\nEncoded: {canary_path}",
                            category="Cache Poisoning", url=url, cwe="CWE-349",
                        )
        except Exception:
            pass

        return vulns

    # ── Phase 6: Cache deception ─────────────────────────────────────

    def _test_cache_deception(self, url, cache_info):
        """Test web cache deception — trick cache into storing private content."""
        vulns = 0
        parsed = urlparse(url)
        base_path = parsed.path.rstrip("/") or ""

        # Common static extensions that caches eagerly serve
        static_extensions = [".css", ".js", ".png", ".jpg", ".ico", ".svg"]

        for ext in static_extensions:
            deception_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/nonexistent{ext}"

            try:
                resp = self.http_client.get(deception_url)
            except Exception:
                continue

            if resp.status_code == 200:
                cache_status = (
                    resp.headers.get("X-Cache", "")
                    or resp.headers.get("CF-Cache-Status", "")
                    or resp.headers.get("X-Cache-Status", "")
                )
                content_type = resp.headers.get("Content-Type", "")

                # If cache stored an HTML response under a static extension URL
                if ("HIT" in cache_status.upper() or "MISS" in cache_status.upper()) and "html" in content_type.lower():
                    vulns += 1
                    self.add_finding(
                        title=f"Web Cache Deception ({ext})",
                        severity=Severity.HIGH,
                        description=(
                            f"The server returns dynamic/HTML content at a URL ending in '{ext}'. "
                            f"A cache may store this as a static resource. An attacker can trick "
                            f"a victim into visiting a URL like /account/profile{ext} which caches "
                            f"their private data for the attacker to retrieve."
                        ),
                        recommendation=(
                            "Return 404 for non-existent static resources. "
                            "Configure cache rules based on Content-Type, not URL extension."
                        ),
                        evidence=(
                            f"URL: {deception_url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Content-Type: {content_type}\n"
                            f"Cache: {cache_status}"
                        ),
                        category="Cache Deception", url=deception_url, cwe="CWE-525",
                    )
                    print_finding(Severity.HIGH, f"Cache deception via {ext}")
                    break  # One finding is enough

        return vulns
