"""
IDOR / BOLA Scanner (Broken Object-Level Authorization).

Discovers numeric/UUID identifiers in URLs, parameters, and response bodies,
then attempts to access other objects by manipulating those identifiers:
  - Sequential ID probing (id=1 → id=2)
  - UUID prediction / swap testing
  - Horizontal privilege escalation checks
  - API endpoint authorization bypass
  - BFLA (Broken Function-Level Authorization) checks
"""

import re
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Patterns for object references in URLs/params
ID_PATTERNS = [
    (r'/(\d{1,10})(?:/|$|\?)', "numeric_path", "Numeric path ID"),
    (r'[?&]id=(\d{1,10})', "id_param", "ID parameter"),
    (r'[?&]user_?id=(\d{1,10})', "user_id_param", "User ID parameter"),
    (r'[?&]account_?id=(\d{1,10})', "account_id_param", "Account ID parameter"),
    (r'[?&]order_?id=(\d{1,10})', "order_id_param", "Order ID parameter"),
    (r'[?&]item_?id=(\d{1,10})', "item_id_param", "Item ID parameter"),
    (r'[?&]doc(?:ument)?_?id=(\d{1,10})', "doc_id_param", "Document ID parameter"),
    (r'[?&]file_?id=(\d{1,10})', "file_id_param", "File ID parameter"),
    (r'[?&]profile_?id=(\d{1,10})', "profile_id_param", "Profile ID parameter"),
    (r'[?&](?:uid|uuid)=([a-f0-9-]{36})', "uuid_param", "UUID parameter"),
]

# API endpoints that commonly have IDOR issues
API_IDOR_PATTERNS = [
    r'/api/v\d+/users?/\d+',
    r'/api/v\d+/accounts?/\d+',
    r'/api/v\d+/orders?/\d+',
    r'/api/v\d+/profiles?/\d+',
    r'/api/v\d+/documents?/\d+',
    r'/api/v\d+/files?/\d+',
    r'/api/v\d+/invoices?/\d+',
    r'/api/v\d+/messages?/\d+',
    r'/api/v\d+/tickets?/\d+',
    r'/api/v\d+/comments?/\d+',
    r'/users?/\d+',
    r'/accounts?/\d+',
    r'/profiles?/\d+',
]

# HTTP methods to test for BFLA
BFLA_METHODS = ["GET", "PUT", "PATCH", "DELETE", "POST"]


class IDORScanner(SmartScanner):
    name = "IDOR/BOLA Scanner"
    description = "Test for Broken Object-Level Authorization and Insecure Direct Object References"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"IDOR/BOLA analysis on {url}", "progress")

        # ── Phase 1: Discover object references ───────────────────
        print_status("Phase 1: Object reference discovery", "progress")
        references = self._discover_references(url)
        print_status(f"Found {len(references)} object reference(s)", "info")

        # ── Phase 2: Test authorization bypass ────────────────────
        print_status("Phase 2: Authorization bypass testing", "progress")
        for ref in references:
            self._test_idor(url, ref)

        # ── Phase 3: API endpoint IDOR testing ────────────────────
        print_status("Phase 3: API endpoint IDOR testing", "progress")
        self._test_api_idor(url)

        # ── Phase 4: BFLA (function-level) checks ─────────────────
        print_status("Phase 4: BFLA method-level checks", "progress")
        self._test_bfla(url)

        # ── Phase 5: Response comparison analysis ─────────────────
        print_status("Phase 5: Response data exposure analysis", "progress")
        self._check_data_exposure(url)

    def _discover_references(self, url):
        """Discover object references in URL, crawled pages, and responses."""
        references = []

        # Check the target URL itself
        for pattern, ref_type, desc in ID_PATTERNS:
            match = re.search(pattern, url)
            if match:
                references.append({
                    "type": ref_type,
                    "value": match.group(1),
                    "description": desc,
                    "url": url,
                    "full_match": match.group(0),
                })

        # Check crawled URLs from context
        crawled = self.context.get_crawled_urls() if hasattr(self.context, 'get_crawled_urls') else []
        for crawled_url in crawled[:50]:
            for pattern, ref_type, desc in ID_PATTERNS:
                match = re.search(pattern, crawled_url)
                if match:
                    references.append({
                        "type": ref_type,
                        "value": match.group(1),
                        "description": desc,
                        "url": crawled_url,
                        "full_match": match.group(0),
                    })

        # Fetch the main page and look for ID references in links
        try:
            resp = self.http_client.get(url)
            links = re.findall(r'href=["\']([^"\']+)', resp.text)
            for link in links[:100]:
                full_link = urljoin(url, link)
                if urlparse(url).hostname in full_link:
                    for pattern, ref_type, desc in ID_PATTERNS:
                        match = re.search(pattern, full_link)
                        if match:
                            references.append({
                                "type": ref_type,
                                "value": match.group(1),
                                "description": desc,
                                "url": full_link,
                                "full_match": match.group(0),
                            })
        except Exception:
            pass

        # Deduplicate
        seen = set()
        unique_refs = []
        for ref in references:
            key = (ref["type"], ref["value"], ref["url"])
            if key not in seen:
                seen.add(key)
                unique_refs.append(ref)

        return unique_refs[:20]  # Limit to 20

    def _test_idor(self, base_url, ref):
        """Test a discovered object reference for IDOR."""
        original_url = ref["url"]
        original_value = ref["value"]

        # Generate alternative IDs to test
        if ref["type"].endswith("_param") and "uuid" not in ref["type"]:
            try:
                original_id = int(original_value)
                test_ids = [
                    str(original_id + 1),
                    str(original_id - 1) if original_id > 1 else "0",
                    str(original_id + 100),
                    "1",
                    "0",
                    "-1",
                ]
            except ValueError:
                return
        elif "uuid" in ref["type"]:
            # Can't easily guess UUIDs, but test with known patterns
            test_ids = [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000000",
            ]
        elif ref["type"] == "numeric_path":
            try:
                original_id = int(original_value)
                test_ids = [str(original_id + 1), str(original_id - 1) if original_id > 1 else "0", "1"]
            except ValueError:
                return
        else:
            return

        # Get original response for comparison
        try:
            orig_resp = self.http_client.get(original_url, timeout=10)
            orig_status = orig_resp.status_code
            orig_length = len(orig_resp.text)
            orig_hash = hashlib.md5(orig_resp.text.encode()).hexdigest()
        except Exception:
            return

        # Test each alternative ID
        for test_id in test_ids:
            test_url = original_url.replace(original_value, test_id, 1)
            if test_url == original_url:
                continue

            try:
                test_resp = self.http_client.get(test_url, timeout=10)
                test_status = test_resp.status_code
                test_length = len(test_resp.text)
                test_hash = hashlib.md5(test_resp.text.encode()).hexdigest()

                # Analyze the response
                if test_status == 200 and test_hash != orig_hash:
                    # Different content returned — potential IDOR
                    # Check if response contains data (not just error page)
                    if test_length > 100 and not self._is_error_page(test_resp.text):
                        severity = Severity.HIGH
                        if abs(test_length - orig_length) < 50:
                            severity = Severity.MEDIUM  # Similar size, might be template

                        self.add_finding(
                            title=f"Potential IDOR: {ref['description']} ({original_value} → {test_id})",
                            severity=severity,
                            description=(
                                f"Changing the {ref['description']} from '{original_value}' to "
                                f"'{test_id}' returned a different 200 OK response, suggesting "
                                f"the application does not properly validate object ownership.\n"
                                f"Original: {orig_status} ({orig_length} bytes)\n"
                                f"Modified: {test_status} ({test_length} bytes)"
                            ),
                            recommendation=(
                                "Implement proper authorization checks:\n"
                                "1. Verify object ownership on every request\n"
                                "2. Use session-based user context, not client-supplied IDs\n"
                                "3. Use unpredictable references (UUIDs) instead of sequential IDs\n"
                                "4. Implement row-level security policies"
                            ),
                            evidence=f"Original URL: {original_url}\nModified URL: {test_url}\nOriginal size: {orig_length}\nModified size: {test_length}",
                            category="IDOR/BOLA",
                            url=test_url,
                            cwe="CWE-639",
                        )
                        print_finding(severity, f"IDOR: {ref['description']} ({original_value}→{test_id})")
                        break  # One finding per reference

                elif test_status == 403:
                    # Good — authorization is checked
                    pass
                elif test_status == 401:
                    # Good — authentication required
                    pass

            except Exception:
                continue

    def _test_api_idor(self, url):
        """Test common API endpoint patterns for IDOR."""
        api_bases = [
            "/api/v1", "/api/v2", "/api",
            "/rest/v1", "/rest",
            "/wp-json/wp/v2",
        ]
        resources = ["users", "accounts", "posts", "orders", "profiles", "comments"]

        for base in api_bases:
            for resource in resources:
                # Test with ID 1 and 2
                for test_id in [1, 2]:
                    test_url = urljoin(url, f"{base}/{resource}/{test_id}")
                    try:
                        resp = self.http_client.get(test_url, timeout=10)
                        if resp.status_code == 200:
                            # Check if response contains actual data
                            try:
                                data = resp.json()
                                if isinstance(data, dict) and len(data) > 2:
                                    # Check for sensitive fields
                                    sensitive_fields = {"email", "password", "ssn", "phone",
                                                       "address", "credit_card", "secret",
                                                       "token", "api_key", "private"}
                                    found_sensitive = sensitive_fields & set(str(k).lower() for k in data.keys())
                                    if found_sensitive:
                                        self.add_finding(
                                            title=f"API IDOR: {base}/{resource}/{test_id} exposes sensitive data",
                                            severity=Severity.HIGH,
                                            description=(
                                                f"API endpoint returns sensitive data fields: {', '.join(found_sensitive)}\n"
                                                f"No authentication required to access this resource."
                                            ),
                                            recommendation="Implement authentication and authorization on all API endpoints.",
                                            evidence=f"URL: {test_url}\nSensitive fields: {', '.join(found_sensitive)}\nResponse keys: {', '.join(list(data.keys())[:10])}",
                                            category="IDOR/BOLA",
                                            url=test_url,
                                            cwe="CWE-639",
                                        )
                                        print_finding(Severity.HIGH, f"API IDOR: {test_url}")
                                    else:
                                        # Still report unauthenticated data access
                                        self.add_finding(
                                            title=f"API data exposure: {base}/{resource}/{test_id}",
                                            severity=Severity.MEDIUM,
                                            description=f"API endpoint returns data without authentication.",
                                            recommendation="Require authentication for API endpoints.",
                                            evidence=f"URL: {test_url}\nResponse keys: {', '.join(list(data.keys())[:10])}",
                                            category="IDOR/BOLA",
                                            url=test_url,
                                            cwe="CWE-639",
                                        )
                            except Exception:
                                pass
                    except Exception:
                        continue

    def _test_bfla(self, url):
        """Test for Broken Function-Level Authorization (HTTP method attacks)."""
        # Try unsafe methods on common endpoints
        test_paths = [
            "/api/v1/users/1",
            "/api/v2/users/1",
            "/api/users/1",
            "/wp-json/wp/v2/users/1",
        ]

        for path in test_paths:
            test_url = urljoin(url, path)
            for method in ["PUT", "DELETE", "PATCH"]:
                try:
                    resp = self.http_client.request(
                        method, test_url,
                        timeout=10,
                        json={"role": "admin"} if method in ("PUT", "PATCH") else None,
                    )
                    if resp.status_code in (200, 201, 204):
                        self.add_finding(
                            title=f"BFLA: {method} {path} accepted",
                            severity=Severity.HIGH,
                            description=(
                                f"The endpoint {path} accepts {method} requests without "
                                f"proper authorization. This could allow privilege escalation "
                                f"or data modification."
                            ),
                            recommendation="Implement proper authorization for all HTTP methods.",
                            evidence=f"Method: {method}\nURL: {test_url}\nStatus: {resp.status_code}",
                            category="IDOR/BOLA",
                            url=test_url,
                            cwe="CWE-285",
                        )
                        print_finding(Severity.HIGH, f"BFLA: {method} {path} accepted ({resp.status_code})")
                except Exception:
                    continue

    def _check_data_exposure(self, url):
        """Check API responses for excessive data exposure."""
        endpoints = [
            "/wp-json/wp/v2/users",
            "/api/v1/users",
            "/api/v2/users",
            "/api/users",
        ]

        for endpoint in endpoints:
            test_url = urljoin(url, endpoint)
            try:
                resp = self.http_client.get(test_url, timeout=10)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 0:
                            # User enumeration
                            if any(isinstance(u, dict) and ("name" in u or "username" in u or "slug" in u) for u in data[:5]):
                                users = []
                                for u in data[:5]:
                                    name = u.get("name") or u.get("username") or u.get("slug", "?")
                                    users.append(str(name))

                                self.add_finding(
                                    title=f"User enumeration: {endpoint}",
                                    severity=Severity.MEDIUM,
                                    description=f"API endpoint exposes user list: {', '.join(users)}",
                                    recommendation="Restrict user list endpoints to authenticated admin users.",
                                    evidence=f"URL: {test_url}\nUsers found: {', '.join(users)}",
                                    category="IDOR/BOLA",
                                    url=test_url,
                                    cwe="CWE-200",
                                )
                    except Exception:
                        pass
            except Exception:
                continue

    def _is_error_page(self, html):
        """Check if response is a generic error page."""
        error_indicators = [
            "404 not found", "page not found", "not exist",
            "error 404", "access denied", "forbidden",
            "unauthorized", "login required",
        ]
        html_lower = html.lower()
        return any(indicator in html_lower for indicator in error_indicators)
