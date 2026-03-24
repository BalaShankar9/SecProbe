"""
Race Condition Scanner — CWE-362: TOCTOU / Concurrency vulnerabilities.

Tests for:
  Phase 1: Discover susceptible endpoints (common API paths + crawl data)
  Phase 2: Concurrent request testing (fire N identical requests simultaneously)
  Phase 3: Limit-overrun tests (coupon reuse, balance overdraft, vote stuffing)
  Phase 4: Response consistency analysis (state corruption detection)
  Phase 5: Time-sensitive token races (reset tokens, OTP)

Detection strategy:
  1. Send N identical requests simultaneously via ThreadPoolExecutor
  2. Analyze for: multiple successes when only one should succeed,
     inconsistent response bodies, state corruption indicators
  3. Specifically test limit-based endpoints with concurrent duplicate requests
"""

import time
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Common endpoints susceptible to race conditions
RACE_ENDPOINTS = [
    ("/api/transfer", "POST", "Balance transfer"),
    ("/api/withdraw", "POST", "Withdrawal"),
    ("/api/payment", "POST", "Payment processing"),
    ("/api/redeem", "POST", "Coupon/voucher redemption"),
    ("/api/apply-coupon", "POST", "Coupon application"),
    ("/api/vote", "POST", "Voting"),
    ("/api/like", "POST", "Like/favorite"),
    ("/api/follow", "POST", "Follow action"),
    ("/api/register", "POST", "Account registration"),
    ("/api/invite", "POST", "Invitation send"),
    ("/checkout", "POST", "Checkout"),
    ("/cart/add", "POST", "Add to cart"),
    ("/api/v1/transactions", "POST", "Transaction creation"),
]

# Endpoints specifically for limit-overrun testing
LIMIT_OVERRUN_ENDPOINTS = [
    ("/api/redeem", "POST", {"code": "TESTCOUPON"}, "Coupon single-use bypass"),
    ("/api/apply-coupon", "POST", {"coupon": "TESTCODE"}, "Coupon application race"),
    ("/api/claim", "POST", {"reward": "signup"}, "One-time claim bypass"),
    ("/api/vote", "POST", {"option": "1"}, "Vote stuffing"),
    ("/api/like", "POST", {"id": "1"}, "Multiple like race"),
    ("/api/transfer", "POST", {"amount": "1", "to": "attacker"}, "Double-spend"),
    ("/api/withdraw", "POST", {"amount": "1"}, "Balance overdraft"),
]

# Token-related endpoints for time-sensitive races
TOKEN_ENDPOINTS = [
    "/forgot-password", "/password-reset", "/reset-password",
    "/api/auth/forgot-password", "/api/otp/send", "/api/otp/verify",
    "/api/auth/verify-email", "/verify-email",
]


class RaceConditionScanner(SmartScanner):
    name = "Race Condition Scanner"
    description = "Test for race condition / TOCTOU vulnerabilities (CWE-362)"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing race conditions on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
        except Exception as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        vulns_found = 0

        # ── Phase 1: Discover susceptible endpoints ──────────────────
        print_status("Phase 1: Discovering race-susceptible endpoints", "progress")
        endpoints = self._discover_endpoints(url, baseline.text)

        if not endpoints:
            print_status("No race-susceptible endpoints found via probing.", "info")

        print_status(f"Found {len(endpoints)} potential race condition target(s)", "info")

        # ── Phase 2: Concurrent request testing ──────────────────────
        if endpoints:
            print_status("Phase 2: Concurrent request race testing", "progress")
            for ep in endpoints:
                result = self._test_race_condition(ep["url"], ep["method"], ep.get("data"))
                if result:
                    vulns_found += 1

        # ── Phase 3: Limit-overrun testing ───────────────────────────
        print_status("Phase 3: Limit-overrun testing", "progress")
        vulns_found += self._test_limit_overrun(url)

        # ── Phase 4: Response consistency analysis ───────────────────
        print_status("Phase 4: GET endpoint response consistency", "progress")
        vulns_found += self._test_response_consistency(url)

        # ── Phase 5: Time-sensitive token races ──────────────────────
        print_status("Phase 5: Time-sensitive token race testing", "progress")
        vulns_found += self._test_token_race(url)

        # ── Phase 6: Form-based race conditions ──────────────────────
        if self.context:
            forms = self.context.get_injectable_forms()
            for form in forms:
                if form.get("method", "").upper() == "POST":
                    result = self._test_race_condition(
                        form["action"], "POST", form.get("fields", {}),
                    )
                    if result:
                        vulns_found += 1

        if vulns_found == 0:
            print_status("No race conditions detected.", "success")
            self.add_finding(
                title="No race conditions detected",
                severity=Severity.INFO,
                description="Automated race condition tests did not find vulnerabilities.",
                category="Race Condition",
            )

    def _discover_endpoints(self, url, html):
        """Find endpoints likely susceptible to race conditions."""
        endpoints = []
        seen = set()

        # Probe common paths
        for path, method, desc in RACE_ENDPOINTS:
            test_url = urljoin(url, path)
            try:
                resp = self.http_client.options(test_url, timeout=3)
                if resp.status_code < 405:
                    if test_url not in seen:
                        endpoints.append({
                            "url": test_url, "method": method,
                            "desc": desc, "data": {"amount": "1", "item": "test"},
                        })
                        seen.add(test_url)
            except Exception:
                continue

        # Check forms from attack surface
        if self.context:
            for form in self.context.get_injectable_forms():
                action = form.get("action", url)
                if form.get("method", "").upper() == "POST" and action not in seen:
                    endpoints.append({
                        "url": action, "method": "POST",
                        "desc": "Form endpoint", "data": form.get("fields", {}),
                    })
                    seen.add(action)

        return endpoints

    def _test_race_condition(self, url, method, data=None, threads=10):
        """
        Send concurrent identical requests and analyze for race conditions.
        Returns True if race condition indicators are found.
        """
        results = []
        errors = []
        lock = threading.Lock()

        def send_request():
            try:
                if method.upper() == "POST":
                    resp = self.http_client.post(url, data=data or {}, timeout=10)
                else:
                    resp = self.http_client.get(url, timeout=10)
                with lock:
                    results.append({
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "body_hash": hash(resp.text),
                        "text_sample": resp.text[:200],
                    })
            except Exception as e:
                with lock:
                    errors.append(str(e))

        # Fire concurrent requests
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_request) for _ in range(threads)]
            for f in as_completed(futures, timeout=30):
                pass

        if len(results) < 3:
            return False

        # Analyze results for race condition indicators
        status_codes = [r["status"] for r in results]
        sizes = [r["size"] for r in results]
        body_hashes = [r["body_hash"] for r in results]

        success_count = status_codes.count(200) + status_codes.count(201)
        unique_hashes = len(set(body_hashes))
        unique_statuses = len(set(status_codes))

        if sizes:
            avg_size = sum(sizes) / len(sizes)
            size_variance = max(sizes) - min(sizes)
        else:
            avg_size = 0
            size_variance = 0

        is_race = False

        # All concurrent POST requests succeeded with different responses
        if success_count == len(results) and method.upper() == "POST":
            if unique_hashes > 1:
                is_race = True
                self.add_finding(
                    title=f"Potential race condition — {url}",
                    severity=Severity.HIGH,
                    description=(
                        f"{success_count}/{len(results)} concurrent requests succeeded "
                        f"with {unique_hashes} different response bodies. "
                        f"This suggests the server may be vulnerable to race conditions."
                    ),
                    recommendation=(
                        "Implement proper locking/mutex. Use database transactions "
                        "with serialization. Apply idempotency keys."
                    ),
                    evidence=(
                        f"URL: {url}\nMethod: {method}\nThreads: {threads}\n"
                        f"Success: {success_count}, Unique bodies: {unique_hashes}\n"
                        f"Size range: {min(sizes)}-{max(sizes)}"
                    ),
                    category="Race Condition", url=url, cwe="CWE-362",
                )
                print_finding(Severity.HIGH, f"Race condition: {url}")

        # Mixed success/failure with significant size variance
        elif unique_statuses > 1 and success_count > 1:
            if size_variance > avg_size * 0.5 and avg_size > 0:
                is_race = True
                self.add_finding(
                    title=f"Race condition — Inconsistent responses at {url}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Concurrent requests produce inconsistent results. "
                        f"Statuses: {set(status_codes)}, Size variance: {size_variance}B"
                    ),
                    recommendation="Implement proper concurrency controls.",
                    evidence=f"URL: {url}\nStatuses: {status_codes}",
                    category="Race Condition", url=url, cwe="CWE-362",
                )

        return is_race

    def _test_limit_overrun(self, url):
        """
        Test limit-bypass race conditions:
        Send concurrent identical requests to endpoints with usage limits.
        If more succeed than expected, the server lacks atomic limit enforcement.
        """
        vulns = 0

        for path, method, data, desc in LIMIT_OVERRUN_ENDPOINTS:
            test_url = urljoin(url, path)

            # First check if endpoint exists
            try:
                probe = self.http_client.options(test_url, timeout=3)
                if probe.status_code >= 405:
                    continue
            except Exception:
                continue

            # Send a single request to get baseline
            try:
                single = self.http_client.post(test_url, data=data, timeout=10)
                single_status = single.status_code
                single_body = single.text
            except Exception:
                continue

            # Now fire concurrent requests
            results = []
            lock = threading.Lock()
            threads = 15

            def fire():
                try:
                    resp = self.http_client.post(test_url, data=data, timeout=10)
                    with lock:
                        results.append({
                            "status": resp.status_code,
                            "body_hash": hash(resp.text),
                            "text": resp.text[:300],
                        })
                except Exception:
                    pass

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(fire) for _ in range(threads)]
                for f in as_completed(futures, timeout=30):
                    pass

            if len(results) < 3:
                continue

            success_codes = [r["status"] for r in results if r["status"] in (200, 201, 202)]
            # Check for indicators of successful limit overrun:
            # - More than 1 success for a single-use token
            # - "success" appearing in multiple response bodies
            success_keywords = ["success", "applied", "redeemed", "confirmed", "accepted", "created"]
            successful_with_keyword = sum(
                1 for r in results
                if any(kw in r["text"].lower() for kw in success_keywords)
            )

            if len(success_codes) > 1 and successful_with_keyword > 1:
                vulns += 1
                self.add_finding(
                    title=f"Limit-overrun race: {desc}",
                    severity=Severity.HIGH,
                    description=(
                        f"Sending {threads} concurrent requests to {path} resulted in "
                        f"{len(success_codes)} successful responses "
                        f"({successful_with_keyword} with success indicators). "
                        f"This suggests the server's usage limits can be bypassed "
                        f"via race conditions."
                    ),
                    recommendation=(
                        "Use database-level atomic operations (SELECT ... FOR UPDATE). "
                        "Implement idempotency keys. Use distributed locks for critical operations."
                    ),
                    evidence=(
                        f"URL: {test_url}\nConcurrent: {threads}\n"
                        f"Successes: {len(success_codes)}\n"
                        f"Keyword matches: {successful_with_keyword}"
                    ),
                    category="Race Condition", url=test_url, cwe="CWE-362",
                )
                print_finding(Severity.HIGH, f"Limit overrun: {desc}")

        return vulns

    def _test_response_consistency(self, url):
        """Test if GET responses are consistent under load (state corruption)."""
        vulns = 0

        results = []
        for _ in range(5):
            try:
                resp = self.http_client.get(url, timeout=10)
                results.append({"status": resp.status_code, "size": len(resp.text)})
            except Exception:
                pass

        if len(results) < 3:
            return 0

        statuses = set(r["status"] for r in results)
        sizes = [r["size"] for r in results]

        if len(statuses) > 1 and any(s >= 500 for s in statuses):
            vulns += 1
            self.add_finding(
                title="Server instability under concurrent load",
                severity=Severity.MEDIUM,
                description=(
                    f"Sequential identical requests produce different status codes: {statuses}. "
                    f"This may indicate server-side state corruption."
                ),
                recommendation="Investigate server stability and concurrency handling.",
                evidence=f"URL: {url}\nStatuses: {list(statuses)}",
                category="Race Condition", url=url, cwe="CWE-362",
            )

        # Check for size variance indicating non-deterministic behavior
        if sizes and len(sizes) >= 3:
            avg_size = sum(sizes) / len(sizes)
            max_deviation = max(abs(s - avg_size) for s in sizes)
            if avg_size > 0 and max_deviation > avg_size * 0.3:
                vulns += 1
                self.add_finding(
                    title="Non-deterministic responses detected",
                    severity=Severity.LOW,
                    description=(
                        f"Response sizes vary significantly for identical GET requests: "
                        f"{sizes}. This may indicate shared mutable state."
                    ),
                    recommendation="Ensure GET handlers are stateless and deterministic.",
                    evidence=f"URL: {url}\nSizes: {sizes}\nDeviation: {max_deviation:.0f}B",
                    category="Race Condition", url=url, cwe="CWE-362",
                )

        return vulns

    def _test_token_race(self, url):
        """
        Test time-sensitive token races: Send concurrent password-reset/OTP requests
        and check if multiple identical tokens are generated (insufficient entropy).
        """
        vulns = 0

        for path in TOKEN_ENDPOINTS:
            test_url = urljoin(url, path)

            # Check if endpoint exists
            try:
                probe = self.http_client.get(test_url, allow_redirects=False, timeout=3)
                if probe.status_code == 404:
                    continue
            except Exception:
                continue

            # Send concurrent token generation requests
            results = []
            lock = threading.Lock()
            threads = 5

            def fire():
                try:
                    resp = self.http_client.post(
                        test_url,
                        data={"email": "test@example.com"},
                        timeout=10,
                    )
                    with lock:
                        results.append({
                            "status": resp.status_code,
                            "body": resp.text[:500],
                            "headers": dict(resp.headers),
                        })
                except Exception:
                    pass

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(fire) for _ in range(threads)]
                for f in as_completed(futures, timeout=20):
                    pass

            if len(results) < 2:
                continue

            # Check for identical responses (same token generated for concurrent requests)
            body_hashes = [hash(r["body"]) for r in results]
            success_results = [r for r in results if r["status"] in (200, 201, 202)]

            if len(success_results) >= 2:
                unique_bodies = len(set(hash(r["body"]) for r in success_results))
                if unique_bodies < len(success_results):
                    vulns += 1
                    self.add_finding(
                        title=f"Time-sensitive token race at {path}",
                        severity=Severity.HIGH,
                        description=(
                            f"Concurrent requests to {path} produced identical responses, "
                            f"suggesting the same token/OTP was generated for multiple requests. "
                            f"This can allow an attacker to predict or reuse security tokens."
                        ),
                        recommendation=(
                            "Use cryptographically secure random token generation. "
                            "Ensure token entropy is independent of request timing. "
                            "Use rate limiting on token generation endpoints."
                        ),
                        evidence=(
                            f"URL: {test_url}\nConcurrent: {threads}\n"
                            f"Unique responses: {unique_bodies}/{len(success_results)}"
                        ),
                        category="Race Condition", url=test_url, cwe="CWE-362",
                    )
                    print_finding(Severity.HIGH, f"Token race: {path}")

        return vulns
