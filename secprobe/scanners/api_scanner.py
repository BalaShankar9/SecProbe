"""
API Scanner — OpenAPI/Swagger spec import + REST parameter fuzzing.

Capabilities:
  - Parse OpenAPI 3.x and Swagger 2.0 specifications
  - Auto-generate test cases per endpoint
  - Test for BOLA/IDOR, mass assignment, rate limiting, auth bypass
  - Parameter type confusion attacks
  - Response validation (schema compliance)
  - Broken authentication endpoint detection
"""

from __future__ import annotations

import json
import re
import time
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode

import yaml

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


class APIScanner(SmartScanner):
    """Comprehensive API security scanner with OpenAPI support."""

    name = "API Scanner"
    description = "REST API security testing with OpenAPI/Swagger spec support"

    # API-specific injection payloads
    INJECTION_PAYLOADS = {
        "sqli": ["' OR '1'='1", "1 OR 1=1", "admin'--", "1; DROP TABLE users"],
        "nosql": ['{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}'],
        "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        "traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\system32"],
        "ssrf": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"],
        "xss": ["<script>alert(1)</script>", "javascript:alert(1)"],
    }

    # Type confusion payloads
    TYPE_CONFUSION = {
        "integer": ["abc", "1.5", "-1", "0", "999999999999", "null", "true", "[]", "{}"],
        "string": [123, True, None, [], {}, -1, 0.5],
        "boolean": ["yes", "no", "1", "0", "null", "[]", "2"],
        "array": ["not_array", 123, True, None, {}, "[]"],
        "object": ["not_object", 123, True, None, [], "{}"],
    }

    def scan(self):
        """Execute API security scan."""
        target = normalize_url(self.config.target)

        # Try to discover OpenAPI spec
        spec = self._discover_spec(target)

        if spec:
            print_status(f"OpenAPI spec found — {spec.get('info', {}).get('title', 'Unknown')}", "success")
            self._scan_from_spec(target, spec)
        else:
            print_status("No OpenAPI spec found — running endpoint discovery", "info")
            self._scan_common_api_endpoints(target)

        # Always run these regardless of spec
        self._test_authentication_endpoints(target)
        self._test_api_info_disclosure(target)
        self._test_rate_limiting(target)
        self._test_cors_api(target)
        self._test_http_methods(target)

    def _discover_spec(self, target: str) -> Optional[dict]:
        """Try to discover and parse OpenAPI/Swagger specification."""
        spec_paths = [
            "/openapi.json", "/openapi.yaml", "/openapi.yml",
            "/swagger.json", "/swagger.yaml", "/swagger.yml",
            "/api-docs", "/api-docs.json",
            "/v2/api-docs", "/v3/api-docs",
            "/docs/openapi.json", "/api/openapi.json",
            "/.well-known/openapi.json",
            "/api/swagger.json", "/api/v1/swagger.json",
        ]

        for path in spec_paths:
            try:
                url = urljoin(target, path)
                resp = self.http_client.get(url, timeout=self.config.timeout)
                if resp and resp.status_code == 200:
                    content = resp.text
                    # Try JSON first
                    try:
                        spec = json.loads(content)
                        if self._is_valid_spec(spec):
                            self.add_finding(
                                title=f"OpenAPI Specification Exposed at {path}",
                                severity=Severity.LOW,
                                description=f"The API specification is publicly accessible at {url}. "
                                           f"This reveals all API endpoints, parameters, and data models.",
                                recommendation="Restrict access to API documentation in production. "
                                              "Use authentication or IP whitelisting.",
                                evidence=f"Spec URL: {url}\nVersion: {spec.get('openapi', spec.get('swagger', 'unknown'))}",
                                category="API Security",
                                url=url,
                                cwe="CWE-200",
                            )
                            return spec
                    except json.JSONDecodeError:
                        pass
                    # Try YAML
                    try:
                        spec = yaml.safe_load(content)
                        if isinstance(spec, dict) and self._is_valid_spec(spec):
                            return spec
                    except Exception:
                        pass
            except Exception:
                continue
        return None

    def _is_valid_spec(self, spec: dict) -> bool:
        """Check if a dict looks like a valid OpenAPI/Swagger spec."""
        return (
            "openapi" in spec or "swagger" in spec
        ) and "paths" in spec

    def _scan_from_spec(self, target: str, spec: dict):
        """Generate and execute tests from OpenAPI specification."""
        base_url = target
        # Try to get server URL from spec
        if "servers" in spec:
            server_url = spec["servers"][0].get("url", "")
            if server_url.startswith("http"):
                base_url = server_url.rstrip("/")
            elif server_url.startswith("/"):
                base_url = target + server_url.rstrip("/")

        paths = spec.get("paths", {})
        total_endpoints = sum(len(methods) for methods in paths.values())
        print_status(f"Testing {total_endpoints} endpoints from spec", "info")

        for path, methods in paths.items():
            for method, operation in methods.items():
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    self._test_endpoint(base_url, path, method.upper(), operation)

    def _test_endpoint(self, base_url: str, path: str, method: str, operation: dict):
        """Test a single API endpoint from spec."""
        # Build URL with path parameters
        test_path = path
        parameters = operation.get("parameters", [])

        for param in parameters:
            if param.get("in") == "path":
                name = param.get("name", "")
                test_path = test_path.replace(f"{{{name}}}", "1")

        url = base_url + test_path

        # Test 1: BOLA/IDOR — try accessing resources with different IDs
        if re.search(r'/\d+$|/\{[^}]+\}', path):
            self._test_bola(url, method, path)

        # Test 2: Parameter injection
        for param in parameters:
            if param.get("in") in ("query", "body", "formData"):
                self._test_parameter_injection(url, method, param)

        # Test 3: Type confusion
        for param in parameters:
            param_type = param.get("schema", {}).get("type", "string")
            self._test_type_confusion(url, method, param, param_type)

        # Test 4: Missing authentication
        if operation.get("security") is not None or "auth" in str(operation).lower():
            self._test_auth_bypass(url, method)

        # Test 5: Request body injection
        request_body = operation.get("requestBody", {})
        if request_body:
            self._test_request_body(url, method, request_body)

    def _test_bola(self, url: str, method: str, path: str):
        """Test for Broken Object-Level Authorization (BOLA/IDOR)."""
        # Try accessing sequential IDs
        test_ids = ["1", "2", "0", "-1", "999999", "admin"]
        responses = []

        for test_id in test_ids[:3]:
            test_url = re.sub(r'/\d+$', f'/{test_id}', url)
            try:
                resp = self.http_client.request(method.lower(), test_url, timeout=self.config.timeout)
                if resp and resp.status_code == 200:
                    responses.append((test_id, resp))
            except Exception:
                continue

        # If multiple different IDs return 200, potential BOLA
        if len(responses) >= 2:
            # Check if responses are different (different resources)
            bodies = set(r[1].text[:200] for r in responses)
            if len(bodies) > 1:
                self.add_finding(
                    title=f"Potential BOLA/IDOR on {path}",
                    severity=Severity.HIGH,
                    description=f"Multiple resource IDs return 200 OK with different content on {path}. "
                               f"This may indicate Broken Object-Level Authorization.",
                    recommendation="Implement proper authorization checks for every resource access. "
                                  "Verify the requesting user has permission to access the specific resource.",
                    evidence=f"Method: {method}\nIDs tested: {', '.join(r[0] for r in responses)}\n"
                            f"All returned HTTP 200 with different content",
                    category="API Security",
                    url=url,
                    cwe="CWE-639",
                )

    def _test_parameter_injection(self, url: str, method: str, param: dict):
        """Test API parameter for injection vulnerabilities."""
        param_name = param.get("name", "")

        for attack_type, payloads in self.INJECTION_PAYLOADS.items():
            for payload in payloads[:2]:  # Limit payloads per type
                try:
                    if method == "GET":
                        test_url = f"{url}?{param_name}={payload}"
                        resp = self.http_client.get(test_url, timeout=self.config.timeout)
                    else:
                        data = {param_name: payload}
                        resp = self.http_client.request(
                            method.lower(), url,
                            json=data,
                            timeout=self.config.timeout,
                        )

                    if resp and self._check_injection_response(resp, attack_type, payload):
                        severity = Severity.HIGH if attack_type in ("sqli", "nosql") else Severity.MEDIUM
                        self.add_finding(
                            title=f"Potential {attack_type.upper()} in API parameter '{param_name}'",
                            severity=severity,
                            description=f"The API parameter '{param_name}' on {url} appears vulnerable "
                                       f"to {attack_type} injection.",
                            recommendation=f"Validate and sanitize the '{param_name}' parameter. "
                                          f"Use parameterized queries and input validation.",
                            evidence=f"Method: {method}\nParameter: {param_name}\n"
                                    f"Payload: {payload}\nStatus: {resp.status_code}",
                            category="API Security",
                            url=url,
                            cwe=self._attack_to_cwe(attack_type),
                        )
                        break  # Found vuln, skip remaining payloads for this type
                except Exception:
                    continue

    def _test_type_confusion(self, url: str, method: str, param: dict, expected_type: str):
        """Test parameter type confusion."""
        param_name = param.get("name", "")
        payloads = self.TYPE_CONFUSION.get(expected_type, [])

        for payload in payloads[:3]:
            try:
                if method == "GET":
                    test_url = f"{url}?{param_name}={payload}"
                    resp = self.http_client.get(test_url, timeout=self.config.timeout)
                else:
                    resp = self.http_client.request(
                        method.lower(), url,
                        json={param_name: payload},
                        timeout=self.config.timeout,
                    )

                if resp and resp.status_code == 500:
                    self.add_finding(
                        title=f"Type Confusion in '{param_name}' (expected {expected_type})",
                        severity=Severity.MEDIUM,
                        description=f"Sending unexpected type to '{param_name}' (expected {expected_type}) "
                                   f"causes a 500 error, indicating missing input validation.",
                        recommendation="Implement strict type validation for all API parameters. "
                                      "Return 400 Bad Request for invalid types instead of 500.",
                        evidence=f"Parameter: {param_name}\nExpected: {expected_type}\n"
                                f"Sent: {payload} (type: {type(payload).__name__})\nStatus: 500",
                        category="API Security",
                        url=url,
                        cwe="CWE-20",
                    )
                    break
            except Exception:
                continue

    def _test_auth_bypass(self, url: str, method: str):
        """Test if authenticated endpoints are accessible without auth."""
        try:
            # Make request without auth headers
            headers = {"Authorization": "", "Cookie": ""}
            resp = self.http_client.request(
                method.lower(), url,
                headers=headers,
                timeout=self.config.timeout,
            )
            if resp and resp.status_code == 200:
                self.add_finding(
                    title=f"Authentication Bypass on {method} {urlparse(url).path}",
                    severity=Severity.CRITICAL,
                    description=f"The endpoint {url} is accessible without authentication "
                               f"despite being marked as requiring auth in the API spec.",
                    recommendation="Enforce authentication on all protected endpoints. "
                                  "Implement proper middleware/guards for auth verification.",
                    evidence=f"Method: {method}\nURL: {url}\nStatus: 200 (no auth)",
                    category="API Security",
                    url=url,
                    cwe="CWE-306",
                )
        except Exception:
            pass

    def _test_request_body(self, url: str, method: str, request_body: dict):
        """Test request body for mass assignment and injection."""
        content = request_body.get("content", {})
        json_schema = content.get("application/json", {}).get("schema", {})

        if json_schema.get("properties"):
            # Test mass assignment — add extra fields
            base_data = {}
            for prop, schema in json_schema["properties"].items():
                base_data[prop] = self._generate_test_value(schema)

            # Add admin/privileged fields
            privilege_fields = {
                "role": "admin", "is_admin": True, "admin": True,
                "privilege": "root", "permissions": ["*"],
                "verified": True, "active": True, "approved": True,
            }

            for field_name, field_value in privilege_fields.items():
                if field_name not in base_data:
                    test_data = {**base_data, field_name: field_value}
                    try:
                        resp = self.http_client.request(
                            method.lower(), url,
                            json=test_data,
                            timeout=self.config.timeout,
                        )
                        if resp and resp.status_code in (200, 201):
                            # Check if the field was accepted
                            try:
                                resp_data = resp.json()
                                if field_name in str(resp_data):
                                    self.add_finding(
                                        title=f"Potential Mass Assignment — '{field_name}' accepted",
                                        severity=Severity.HIGH,
                                        description=f"The API endpoint {url} accepts the undocumented field '{field_name}' "
                                                   f"which could allow privilege escalation.",
                                        recommendation="Implement strict input validation. Use allowlists for "
                                                      "accepted fields. Never bind request data directly to models.",
                                        evidence=f"Field: {field_name}\nValue: {field_value}\nStatus: {resp.status_code}",
                                        category="API Security",
                                        url=url,
                                        cwe="CWE-915",
                                    )
                                    break
                            except Exception:
                                pass
                    except Exception:
                        continue

    def _test_authentication_endpoints(self, target: str):
        """Test common authentication-related API endpoints."""
        auth_paths = [
            "/api/login", "/api/auth/login", "/api/v1/login",
            "/api/register", "/api/auth/register", "/api/v1/register",
            "/api/password/reset", "/api/auth/forgot-password",
            "/api/token", "/api/auth/token", "/oauth/token",
            "/api/users/me", "/api/user/profile",
        ]

        for path in auth_paths:
            url = urljoin(target, path)
            try:
                resp = self.http_client.get(url, timeout=self.config.timeout)
                if resp and resp.status_code in (200, 405, 401):
                    # Endpoint exists
                    if resp.status_code == 200:
                        self.add_finding(
                            title=f"API Auth Endpoint Found: {path}",
                            severity=Severity.INFO,
                            description=f"Authentication endpoint discovered at {url}.",
                            category="API Security",
                            url=url,
                            cwe="CWE-200",
                        )
            except Exception:
                continue

    def _test_api_info_disclosure(self, target: str):
        """Test for API information disclosure."""
        info_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/api/health", "/api/status", "/api/info",
            "/api/version", "/api/debug", "/api/config",
            "/api/env", "/api/metrics", "/api/actuator",
            "/api/graphql", "/graphql",
            "/api/docs", "/api/redoc", "/api/swagger-ui",
        ]

        for path in info_paths:
            url = urljoin(target, path)
            try:
                resp = self.http_client.get(url, timeout=self.config.timeout)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    # Check for sensitive info in response
                    sensitive_patterns = [
                        r'"password"', r'"secret"', r'"api_key"', r'"token"',
                        r'"database"', r'"dsn"', r'"connection_string"',
                        r'"debug"\s*:\s*true', r'"env"\s*:\s*"(dev|staging)"',
                    ]
                    for pattern in sensitive_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self.add_finding(
                                title=f"Sensitive Information in API Response: {path}",
                                severity=Severity.MEDIUM,
                                description=f"The endpoint {url} exposes potentially sensitive information.",
                                recommendation="Remove debug endpoints from production. Restrict API "
                                              "info endpoints with authentication.",
                                evidence=f"URL: {url}\nPattern: {pattern}\nStatus: {resp.status_code}",
                                category="API Security",
                                url=url,
                                cwe="CWE-200",
                            )
                            break
            except Exception:
                continue

    def _test_rate_limiting(self, target: str):
        """Test if API has rate limiting."""
        test_url = urljoin(target, "/api/v1/test")
        # Try a burst of requests
        success_count = 0
        for _ in range(20):
            try:
                resp = self.http_client.get(target, timeout=5)
                if resp and resp.status_code == 200:
                    success_count += 1
                elif resp and resp.status_code == 429:
                    return  # Rate limiting is working
            except Exception:
                break

        if success_count >= 18:
            self.add_finding(
                title="No Rate Limiting Detected on API",
                severity=Severity.MEDIUM,
                description="The API does not appear to implement rate limiting. "
                           "20 rapid requests all returned 200 OK.",
                recommendation="Implement rate limiting (e.g., 100 requests/minute per IP). "
                              "Use HTTP 429 Too Many Requests responses. Consider API key-based limits.",
                evidence=f"20 rapid requests → {success_count} successful (no 429 responses)",
                category="API Security",
                url=target,
                cwe="CWE-770",
            )

    def _test_cors_api(self, target: str):
        """Test CORS configuration on API endpoints."""
        try:
            headers = {"Origin": "https://evil.com"}
            resp = self.http_client.get(target, headers=headers, timeout=self.config.timeout)
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*" and acac.lower() == "true":
                    self.add_finding(
                        title="Dangerous CORS Configuration on API",
                        severity=Severity.HIGH,
                        description="The API allows any origin with credentials, enabling "
                                   "cross-origin data theft.",
                        recommendation="Configure CORS with specific allowed origins. "
                                      "Never use wildcard (*) with credentials.",
                        evidence=f"Access-Control-Allow-Origin: {acao}\n"
                                f"Access-Control-Allow-Credentials: {acac}",
                        category="API Security",
                        url=target,
                        cwe="CWE-346",
                    )
                elif "evil.com" in acao:
                    self.add_finding(
                        title="CORS Origin Reflection on API",
                        severity=Severity.HIGH,
                        description="The API reflects the Origin header in Access-Control-Allow-Origin.",
                        recommendation="Use a whitelist of allowed origins instead of reflecting the Origin.",
                        evidence=f"Sent Origin: https://evil.com\nReflected: {acao}",
                        category="API Security",
                        url=target,
                        cwe="CWE-346",
                    )
        except Exception:
            pass

    def _test_http_methods(self, target: str):
        """Test for dangerous HTTP methods."""
        dangerous_methods = ["PUT", "DELETE", "PATCH", "TRACE"]
        for method in dangerous_methods:
            try:
                resp = self.http_client.request(method.lower(), target, timeout=self.config.timeout)
                if resp and resp.status_code not in (404, 405, 501):
                    if method == "TRACE" and resp.status_code == 200:
                        self.add_finding(
                            title=f"HTTP TRACE Method Enabled",
                            severity=Severity.MEDIUM,
                            description="HTTP TRACE method is enabled, which can be used for XST attacks.",
                            recommendation="Disable TRACE method on the web server.",
                            evidence=f"TRACE {target} → {resp.status_code}",
                            category="API Security",
                            url=target,
                            cwe="CWE-16",
                        )
            except Exception:
                continue

    # ── Helpers ──────────────────────────────────────────────────────

    def _check_injection_response(self, resp, attack_type: str, payload: str) -> bool:
        """Check if response indicates injection success."""
        if resp.status_code == 500:
            return True

        text = resp.text.lower()
        indicators = {
            "sqli": ["sql", "syntax error", "mysql", "postgresql", "oracle", "sqlite", "odbc"],
            "nosql": ["mongodb", "bson", "mongoclient", "aggregation"],
            "ssti": ["49", "7777777", "template", "jinja2", "twig"],
            "traversal": ["root:", "/bin/", "\\windows\\"],
            "ssrf": ["127.0.0.1", "localhost", "internal"],
            "xss": ["<script>alert(1)</script>"],
        }

        for indicator in indicators.get(attack_type, []):
            if indicator in text:
                return True
        return False

    def _attack_to_cwe(self, attack_type: str) -> str:
        """Map attack type to CWE ID."""
        mapping = {
            "sqli": "CWE-89",
            "nosql": "CWE-943",
            "ssti": "CWE-917",
            "traversal": "CWE-22",
            "ssrf": "CWE-918",
            "xss": "CWE-79",
        }
        return mapping.get(attack_type, "CWE-74")

    def _generate_test_value(self, schema: dict) -> any:
        """Generate a test value based on JSON schema type."""
        schema_type = schema.get("type", "string")
        if schema_type == "string":
            return "test"
        elif schema_type == "integer":
            return 1
        elif schema_type == "number":
            return 1.0
        elif schema_type == "boolean":
            return True
        elif schema_type == "array":
            return []
        elif schema_type == "object":
            return {}
        return "test"

    def _scan_common_api_endpoints(self, target: str):
        """Scan common API endpoint patterns when no spec is available."""
        common_patterns = [
            "/api/users", "/api/v1/users", "/api/v2/users",
            "/api/admin", "/api/v1/admin",
            "/api/settings", "/api/config",
            "/api/upload", "/api/files",
            "/api/search", "/api/query",
        ]

        for path in common_patterns:
            url = urljoin(target, path)
            try:
                resp = self.http_client.get(url, timeout=self.config.timeout)
                if resp and resp.status_code == 200:
                    print_status(f"API endpoint found: {path} ({resp.status_code})", "info")
            except Exception:
                continue
