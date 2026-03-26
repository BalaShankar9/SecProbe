"""OWASP Juice Shop challenge mapping for benchmark tracking."""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Challenge:
    name: str
    category: str       # sqli, xss, auth, access_control, injection, misconfiguration, etc.
    difficulty: int      # 1-6 stars
    description: str = ""
    url_patterns: list[str] = field(default_factory=list)  # URL patterns that indicate detection
    finding_keywords: list[str] = field(default_factory=list)  # Keywords in finding titles


# At minimum include these 50+ challenges (real Juice Shop challenges):
CHALLENGES = [
    # SQL Injection
    Challenge("Login Admin", "sqli", 2, "Log in as admin via SQLi", ["/rest/user/login"], ["sql injection", "sqli"]),
    Challenge("Login Bender", "sqli", 3, "Log in as Bender via SQLi", ["/rest/user/login"], ["sql injection"]),
    Challenge("Login Jim", "sqli", 3, "Log in as Jim via SQLi", ["/rest/user/login"], ["sql injection"]),
    Challenge("Christmas Special", "sqli", 4, "Order Christmas special via SQLi", ["/rest/products/search", "/api/Products"], ["sql injection", "union"]),
    Challenge("Database Schema", "sqli", 5, "Extract DB schema via SQLi", ["/rest/products/search"], ["sql injection", "union"]),
    Challenge("User Credentials", "sqli", 6, "Extract user credentials via SQLi", ["/rest/products/search"], ["sql injection", "union"]),

    # XSS
    Challenge("DOM XSS", "xss", 1, "Perform DOM XSS via search", ["/search"], ["xss", "cross-site scripting"]),
    Challenge("Bonus Payload", "xss", 1, "Use bonus payload for XSS", [], ["xss"]),
    Challenge("Reflected XSS", "xss", 2, "Perform reflected XSS", ["/track"], ["xss", "reflected"]),
    Challenge("Stored XSS", "xss", 4, "Perform stored XSS via API", ["/api/Products"], ["xss", "stored"]),
    Challenge("API-only XSS", "xss", 3, "XSS via API", ["/api/"], ["xss"]),

    # Authentication / Session
    Challenge("Password Strength", "auth", 2, "Log in with weak password", ["/rest/user/login"], ["weak password", "brute force", "authentication"]),
    Challenge("Forged Feedback", "auth", 3, "Post feedback as another user", ["/api/Feedbacks"], ["auth", "idor"]),
    Challenge("CSRF", "auth", 3, "Change password via CSRF", ["/rest/user/change-password"], ["csrf"]),
    Challenge("JWT Issues", "auth", 5, "Forge JWT token", [], ["jwt", "token"]),

    # Access Control
    Challenge("Admin Section", "access_control", 2, "Access admin page", ["/administration"], ["access control", "authorization"]),
    Challenge("Five-Star Feedback", "access_control", 2, "Delete 5-star feedback", ["/api/Feedbacks"], ["access control", "idor"]),
    Challenge("View Basket", "access_control", 2, "View another user basket", ["/rest/basket"], ["idor", "bola", "access control"]),
    Challenge("Forged Review", "access_control", 3, "Post review as another user", ["/rest/products/reviews"], ["idor"]),
    Challenge("Manipulate Basket", "access_control", 3, "Put item in another basket", ["/api/BasketItems"], ["idor", "mass assignment"]),

    # Security Misconfiguration
    Challenge("Error Handling", "misconfiguration", 1, "Provoke error with stack trace", [], ["error", "stack trace", "information disclosure"]),
    Challenge("Exposed Metrics", "misconfiguration", 1, "Find exposed Prometheus metrics", ["/metrics"], ["exposed", "metrics"]),
    Challenge("Missing Encoding", "misconfiguration", 1, "Missing encoding", [], ["encoding"]),
    Challenge("Outdated Allowlist", "misconfiguration", 1, "Redirect via allowlist bypass", [], ["redirect", "allowlist"]),
    Challenge("Deprecated Interface", "misconfiguration", 2, "Use deprecated B2B interface", ["/file-upload"], ["upload", "deprecated"]),
    Challenge("Login Support Team", "misconfiguration", 6, "Login as support team", [], ["authentication"]),

    # Sensitive Data Exposure
    Challenge("Confidential Document", "sensitive_data", 1, "Access confidential document", ["/ftp"], ["directory", "sensitive", "exposure"]),
    Challenge("Email Leak", "sensitive_data", 1, "Leak email via logs", ["/support/logs"], ["email", "log", "sensitive"]),
    Challenge("Exposed FTP", "sensitive_data", 2, "Access FTP directory", ["/ftp"], ["directory listing", "ftp"]),
    Challenge("Forgotten Developer Backup", "sensitive_data", 4, "Find developer backup", ["/ftp"], ["backup", "sensitive"]),

    # Injection (non-SQL)
    Challenge("NoSQL Injection", "injection", 4, "NoSQL injection in review", ["/rest/products/reviews"], ["nosql", "injection"]),
    Challenge("Server-side XSS Protection", "injection", 4, "Bypass sanitization", [], ["xss", "bypass", "sanitization"]),

    # Broken Anti Automation
    Challenge("CAPTCHA Bypass", "anti_automation", 3, "Bypass CAPTCHA", ["/api/Feedbacks"], ["captcha", "bypass"]),
    Challenge("Extra Language", "anti_automation", 5, "Retrieve language file", ["/i18n"], ["directory", "traversal"]),

    # Cryptographic Issues
    Challenge("Weird Crypto", "crypto", 2, "Inform about weak crypto", ["/api/Complaints"], ["crypto", "weak", "md5", "sha1"]),
    Challenge("Nested Easter Egg", "crypto", 4, "Find nested easter egg", [], ["crypto", "base64"]),

    # CORS/Headers
    Challenge("Missing Security Headers", "headers", 1, "Identify missing headers", [], ["header", "hsts", "csp", "x-frame"]),
    Challenge("CORS Misconfiguration", "cors", 2, "Exploit CORS", [], ["cors", "origin"]),

    # File Upload
    Challenge("Upload Size", "upload", 3, "Upload file >100kb", ["/file-upload"], ["upload", "size"]),
    Challenge("Upload Type", "upload", 3, "Upload non-allowed file type", ["/file-upload"], ["upload", "type", "extension"]),

    # Redirect
    Challenge("Allowlist Bypass", "redirect", 4, "Redirect via URL manipulation", [], ["redirect", "open redirect"]),

    # Privacy
    Challenge("Privacy Policy", "privacy", 1, "Read privacy policy", ["/privacy-security/privacy-policy"], ["privacy"]),
    Challenge("Data Export", "privacy", 3, "Request data export", ["/rest/data-export"], ["gdpr", "data export"]),
]


class JuiceShopBenchmark:
    """Map SecProbe findings to Juice Shop challenges."""

    def get_challenges(self) -> list[dict]:
        return [{"name": c.name, "category": c.category, "difficulty": c.difficulty, "description": c.description} for c in CHALLENGES]

    def match_finding(self, finding: dict) -> list[Challenge]:
        """Match a SecProbe finding to Juice Shop challenges."""
        matches = []
        title = (finding.get("title", "") or "").lower()
        category = (finding.get("category", "") or "").lower()
        url = (finding.get("url", "") or "").lower()

        for challenge in CHALLENGES:
            # Check keyword match in title or category
            keyword_match = any(kw in title or kw in category for kw in challenge.finding_keywords)
            # Check URL pattern match
            url_match = any(pattern.lower() in url for pattern in challenge.url_patterns) if challenge.url_patterns else False

            if keyword_match or url_match:
                matches.append(challenge)

        return matches

    def run_benchmark(self, findings: list[dict]) -> dict:
        """Run full benchmark against a list of findings."""
        total = len(CHALLENGES)
        matched_challenges: set[str] = set()
        unmatched_findings: list[dict] = []

        for finding in findings:
            matches = self.match_finding(finding)
            if matches:
                for m in matches:
                    matched_challenges.add(m.name)
            else:
                unmatched_findings.append(finding)

        detected = len(matched_challenges)
        return {
            "total_challenges": total,
            "detected": detected,
            "detection_rate": detected / total if total > 0 else 0.0,
            "matched_challenges": sorted(matched_challenges),
            "unmatched_findings": len(unmatched_findings),
            "total_findings": len(findings),
        }
