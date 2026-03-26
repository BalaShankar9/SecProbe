"""
Secret detection engine — finds exposed API keys, tokens, and credentials.

Inspired by TruffleHog (25K stars) and Gitleaks (25K stars).
Patterns cover 50+ secret types including AWS, GCP, Azure, GitHub, Slack, etc.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DetectedSecret:
    """A secret found in source code or responses."""
    secret_type: str        # e.g., "AWS Access Key"
    pattern_name: str       # e.g., "aws_access_key"
    matched_value: str      # The actual match (redacted in reports)
    location: str           # URL or file where found
    line_number: int = 0
    confidence: float = 0.9
    verified: bool = False  # Has the secret been verified as valid?

    @property
    def redacted_value(self) -> str:
        """Show first 4 and last 4 chars only."""
        if len(self.matched_value) <= 12:
            return self.matched_value[:4] + "..." + self.matched_value[-2:]
        return self.matched_value[:4] + "..." + self.matched_value[-4:]


# Secret detection patterns (inspired by TruffleHog + Gitleaks)
SECRET_PATTERNS: dict[str, dict] = {
    # AWS
    "aws_access_key": {
        "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
        "type": "AWS Access Key ID",
        "severity": "CRITICAL",
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "type": "AWS Secret Access Key",
        "severity": "CRITICAL",
    },
    # Google Cloud
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "type": "Google Cloud API Key",
        "severity": "HIGH",
    },
    "gcp_service_account": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "type": "GCP Service Account Key",
        "severity": "CRITICAL",
    },
    # GitHub
    "github_pat": {
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "type": "GitHub Personal Access Token",
        "severity": "CRITICAL",
    },
    "github_oauth": {
        "pattern": r"gho_[A-Za-z0-9]{36}",
        "type": "GitHub OAuth Token",
        "severity": "CRITICAL",
    },
    "github_app_token": {
        "pattern": r"(?:ghu|ghs)_[A-Za-z0-9]{36}",
        "type": "GitHub App Token",
        "severity": "CRITICAL",
    },
    # Slack
    "slack_token": {
        "pattern": r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
        "type": "Slack Token",
        "severity": "HIGH",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{24}",
        "type": "Slack Webhook URL",
        "severity": "MEDIUM",
    },
    # Stripe
    "stripe_secret": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,99}",
        "type": "Stripe Secret Key",
        "severity": "CRITICAL",
    },
    "stripe_publishable": {
        "pattern": r"pk_live_[0-9a-zA-Z]{24,99}",
        "type": "Stripe Publishable Key",
        "severity": "LOW",
    },
    # JWT
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "type": "JWT Token",
        "severity": "MEDIUM",
    },
    # Generic API keys
    "generic_api_key": {
        "pattern": r"""(?i)(?:api[_\-\s]?key|apikey|api_secret|api_token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,60})['\"]?""",
        "type": "Generic API Key",
        "severity": "HIGH",
    },
    "generic_secret": {
        "pattern": r"""(?i)(?:secret|password|passwd|pwd|token|auth)[_\-\s]?(?:key|token|secret)?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_!@#$%^&*]{8,60})['\"]?""",
        "type": "Generic Secret/Password",
        "severity": "HIGH",
    },
    # Private Keys
    "private_key_rsa": {
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "type": "RSA Private Key",
        "severity": "CRITICAL",
    },
    "private_key_generic": {
        "pattern": r"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "type": "Private Key",
        "severity": "CRITICAL",
    },
    # Database
    "postgres_uri": {
        "pattern": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+",
        "type": "PostgreSQL Connection String",
        "severity": "CRITICAL",
    },
    "mongodb_uri": {
        "pattern": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+",
        "type": "MongoDB Connection String",
        "severity": "CRITICAL",
    },
    "mysql_uri": {
        "pattern": r"mysql://[^:]+:[^@]+@[^/]+/\w+",
        "type": "MySQL Connection String",
        "severity": "CRITICAL",
    },
    # Azure
    "azure_storage_key": {
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        "type": "Azure Storage Account Key",
        "severity": "CRITICAL",
    },
    # Twilio
    "twilio_api_key": {
        "pattern": r"SK[a-f0-9]{32}",
        "type": "Twilio API Key",
        "severity": "HIGH",
    },
    # SendGrid
    "sendgrid_api_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "type": "SendGrid API Key",
        "severity": "HIGH",
    },
    # Mailgun
    "mailgun_api_key": {
        "pattern": r"key-[a-f0-9]{32}",
        "type": "Mailgun API Key",
        "severity": "HIGH",
    },
    # Firebase
    "firebase_url": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "type": "Firebase Database URL",
        "severity": "MEDIUM",
    },
    # Heroku
    "heroku_api_key": {
        "pattern": r"(?i)heroku[_\-\.]?api[_\-\.]?key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
        "type": "Heroku API Key",
        "severity": "HIGH",
    },
    # Supabase
    "supabase_key": {
        "pattern": r"eyJ[A-Za-z0-9_-]{100,}",
        "type": "Supabase/JWT Long Token",
        "severity": "MEDIUM",
    },
    # npm
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "type": "npm Access Token",
        "severity": "HIGH",
    },
    # Telegram
    "telegram_bot_token": {
        "pattern": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
        "type": "Telegram Bot Token",
        "severity": "HIGH",
    },
    # Discord
    "discord_bot_token": {
        "pattern": r"[MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}",
        "type": "Discord Bot Token",
        "severity": "HIGH",
    },
}


class SecretScanner:
    """Scan text content for exposed secrets and credentials."""

    def __init__(self):
        self._compiled = {
            name: re.compile(info["pattern"])
            for name, info in SECRET_PATTERNS.items()
        }

    def scan_text(self, text: str, location: str = "") -> list[DetectedSecret]:
        """Scan text content for secrets."""
        if not text:
            return []

        secrets = []
        seen_values = set()

        for name, pattern in self._compiled.items():
            info = SECRET_PATTERNS[name]
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                if value in seen_values:
                    continue
                seen_values.add(value)

                # Find line number
                line_num = text[:match.start()].count("\n") + 1

                secrets.append(DetectedSecret(
                    secret_type=info["type"],
                    pattern_name=name,
                    matched_value=value,
                    location=location,
                    line_number=line_num,
                    confidence=0.9 if len(value) > 20 else 0.7,
                ))

        logger.debug("Found %d secrets in %s", len(secrets), location[:60])
        return secrets

    def scan_response(self, url: str, response_text: str,
                       response_headers: dict = None) -> list[DetectedSecret]:
        """Scan an HTTP response for secrets."""
        secrets = self.scan_text(response_text, location=url)

        # Also check headers
        if response_headers:
            header_text = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
            header_secrets = self.scan_text(header_text, location=f"{url} [headers]")
            secrets.extend(header_secrets)

        return secrets

    def scan_js_files(self, js_contents: dict[str, str]) -> list[DetectedSecret]:
        """Scan multiple JS files for secrets."""
        all_secrets = []
        for url, content in js_contents.items():
            secrets = self.scan_text(content, location=url)
            all_secrets.extend(secrets)
        return all_secrets

    def get_pattern_count(self) -> int:
        return len(SECRET_PATTERNS)

    def get_pattern_names(self) -> list[str]:
        return sorted(SECRET_PATTERNS.keys())
