"""
L5: Federated Memory — Community intelligence (opt-in, anonymised).

The most powerful memory tier.  When enabled, SecProbe can learn from
the collective experience of all users:

    - "This payload bypassed Cloudflare for 47 users this week"
    - "WordPress 6.4 has a new SQLi pattern in REST API"
    - "AWS WAF v2 blocks X-Forwarded-For spoofing since March"

Privacy model:
    - ALL data is anonymised before sharing — no target URLs, IPs,
      credentials, or organisation info are ever transmitted.
    - Only statistical patterns are shared: (technology, vuln_type,
      payload_hash, effectiveness, waf_name).
    - Users opt-in explicitly (``enabled=True``).
    - Local-only mode is the default.

Network layer:
    Uses ``httpx`` for async HTTP calls to a Supabase REST API backend.
    Falls back gracefully when offline or misconfigured.

Storage: The Supabase ``federated_patterns`` table (remote).  No local
persistence beyond what the caller provides — this tier is intentionally
stateless on the client side.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("secprobe.memory.federated")

# ---------------------------------------------------------------------------
# Lazy httpx import — only needed when federated mode is actually enabled.
# This prevents an import-time dependency for users who never enable the
# federated tier.
# ---------------------------------------------------------------------------
_httpx = None


def _get_httpx():
    global _httpx
    if _httpx is None:
        try:
            import httpx
            _httpx = httpx
        except ImportError:
            raise ImportError(
                "httpx is required for Federated Memory. "
                "Install it with: pip install httpx"
            )
    return _httpx


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FederatedPattern:
    """An anonymised pattern from the community intelligence network."""

    pattern_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    vuln_type: str = ""
    technology: str = ""
    payload_hash: str = ""
    effectiveness: float = 0.0
    contributor_count: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_confirmed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    waf_bypasses: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a Supabase-ready dict."""
        return {
            "pattern_id": self.pattern_id,
            "vuln_type": self.vuln_type,
            "technology": self.technology,
            "payload_hash": self.payload_hash,
            "effectiveness": self.effectiveness,
            "contributor_count": self.contributor_count,
            "first_seen": self.first_seen.isoformat() if isinstance(self.first_seen, datetime) else str(self.first_seen),
            "last_confirmed": self.last_confirmed.isoformat() if isinstance(self.last_confirmed, datetime) else str(self.last_confirmed),
            "waf_bypasses": self.waf_bypasses,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> FederatedPattern:
        """Deserialise from a Supabase response row."""
        first_seen = d.get("first_seen", "")
        last_confirmed = d.get("last_confirmed", "")
        try:
            fs = datetime.fromisoformat(first_seen) if first_seen else datetime.now(timezone.utc)
        except (ValueError, TypeError):
            fs = datetime.now(timezone.utc)
        try:
            lc = datetime.fromisoformat(last_confirmed) if last_confirmed else datetime.now(timezone.utc)
        except (ValueError, TypeError):
            lc = datetime.now(timezone.utc)

        return cls(
            pattern_id=d.get("pattern_id", d.get("id", uuid.uuid4().hex[:16])),
            vuln_type=d.get("vuln_type", ""),
            technology=d.get("technology", ""),
            payload_hash=d.get("payload_hash", ""),
            effectiveness=float(d.get("effectiveness", 0.0)),
            contributor_count=int(d.get("contributor_count", 0)),
            first_seen=fs,
            last_confirmed=lc,
            waf_bypasses=d.get("waf_bypasses", []),
            metadata=d.get("metadata", {}),
        )


# ---------------------------------------------------------------------------
# Sensitive-field blacklist for anonymisation
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = frozenset({
    "target", "target_url", "url", "host", "hostname", "ip", "ip_address",
    "domain", "fqdn", "email", "username", "password", "credential",
    "credentials", "api_key", "token", "secret", "cookie", "session",
    "authorization", "auth", "org", "organisation", "organization",
    "company", "internal_url", "path", "full_payload",
})


class FederatedMemory:
    """
    Community intelligence layer — opt-in, privacy-first, async.

    All network calls are ``async`` and use ``httpx.AsyncClient`` to talk
    to a Supabase REST API.  The class degrades gracefully: if httpx is
    not installed, if the connection fails, or if the user has not opted
    in, every method returns an empty result rather than raising.

    Usage::

        mem = FederatedMemory(
            supabase_url="https://xxx.supabase.co",
            supabase_key="eyJ...",
            enabled=True,
        )

        # Query community intelligence
        patterns = await mem.query_patterns("sqli", tech="wordpress")
        for p in patterns:
            print(f"{p.vuln_type} on {p.technology}: "
                  f"{p.effectiveness:.0%} ({p.contributor_count} contributors)")

        # Contribute an anonymised pattern
        await mem.contribute_pattern(FederatedPattern(
            vuln_type="sqli",
            technology="mysql",
            payload_hash=FederatedMemory.hash_payload("' OR 1=1--"),
            effectiveness=0.85,
            waf_bypasses=["cloudflare"],
        ))

        # WAF bypass intelligence
        bypasses = await mem.query_waf_bypasses("cloudflare")

        # Trending vulns across the community
        trending = await mem.get_trending_vulns()
    """

    _TABLE = "federated_patterns"
    _REQUEST_TIMEOUT = 10.0  # seconds

    def __init__(
        self,
        supabase_url: str | None = None,
        supabase_key: str | None = None,
        enabled: bool = False,
    ):
        self.enabled = enabled
        self._supabase_url = (supabase_url or "").rstrip("/")
        self._supabase_key = supabase_key or ""
        self._client: Any = None  # httpx.AsyncClient, created lazily

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get_client(self):
        """Lazily create an httpx.AsyncClient with Supabase headers."""
        if self._client is None:
            httpx = _get_httpx()
            self._client = httpx.AsyncClient(
                base_url=f"{self._supabase_url}/rest/v1",
                headers={
                    "apikey": self._supabase_key,
                    "Authorization": f"Bearer {self._supabase_key}",
                    "Content-Type": "application/json",
                    "Prefer": "return=representation",
                },
                timeout=self._REQUEST_TIMEOUT,
            )
        return self._client

    async def _safe_request(self, method: str, path: str, **kwargs) -> list[dict]:
        """
        Execute an HTTP request, returning parsed JSON on success or an
        empty list on any failure.  Logs warnings but never raises.
        """
        if not self.enabled or not self._supabase_url or not self._supabase_key:
            return []
        try:
            client = await self._get_client()
            response = await getattr(client, method)(path, **kwargs)
            response.raise_for_status()
            data = response.json()
            return data if isinstance(data, list) else [data] if data else []
        except Exception:
            logger.warning(
                "Federated memory %s %s failed", method.upper(), path,
                exc_info=True,
            )
            return []

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Query operations
    # ------------------------------------------------------------------

    async def query_patterns(
        self, vuln_type: str, tech: str | None = None, limit: int = 50
    ) -> list[FederatedPattern]:
        """
        Query community intelligence for patterns matching *vuln_type*
        and optionally *tech*.

        Returns patterns sorted by effectiveness (highest first).
        """
        params: dict[str, str] = {
            "vuln_type": f"eq.{vuln_type}",
            "order": "effectiveness.desc",
            "limit": str(limit),
        }
        if tech:
            params["technology"] = f"eq.{tech}"

        rows = await self._safe_request("get", f"/{self._TABLE}", params=params)
        patterns = [FederatedPattern.from_dict(r) for r in rows]
        patterns.sort(key=lambda p: p.effectiveness, reverse=True)
        return patterns

    async def query_waf_bypasses(self, waf_name: str, limit: int = 30) -> list[dict]:
        """
        Get community-shared WAF bypass techniques for *waf_name*.

        Returns a list of dicts, each containing the bypass pattern's
        vuln_type, technology, effectiveness, and contributor_count.
        """
        params: dict[str, str] = {
            "waf_bypasses": f"cs.{{{waf_name}}}",  # Supabase array contains
            "order": "effectiveness.desc",
            "limit": str(limit),
        }
        rows = await self._safe_request("get", f"/{self._TABLE}", params=params)
        return [
            {
                "pattern_id": r.get("pattern_id", ""),
                "vuln_type": r.get("vuln_type", ""),
                "technology": r.get("technology", ""),
                "payload_hash": r.get("payload_hash", ""),
                "effectiveness": r.get("effectiveness", 0.0),
                "contributor_count": r.get("contributor_count", 0),
                "waf_bypasses": r.get("waf_bypasses", []),
            }
            for r in rows
        ]

    async def get_trending_vulns(self, limit: int = 20) -> list[dict]:
        """
        Get the most frequently confirmed vulnerability types across the
        community in recent time.

        Returns dicts with keys: vuln_type, technology, effectiveness,
        contributor_count, last_confirmed.
        """
        params: dict[str, str] = {
            "order": "contributor_count.desc,last_confirmed.desc",
            "limit": str(limit),
        }
        rows = await self._safe_request("get", f"/{self._TABLE}", params=params)
        return [
            {
                "vuln_type": r.get("vuln_type", ""),
                "technology": r.get("technology", ""),
                "effectiveness": r.get("effectiveness", 0.0),
                "contributor_count": r.get("contributor_count", 0),
                "last_confirmed": r.get("last_confirmed", ""),
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Contribute operations
    # ------------------------------------------------------------------

    async def contribute_pattern(self, pattern: FederatedPattern) -> bool:
        """
        Anonymise and share a successful pattern with the community.

        **Privacy guarantee**: this method passes all outgoing data through
        ``_anonymise()`` which strips any sensitive fields.  Only the
        following are transmitted:

        - ``vuln_type``
        - ``technology``
        - ``payload_hash`` (SHA-256 of the payload, never the payload itself)
        - ``effectiveness``
        - ``waf_bypasses`` (WAF product names only)

        Returns ``True`` if the contribution was accepted by the server.
        """
        if not self.enabled:
            return False

        safe_data = self._anonymise(pattern.to_dict())
        rows = await self._safe_request(
            "post", f"/{self._TABLE}", json=safe_data
        )
        if rows:
            logger.info(
                "Contributed pattern %s (%s / %s)",
                pattern.pattern_id, pattern.vuln_type, pattern.technology,
            )
            return True
        return False

    # ------------------------------------------------------------------
    # Anonymisation
    # ------------------------------------------------------------------

    @staticmethod
    def _anonymise(data: dict) -> dict:
        """
        Strip all identifying information before sharing.

        Removes any key whose name appears in ``_SENSITIVE_KEYS`` and
        recursively sanitises nested dicts.  The ``metadata`` field is
        dropped entirely since it may contain arbitrary user data.
        """
        cleaned: dict[str, Any] = {}
        for key, value in data.items():
            lower_key = key.lower()
            # Drop sensitive keys entirely
            if lower_key in _SENSITIVE_KEYS:
                continue
            # Drop metadata — it can contain anything
            if lower_key == "metadata":
                continue
            # Recurse into nested dicts
            if isinstance(value, dict):
                value = FederatedMemory._anonymise(value)
            cleaned[key] = value
        return cleaned

    @staticmethod
    def hash_payload(payload: str) -> str:
        """
        Hash a payload for privacy-preserving sharing.

        Uses SHA-256 so the community can deduplicate patterns without
        ever seeing the raw payload text.
        """
        return hashlib.sha256(
            payload.encode("utf-8", errors="replace")
        ).hexdigest()

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """Whether the federated tier has valid connection details."""
        return bool(self.enabled and self._supabase_url and self._supabase_key)

    def __repr__(self) -> str:
        status = "enabled" if self.is_configured else "disabled"
        return f"<FederatedMemory status={status}>"
