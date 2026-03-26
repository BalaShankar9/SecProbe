"""
Kill chain builder — constructs multi-step attack chains from findings.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ChainStep:
    finding_title: str
    category: str
    url: str
    severity: str
    tactic: str  # ATT&CK tactic
    description: str = ""

@dataclass
class AttackChain:
    chain_id: str
    name: str
    steps: list[ChainStep] = field(default_factory=list)
    impact: str = ""  # What an attacker could achieve
    risk_level: str = "HIGH"

    @property
    def length(self) -> int:
        return len(self.steps)


class KillChainBuilder:
    """Builds attack chains from correlated findings."""

    # Chain templates: if findings match these patterns, build a chain
    CHAIN_TEMPLATES = [
        {
            "name": "SQLi to Data Breach",
            "requires": ["sqli"],
            "impact": "Full database access — attacker can read/modify/delete all data",
            "steps_template": [
                ("sqli", "Initial Access", "Exploit SQL injection to access database"),
                ("sqli", "Collection", "Extract sensitive data (user records, credentials)"),
            ],
        },
        {
            "name": "XSS to Account Takeover",
            "requires": ["xss"],
            "impact": "Session hijacking — attacker can impersonate any user",
            "steps_template": [
                ("xss", "Initial Access", "Inject malicious script via XSS"),
                ("cookies", "Credential Access", "Steal session cookies"),
            ],
        },
        {
            "name": "Auth Bypass to Admin Access",
            "requires": ["auth"],
            "optional": ["idor", "sqli"],
            "impact": "Administrative access — full control over application",
            "steps_template": [
                ("auth", "Initial Access", "Bypass authentication mechanism"),
                ("idor", "Privilege Escalation", "Access admin resources via IDOR"),
            ],
        },
        {
            "name": "SSRF to Internal Network Access",
            "requires": ["ssrf"],
            "impact": "Internal network access — can reach internal services and cloud metadata",
            "steps_template": [
                ("ssrf", "Initial Access", "Exploit SSRF to reach internal services"),
                ("ssrf", "Discovery", "Enumerate internal network services"),
                ("ssrf", "Lateral Movement", "Access cloud metadata (169.254.169.254)"),
            ],
        },
        {
            "name": "LFI to Credential Theft",
            "requires": ["lfi"],
            "impact": "Server credential exposure — attacker reads sensitive files",
            "steps_template": [
                ("lfi", "Collection", "Read sensitive files via path traversal"),
                ("lfi", "Credential Access", "Extract credentials from config files"),
            ],
        },
        {
            "name": "File Upload to Remote Code Execution",
            "requires": ["upload"],
            "impact": "Remote code execution — attacker runs arbitrary commands on server",
            "steps_template": [
                ("upload", "Execution", "Upload malicious web shell"),
                ("upload", "Persistence", "Maintain persistent backdoor access"),
            ],
        },
        {
            "name": "CMDi to Full Server Compromise",
            "requires": ["cmdi"],
            "impact": "Full server control — attacker executes arbitrary OS commands",
            "steps_template": [
                ("cmdi", "Execution", "Execute OS commands via injection"),
            ],
        },
    ]

    def build_chains(self, findings: list) -> list[AttackChain]:
        """Build attack chains from a list of findings."""
        categories = set()
        findings_by_cat: dict[str, list] = {}
        for f in findings:
            cat = (getattr(f, 'category', '') or '').lower()
            if cat:
                categories.add(cat)
                findings_by_cat.setdefault(cat, []).append(f)

        chains = []
        for template in self.CHAIN_TEMPLATES:
            required = set(template["requires"])
            if required.issubset(categories):
                chain = self._build_from_template(template, findings_by_cat)
                if chain:
                    chains.append(chain)

        return chains

    def _build_from_template(self, template: dict, findings_by_cat: dict) -> AttackChain | None:
        import hashlib
        steps = []
        for cat, tactic, desc in template["steps_template"]:
            matching = findings_by_cat.get(cat, [])
            if matching:
                f = matching[0]
                steps.append(ChainStep(
                    finding_title=getattr(f, 'title', ''),
                    category=cat,
                    url=getattr(f, 'url', ''),
                    severity=str(getattr(f, 'severity', '')),
                    tactic=tactic,
                    description=desc,
                ))
            else:
                steps.append(ChainStep(
                    finding_title=f"Potential {cat} (not yet confirmed)",
                    category=cat, url="", severity="INFO",
                    tactic=tactic, description=desc,
                ))

        chain_id = hashlib.md5(template["name"].encode()).hexdigest()[:8]
        return AttackChain(
            chain_id=chain_id,
            name=template["name"],
            steps=steps,
            impact=template["impact"],
            risk_level="CRITICAL" if any(s.severity in ("CRITICAL", "Severity.CRITICAL") for s in steps) else "HIGH",
        )
