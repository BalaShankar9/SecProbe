"""MITRE ATT&CK mapping for SecProbe findings."""

from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class ATTACKMapping:
    tactic: str         # e.g., "Initial Access"
    tactic_id: str      # e.g., "TA0001"
    technique: str      # e.g., "Exploit Public-Facing Application"
    technique_id: str   # e.g., "T1190"
    description: str = ""

# Map vuln categories to ATT&CK
VULN_TO_ATTACK: dict[str, list[ATTACKMapping]] = {
    "sqli": [
        ATTACKMapping("Initial Access", "TA0001", "Exploit Public-Facing Application", "T1190"),
        ATTACKMapping("Collection", "TA0009", "Data from Information Repositories", "T1213"),
    ],
    "xss": [
        ATTACKMapping("Initial Access", "TA0001", "Drive-by Compromise", "T1189"),
        ATTACKMapping("Execution", "TA0002", "User Execution", "T1204"),
        ATTACKMapping("Credential Access", "TA0006", "Input Capture", "T1056"),
    ],
    "ssrf": [
        ATTACKMapping("Initial Access", "TA0001", "Exploit Public-Facing Application", "T1190"),
        ATTACKMapping("Discovery", "TA0007", "Network Service Discovery", "T1046"),
        ATTACKMapping("Lateral Movement", "TA0008", "Exploitation of Remote Services", "T1210"),
    ],
    "auth": [
        ATTACKMapping("Credential Access", "TA0006", "Brute Force", "T1110"),
        ATTACKMapping("Initial Access", "TA0001", "Valid Accounts", "T1078"),
    ],
    "idor": [
        ATTACKMapping("Collection", "TA0009", "Data from Information Repositories", "T1213"),
        ATTACKMapping("Privilege Escalation", "TA0004", "Access Token Manipulation", "T1134"),
    ],
    "lfi": [
        ATTACKMapping("Collection", "TA0009", "Data from Local System", "T1005"),
        ATTACKMapping("Credential Access", "TA0006", "Credentials from Password Stores", "T1555"),
    ],
    "cmdi": [
        ATTACKMapping("Execution", "TA0002", "Command and Scripting Interpreter", "T1059"),
    ],
    "ssti": [
        ATTACKMapping("Execution", "TA0002", "Server Software Component", "T1505"),
    ],
    "jwt": [
        ATTACKMapping("Credential Access", "TA0006", "Forge Web Credentials", "T1606"),
    ],
    "cors": [
        ATTACKMapping("Collection", "TA0009", "Data from Information Repositories", "T1213"),
    ],
    "csrf": [
        ATTACKMapping("Execution", "TA0002", "User Execution", "T1204"),
    ],
    "xxe": [
        ATTACKMapping("Collection", "TA0009", "Data from Local System", "T1005"),
        ATTACKMapping("Exfiltration", "TA0010", "Exfiltration Over Web Service", "T1567"),
    ],
    "redirect": [
        ATTACKMapping("Initial Access", "TA0001", "Phishing", "T1566"),
    ],
    "upload": [
        ATTACKMapping("Execution", "TA0002", "Server Software Component: Web Shell", "T1505.003"),
        ATTACKMapping("Persistence", "TA0003", "Server Software Component: Web Shell", "T1505.003"),
    ],
    "deserialization": [
        ATTACKMapping("Execution", "TA0002", "Exploitation for Client Execution", "T1203"),
    ],
    "nosql": [
        ATTACKMapping("Initial Access", "TA0001", "Exploit Public-Facing Application", "T1190"),
        ATTACKMapping("Collection", "TA0009", "Data from Information Repositories", "T1213"),
    ],
    "headers": [
        ATTACKMapping("Reconnaissance", "TA0043", "Gather Victim Host Information", "T1592"),
    ],
    "cookies": [
        ATTACKMapping("Credential Access", "TA0006", "Steal Web Session Cookie", "T1539"),
    ],
}


class ATTACKMapper:
    """Map SecProbe findings to MITRE ATT&CK framework."""

    def map_finding(self, finding) -> list[ATTACKMapping]:
        category = (getattr(finding, 'category', '') or '').lower().strip()
        # Direct match
        if category in VULN_TO_ATTACK:
            return VULN_TO_ATTACK[category]
        # Partial match
        for key, mappings in VULN_TO_ATTACK.items():
            if key in category or category in key:
                return mappings
        return []

    def map_findings(self, findings: list) -> dict:
        """Map all findings and aggregate by tactic."""
        tactics: dict[str, list[dict]] = {}
        for f in findings:
            mappings = self.map_finding(f)
            for m in mappings:
                if m.tactic not in tactics:
                    tactics[m.tactic] = []
                tactics[m.tactic].append({
                    "technique": m.technique,
                    "technique_id": m.technique_id,
                    "finding": getattr(f, 'title', ''),
                    "severity": str(getattr(f, 'severity', '')),
                })
        return tactics

    def get_kill_chain_coverage(self, findings: list) -> dict:
        """Show ATT&CK kill chain coverage from findings."""
        all_tactics = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Exfiltration", "Impact",
        ]
        tactics_found = self.map_findings(findings)
        coverage = {}
        for tactic in all_tactics:
            techniques = tactics_found.get(tactic, [])
            coverage[tactic] = {
                "covered": len(techniques) > 0,
                "technique_count": len(techniques),
                "techniques": techniques,
            }
        return coverage
