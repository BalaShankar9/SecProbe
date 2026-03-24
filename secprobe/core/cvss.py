"""
CVSS 3.1 Calculator — Full implementation of the Common Vulnerability Scoring System.

Computes Base, Temporal, and Environmental scores per FIRST.org specification.
Generates vector strings, severity ratings, and detailed score breakdowns.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── CVSS 3.1 Metric Enumerations ────────────────────────────────────

class AttackVector(Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class ExploitCodeMaturity(Enum):
    NOT_DEFINED = "X"
    UNPROVEN = "U"
    PROOF_OF_CONCEPT = "P"
    FUNCTIONAL = "F"
    HIGH = "H"


class RemediationLevel(Enum):
    NOT_DEFINED = "X"
    OFFICIAL_FIX = "O"
    TEMPORARY_FIX = "T"
    WORKAROUND = "W"
    UNAVAILABLE = "U"


class ReportConfidence(Enum):
    NOT_DEFINED = "X"
    UNKNOWN = "U"
    REASONABLE = "R"
    CONFIRMED = "C"


class Requirement(Enum):
    NOT_DEFINED = "X"
    LOW = "L"
    MEDIUM = "M"
    HIGH = "H"


# ── Weight Tables (FIRST.org CVSS 3.1 specification) ────────────────

AV_WEIGHTS = {
    AttackVector.NETWORK: 0.85,
    AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL: 0.55,
    AttackVector.PHYSICAL: 0.20,
}

AC_WEIGHTS = {
    AttackComplexity.LOW: 0.77,
    AttackComplexity.HIGH: 0.44,
}

# Privileges Required changes based on Scope
PR_WEIGHTS_UNCHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.62,
    PrivilegesRequired.HIGH: 0.27,
}

PR_WEIGHTS_CHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.68,
    PrivilegesRequired.HIGH: 0.50,
}

UI_WEIGHTS = {
    UserInteraction.NONE: 0.85,
    UserInteraction.REQUIRED: 0.62,
}

CIA_WEIGHTS = {
    Impact.NONE: 0,
    Impact.LOW: 0.22,
    Impact.HIGH: 0.56,
}

E_WEIGHTS = {
    ExploitCodeMaturity.NOT_DEFINED: 1.0,
    ExploitCodeMaturity.UNPROVEN: 0.91,
    ExploitCodeMaturity.PROOF_OF_CONCEPT: 0.94,
    ExploitCodeMaturity.FUNCTIONAL: 0.97,
    ExploitCodeMaturity.HIGH: 1.0,
}

RL_WEIGHTS = {
    RemediationLevel.NOT_DEFINED: 1.0,
    RemediationLevel.OFFICIAL_FIX: 0.95,
    RemediationLevel.TEMPORARY_FIX: 0.96,
    RemediationLevel.WORKAROUND: 0.97,
    RemediationLevel.UNAVAILABLE: 1.0,
}

RC_WEIGHTS = {
    ReportConfidence.NOT_DEFINED: 1.0,
    ReportConfidence.UNKNOWN: 0.92,
    ReportConfidence.REASONABLE: 0.96,
    ReportConfidence.CONFIRMED: 1.0,
}

CR_WEIGHTS = {
    Requirement.NOT_DEFINED: 1.0,
    Requirement.LOW: 0.5,
    Requirement.MEDIUM: 1.0,
    Requirement.HIGH: 1.5,
}


def _roundup(x: float) -> float:
    """CVSS roundup function — round to nearest tenth, always up."""
    return math.ceil(x * 10) / 10


# ── CVSS Score Result ────────────────────────────────────────────────

@dataclass
class CVSSScore:
    """Complete CVSS 3.1 score result."""
    vector_string: str
    base_score: float
    base_severity: str
    exploitability_score: float
    impact_score: float
    temporal_score: Optional[float] = None
    temporal_severity: Optional[str] = None
    environmental_score: Optional[float] = None
    environmental_severity: Optional[str] = None

    def to_dict(self) -> dict:
        result = {
            "vector_string": self.vector_string,
            "base_score": self.base_score,
            "base_severity": self.base_severity,
            "exploitability_score": round(self.exploitability_score, 1),
            "impact_score": round(self.impact_score, 1),
        }
        if self.temporal_score is not None:
            result["temporal_score"] = self.temporal_score
            result["temporal_severity"] = self.temporal_severity
        if self.environmental_score is not None:
            result["environmental_score"] = self.environmental_score
            result["environmental_severity"] = self.environmental_severity
        return result


# ── CVSS 3.1 Calculator ─────────────────────────────────────────────

@dataclass
class CVSSVector:
    """
    Full CVSS 3.1 vector with all metric groups.

    Usage:
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        score = vector.calculate()
        print(score.base_score)       # 9.8
        print(score.base_severity)    # CRITICAL
        print(score.vector_string)    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """

    # Base metrics (required)
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.NONE
    integrity: Impact = Impact.NONE
    availability: Impact = Impact.NONE

    # Temporal metrics (optional)
    exploit_code_maturity: ExploitCodeMaturity = ExploitCodeMaturity.NOT_DEFINED
    remediation_level: RemediationLevel = RemediationLevel.NOT_DEFINED
    report_confidence: ReportConfidence = ReportConfidence.NOT_DEFINED

    # Environmental metrics (optional)
    confidentiality_requirement: Requirement = Requirement.NOT_DEFINED
    integrity_requirement: Requirement = Requirement.NOT_DEFINED
    availability_requirement: Requirement = Requirement.NOT_DEFINED

    # Modified base metrics (environmental)
    modified_attack_vector: Optional[AttackVector] = None
    modified_attack_complexity: Optional[AttackComplexity] = None
    modified_privileges_required: Optional[PrivilegesRequired] = None
    modified_user_interaction: Optional[UserInteraction] = None
    modified_scope: Optional[Scope] = None
    modified_confidentiality: Optional[Impact] = None
    modified_integrity: Optional[Impact] = None
    modified_availability: Optional[Impact] = None

    def calculate(self) -> CVSSScore:
        """Calculate all CVSS 3.1 scores."""
        base_score, exploitability, impact = self._calculate_base()
        temporal_score = self._calculate_temporal(base_score)
        environmental_score = self._calculate_environmental()

        return CVSSScore(
            vector_string=self.to_vector_string(),
            base_score=base_score,
            base_severity=self._severity_rating(base_score),
            exploitability_score=exploitability,
            impact_score=impact,
            temporal_score=temporal_score if self._has_temporal() else None,
            temporal_severity=self._severity_rating(temporal_score) if self._has_temporal() else None,
            environmental_score=environmental_score if self._has_environmental() else None,
            environmental_severity=self._severity_rating(environmental_score) if self._has_environmental() else None,
        )

    def _calculate_base(self) -> tuple[float, float, float]:
        """Calculate Base Score per CVSS 3.1 specification."""
        # ISS = Impact Sub-Score
        iss = 1 - (
            (1 - CIA_WEIGHTS[self.confidentiality])
            * (1 - CIA_WEIGHTS[self.integrity])
            * (1 - CIA_WEIGHTS[self.availability])
        )

        # Impact
        if self.scope == Scope.UNCHANGED:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        # Exploitability
        pr_weights = PR_WEIGHTS_CHANGED if self.scope == Scope.CHANGED else PR_WEIGHTS_UNCHANGED
        exploitability = (
            8.22
            * AV_WEIGHTS[self.attack_vector]
            * AC_WEIGHTS[self.attack_complexity]
            * pr_weights[self.privileges_required]
            * UI_WEIGHTS[self.user_interaction]
        )

        # Base Score
        if impact <= 0:
            base_score = 0.0
        elif self.scope == Scope.UNCHANGED:
            base_score = _roundup(min(exploitability + impact, 10))
        else:
            base_score = _roundup(min(1.08 * (exploitability + impact), 10))

        return base_score, round(exploitability, 1), round(impact, 1)

    def _calculate_temporal(self, base_score: float) -> float:
        """Calculate Temporal Score."""
        temporal = _roundup(
            base_score
            * E_WEIGHTS[self.exploit_code_maturity]
            * RL_WEIGHTS[self.remediation_level]
            * RC_WEIGHTS[self.report_confidence]
        )
        return temporal

    def _calculate_environmental(self) -> float:
        """Calculate Environmental Score using modified base metrics."""
        # Use modified metrics or fall back to base
        mav = self.modified_attack_vector or self.attack_vector
        mac = self.modified_attack_complexity or self.attack_complexity
        mpr = self.modified_privileges_required or self.privileges_required
        mui = self.modified_user_interaction or self.user_interaction
        ms = self.modified_scope or self.scope
        mc = self.modified_confidentiality or self.confidentiality
        mi = self.modified_integrity or self.integrity
        ma = self.modified_availability or self.availability

        # Modified ISS
        miss = min(
            1
            - (1 - CIA_WEIGHTS[mc] * CR_WEIGHTS[self.confidentiality_requirement])
            * (1 - CIA_WEIGHTS[mi] * CR_WEIGHTS[self.integrity_requirement])
            * (1 - CIA_WEIGHTS[ma] * CR_WEIGHTS[self.availability_requirement]),
            0.915,
        )

        # Modified Impact
        if ms == Scope.UNCHANGED:
            m_impact = 6.42 * miss
        else:
            m_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13

        # Modified Exploitability
        pr_weights = PR_WEIGHTS_CHANGED if ms == Scope.CHANGED else PR_WEIGHTS_UNCHANGED
        m_exploitability = (
            8.22
            * AV_WEIGHTS[mav]
            * AC_WEIGHTS[mac]
            * pr_weights[mpr]
            * UI_WEIGHTS[mui]
        )

        if m_impact <= 0:
            env_score = 0.0
        elif ms == Scope.UNCHANGED:
            env_score = _roundup(
                _roundup(min(m_exploitability + m_impact, 10))
                * E_WEIGHTS[self.exploit_code_maturity]
                * RL_WEIGHTS[self.remediation_level]
                * RC_WEIGHTS[self.report_confidence]
            )
        else:
            env_score = _roundup(
                _roundup(min(1.08 * (m_exploitability + m_impact), 10))
                * E_WEIGHTS[self.exploit_code_maturity]
                * RL_WEIGHTS[self.remediation_level]
                * RC_WEIGHTS[self.report_confidence]
            )

        return env_score

    def _has_temporal(self) -> bool:
        return (
            self.exploit_code_maturity != ExploitCodeMaturity.NOT_DEFINED
            or self.remediation_level != RemediationLevel.NOT_DEFINED
            or self.report_confidence != ReportConfidence.NOT_DEFINED
        )

    def _has_environmental(self) -> bool:
        return (
            self.confidentiality_requirement != Requirement.NOT_DEFINED
            or self.integrity_requirement != Requirement.NOT_DEFINED
            or self.availability_requirement != Requirement.NOT_DEFINED
            or self.modified_attack_vector is not None
            or self.modified_attack_complexity is not None
            or self.modified_privileges_required is not None
            or self.modified_user_interaction is not None
            or self.modified_scope is not None
            or self.modified_confidentiality is not None
            or self.modified_integrity is not None
            or self.modified_availability is not None
        )

    def to_vector_string(self) -> str:
        """Generate CVSS 3.1 vector string."""
        parts = [
            "CVSS:3.1",
            f"AV:{self.attack_vector.value}",
            f"AC:{self.attack_complexity.value}",
            f"PR:{self.privileges_required.value}",
            f"UI:{self.user_interaction.value}",
            f"S:{self.scope.value}",
            f"C:{self.confidentiality.value}",
            f"I:{self.integrity.value}",
            f"A:{self.availability.value}",
        ]
        # Temporal
        if self.exploit_code_maturity != ExploitCodeMaturity.NOT_DEFINED:
            parts.append(f"E:{self.exploit_code_maturity.value}")
        if self.remediation_level != RemediationLevel.NOT_DEFINED:
            parts.append(f"RL:{self.remediation_level.value}")
        if self.report_confidence != ReportConfidence.NOT_DEFINED:
            parts.append(f"RC:{self.report_confidence.value}")
        # Environmental
        if self.confidentiality_requirement != Requirement.NOT_DEFINED:
            parts.append(f"CR:{self.confidentiality_requirement.value}")
        if self.integrity_requirement != Requirement.NOT_DEFINED:
            parts.append(f"IR:{self.integrity_requirement.value}")
        if self.availability_requirement != Requirement.NOT_DEFINED:
            parts.append(f"AR:{self.availability_requirement.value}")
        if self.modified_attack_vector is not None:
            parts.append(f"MAV:{self.modified_attack_vector.value}")
        if self.modified_attack_complexity is not None:
            parts.append(f"MAC:{self.modified_attack_complexity.value}")
        if self.modified_privileges_required is not None:
            parts.append(f"MPR:{self.modified_privileges_required.value}")
        if self.modified_user_interaction is not None:
            parts.append(f"MUI:{self.modified_user_interaction.value}")
        if self.modified_scope is not None:
            parts.append(f"MS:{self.modified_scope.value}")
        if self.modified_confidentiality is not None:
            parts.append(f"MC:{self.modified_confidentiality.value}")
        if self.modified_integrity is not None:
            parts.append(f"MI:{self.modified_integrity.value}")
        if self.modified_availability is not None:
            parts.append(f"MA:{self.modified_availability.value}")

        return "/".join(parts)

    @staticmethod
    def _severity_rating(score: float) -> str:
        """Convert numeric score to severity label."""
        if score == 0.0:
            return "NONE"
        elif score <= 3.9:
            return "LOW"
        elif score <= 6.9:
            return "MEDIUM"
        elif score <= 8.9:
            return "HIGH"
        else:
            return "CRITICAL"

    @classmethod
    def from_vector_string(cls, vector: str) -> CVSSVector:
        """Parse a CVSS 3.1 vector string into a CVSSVector object."""
        parts = vector.split("/")
        if not parts[0].startswith("CVSS:3."):
            raise ValueError(f"Invalid CVSS 3.1 vector: {vector}")

        metrics = {}
        for part in parts[1:]:
            key, value = part.split(":", 1)
            metrics[key] = value

        # Reverse lookup helpers
        def _find_enum(enum_cls, value):
            for member in enum_cls:
                if member.value == value:
                    return member
            raise ValueError(f"Invalid value '{value}' for {enum_cls.__name__}")

        kwargs = {}
        if "AV" in metrics:
            kwargs["attack_vector"] = _find_enum(AttackVector, metrics["AV"])
        if "AC" in metrics:
            kwargs["attack_complexity"] = _find_enum(AttackComplexity, metrics["AC"])
        if "PR" in metrics:
            kwargs["privileges_required"] = _find_enum(PrivilegesRequired, metrics["PR"])
        if "UI" in metrics:
            kwargs["user_interaction"] = _find_enum(UserInteraction, metrics["UI"])
        if "S" in metrics:
            kwargs["scope"] = _find_enum(Scope, metrics["S"])
        if "C" in metrics:
            kwargs["confidentiality"] = _find_enum(Impact, metrics["C"])
        if "I" in metrics:
            kwargs["integrity"] = _find_enum(Impact, metrics["I"])
        if "A" in metrics:
            kwargs["availability"] = _find_enum(Impact, metrics["A"])
        # Temporal
        if "E" in metrics:
            kwargs["exploit_code_maturity"] = _find_enum(ExploitCodeMaturity, metrics["E"])
        if "RL" in metrics:
            kwargs["remediation_level"] = _find_enum(RemediationLevel, metrics["RL"])
        if "RC" in metrics:
            kwargs["report_confidence"] = _find_enum(ReportConfidence, metrics["RC"])
        # Environmental
        if "CR" in metrics:
            kwargs["confidentiality_requirement"] = _find_enum(Requirement, metrics["CR"])
        if "IR" in metrics:
            kwargs["integrity_requirement"] = _find_enum(Requirement, metrics["IR"])
        if "AR" in metrics:
            kwargs["availability_requirement"] = _find_enum(Requirement, metrics["AR"])
        if "MAV" in metrics:
            kwargs["modified_attack_vector"] = _find_enum(AttackVector, metrics["MAV"])
        if "MAC" in metrics:
            kwargs["modified_attack_complexity"] = _find_enum(AttackComplexity, metrics["MAC"])
        if "MPR" in metrics:
            kwargs["modified_privileges_required"] = _find_enum(PrivilegesRequired, metrics["MPR"])
        if "MUI" in metrics:
            kwargs["modified_user_interaction"] = _find_enum(UserInteraction, metrics["MUI"])
        if "MS" in metrics:
            kwargs["modified_scope"] = _find_enum(Scope, metrics["MS"])
        if "MC" in metrics:
            kwargs["modified_confidentiality"] = _find_enum(Impact, metrics["MC"])
        if "MI" in metrics:
            kwargs["modified_integrity"] = _find_enum(Impact, metrics["MI"])
        if "MA" in metrics:
            kwargs["modified_availability"] = _find_enum(Impact, metrics["MA"])

        return cls(**kwargs)


# ── Vulnerability-to-CVSS Mapping ────────────────────────────────────

# Pre-built CVSS vectors for common vulnerability types
VULN_CVSS_MAP: dict[str, CVSSVector] = {
    # SQL Injection — Network/Low/None/None, full CIA impact
    "sqli": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    # XSS Reflected — requires user interaction
    "xss_reflected": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    # XSS Stored — no user interaction needed for trigger
    "xss_stored": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    # SSTI — can lead to RCE
    "ssti": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    # Command Injection — full system compromise
    "cmdi": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    # LFI — file read, potential RCE via log poisoning
    "lfi": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    # SSRF — internal network access
    "ssrf": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    # XXE — XML external entity, file read + SSRF
    "xxe": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.NONE,
        availability=Impact.LOW,
    ),
    # NoSQL Injection
    "nosql": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    # Open Redirect
    "redirect": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    # CORS Misconfiguration
    "cors": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    # CSRF
    "csrf": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    # JWT Vulnerabilities
    "jwt": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    # HTTP Request Smuggling
    "smuggling": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    # Host Header Injection
    "hostheader": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    # SSL/TLS Misconfig
    "ssl": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    # Missing Security Headers
    "headers": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    # Cookie Security Issues
    "cookies": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    # GraphQL Injection
    "graphql": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        availability=Impact.LOW,
    ),
    # WebSocket Hijacking
    "websocket": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    # API Security Issues
    "api": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    # Information Disclosure (generic)
    "info_disclosure": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
}


def get_cvss_for_finding(scanner_name: str, severity: str) -> Optional[CVSSScore]:
    """
    Get a CVSS score for a finding based on its scanner type.

    Falls back to severity-based estimation if no specific mapping exists.
    """
    scanner_key = scanner_name.lower().replace(" scanner", "").replace(" ", "_")

    if scanner_key in VULN_CVSS_MAP:
        return VULN_CVSS_MAP[scanner_key].calculate()

    # Fallback: estimate from severity
    severity_vectors = {
        "CRITICAL": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        ),
        "HIGH": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        ),
        "MEDIUM": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        ),
        "LOW": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        ),
    }

    if severity in severity_vectors:
        return severity_vectors[severity].calculate()

    return None
