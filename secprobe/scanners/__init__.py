"""
Scanner modules package — 45 attack scanners.
"""

from secprobe.scanners.base import BaseScanner
from secprobe.scanners.port_scanner import PortScanner
from secprobe.scanners.ssl_scanner import SSLScanner
from secprobe.scanners.header_scanner import HeaderScanner
from secprobe.scanners.sqli_scanner import SQLiScanner
from secprobe.scanners.xss_scanner import XSSScanner
from secprobe.scanners.directory_scanner import DirectoryScanner
from secprobe.scanners.dns_scanner import DNSScanner
from secprobe.scanners.cookie_scanner import CookieScanner
from secprobe.scanners.cors_scanner import CORSScanner
from secprobe.scanners.tech_scanner import TechScanner
from secprobe.scanners.ssrf_scanner import SSRFScanner
from secprobe.scanners.ssti_scanner import SSTIScanner
from secprobe.scanners.cmdi_scanner import CMDiScanner
from secprobe.scanners.redirect_scanner import RedirectScanner
from secprobe.scanners.jwt_scanner import JWTScanner
from secprobe.scanners.lfi_scanner import LFIScanner
from secprobe.scanners.xxe_scanner import XXEScanner
from secprobe.scanners.nosql_scanner import NoSQLScanner
from secprobe.scanners.hostheader_scanner import HostHeaderScanner
from secprobe.scanners.csrf_scanner import CSRFScanner
from secprobe.scanners.smuggling_scanner import SmugglingScanner
from secprobe.scanners.api_scanner import APIScanner
from secprobe.scanners.graphql_scanner import GraphQLScanner
from secprobe.scanners.websocket_scanner import WebSocketScanner
from secprobe.scanners.upload_scanner import UploadScanner
from secprobe.scanners.deserialization_scanner import DeserializationScanner
from secprobe.scanners.oauth_scanner import OAuthScanner
from secprobe.scanners.race_scanner import RaceConditionScanner
from secprobe.scanners.ldap_scanner import LDAPScanner
from secprobe.scanners.xpath_scanner import XPathScanner
from secprobe.scanners.crlf_scanner import CRLFScanner
from secprobe.scanners.hpp_scanner import HPPScanner
# ── v7.0 scanners ────────────────────────────────────────────────
from secprobe.scanners.js_scanner import JSScanner
from secprobe.scanners.cve_scanner import CVEScanner
from secprobe.scanners.takeover_scanner import TakeoverScanner
from secprobe.scanners.domxss_scanner import DOMXSSScanner
from secprobe.scanners.idor_scanner import IDORScanner
from secprobe.scanners.waf_scanner import WAFScanner
from secprobe.scanners.email_scanner import EmailScanner
from secprobe.scanners.bizlogic_scanner import BizLogicScanner
from secprobe.scanners.prototype_scanner import PrototypePollutionScanner
from secprobe.scanners.cloud_scanner import CloudScanner
from secprobe.scanners.fuzzer_scanner import FuzzerScanner
from secprobe.scanners.passive_scanner import PassiveScanner
from secprobe.scanners.cache_poisoning_scanner import CachePoisoningScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "ports": PortScanner,
    "ssl": SSLScanner,
    "headers": HeaderScanner,
    "sqli": SQLiScanner,
    "xss": XSSScanner,
    "dirs": DirectoryScanner,
    "dns": DNSScanner,
    "cookies": CookieScanner,
    "cors": CORSScanner,
    "tech": TechScanner,
    "ssrf": SSRFScanner,
    "ssti": SSTIScanner,
    "cmdi": CMDiScanner,
    "redirect": RedirectScanner,
    "jwt": JWTScanner,
    "lfi": LFIScanner,
    "xxe": XXEScanner,
    "nosql": NoSQLScanner,
    "hostheader": HostHeaderScanner,
    "csrf": CSRFScanner,
    "smuggling": SmugglingScanner,
    "api": APIScanner,
    "graphql": GraphQLScanner,
    "websocket": WebSocketScanner,
    "upload": UploadScanner,
    "deser": DeserializationScanner,
    "oauth": OAuthScanner,
    "race": RaceConditionScanner,
    "ldap": LDAPScanner,
    "xpath": XPathScanner,
    "crlf": CRLFScanner,
    "hpp": HPPScanner,
    # ── v7.0 ──────────────────────────────────────────────────
    "js": JSScanner,
    "cve": CVEScanner,
    "takeover": TakeoverScanner,
    "domxss": DOMXSSScanner,
    "idor": IDORScanner,
    "wafid": WAFScanner,
    "email": EmailScanner,
    "bizlogic": BizLogicScanner,
    "prototype": PrototypePollutionScanner,
    "cloud": CloudScanner,
    "fuzz": FuzzerScanner,
    "passive": PassiveScanner,
    "cachepoisoning": CachePoisoningScanner,
}

__all__ = [
    "BaseScanner",
    "PortScanner",
    "SSLScanner",
    "HeaderScanner",
    "SQLiScanner",
    "XSSScanner",
    "DirectoryScanner",
    "DNSScanner",
    "CookieScanner",
    "CORSScanner",
    "TechScanner",
    "SSRFScanner",
    "SSTIScanner",
    "CMDiScanner",
    "RedirectScanner",
    "JWTScanner",
    "LFIScanner",
    "XXEScanner",
    "NoSQLScanner",
    "HostHeaderScanner",
    "CSRFScanner",
    "SmugglingScanner",
    "APIScanner",
    "GraphQLScanner",
    "WebSocketScanner",
    "UploadScanner",
    "DeserializationScanner",
    "OAuthScanner",
    "RaceConditionScanner",
    "LDAPScanner",
    "XPathScanner",
    "CRLFScanner",
    "HPPScanner",
    "JSScanner",
    "CVEScanner",
    "TakeoverScanner",
    "DOMXSSScanner",
    "IDORScanner",
    "WAFScanner",
    "EmailScanner",
    "BizLogicScanner",
    "PrototypePollutionScanner",
    "CloudScanner",
    "FuzzerScanner",
    "PassiveScanner",
    "CachePoisoningScanner",
    "SCANNER_REGISTRY",
]
