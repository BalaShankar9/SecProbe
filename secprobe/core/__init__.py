"""
Core infrastructure package for SecProbe.
"""

from secprobe.core.exceptions import (
    SecProbeError,
    TargetUnreachableError,
    AuthenticationError,
    WAFBlockedError,
    ScannerError,
    CrawlerError,
    TemplateError,
)
from secprobe.core.logger import get_logger
from secprobe.core.http_client import HTTPClient, HTTPClientConfig
from secprobe.core.waf import WAFDetector
from secprobe.core.auth import AuthHandler, AuthConfig
from secprobe.core.crawler import Crawler
from secprobe.core.context import ScanContext
from secprobe.core.detection import (
    Confidence,
    VulnType,
    BaselineProfile,
    DetectionResult,
    ResponseAnalyzer,
    ReflectionTracker,
    ErrorPatternMatcher,
    ConfidenceScorer,
    FindingDeduplicator,
    DetectionEngine,
)

__all__ = [
    "SecProbeError",
    "TargetUnreachableError",
    "AuthenticationError",
    "WAFBlockedError",
    "ScannerError",
    "CrawlerError",
    "TemplateError",
    "get_logger",
    "HTTPClient",
    "HTTPClientConfig",
    "WAFDetector",
    "AuthHandler",
    "AuthConfig",
    "Crawler",
    "ScanContext",
    "Confidence",
    "VulnType",
    "BaselineProfile",
    "DetectionResult",
    "ResponseAnalyzer",
    "ReflectionTracker",
    "ErrorPatternMatcher",
    "ConfidenceScorer",
    "FindingDeduplicator",
    "DetectionEngine",
]
