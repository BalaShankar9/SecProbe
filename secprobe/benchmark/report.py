"""Benchmark reporting."""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class BenchmarkReport:
    total_challenges: int = 0
    detected: int = 0
    false_positives: int = 0
    findings: list[dict] = field(default_factory=list)
    duration_seconds: float = 0.0
    target: str = ""

    @property
    def detection_rate(self) -> float:
        return self.detected / self.total_challenges if self.total_challenges > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        total = self.detected + self.false_positives
        return self.false_positives / total if total > 0 else 0.0

    @property
    def grade(self) -> str:
        rate = self.detection_rate
        if rate >= 0.95:
            return "A+"
        if rate >= 0.90:
            return "A"
        if rate >= 0.80:
            return "B"
        if rate >= 0.70:
            return "C"
        if rate >= 0.60:
            return "D"
        return "F"

    def to_markdown(self) -> str:
        lines = [
            f"# Benchmark Report: {self.target}",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Detection Rate | {self.detection_rate:.1%} ({self.detected}/{self.total_challenges}) |",
            f"| False Positive Rate | {self.fp_rate:.1%} |",
            f"| Grade | {self.grade} |",
            f"| Duration | {self.duration_seconds:.1f}s |",
            f"| Total Findings | {len(self.findings)} |",
        ]
        return "\n".join(lines)
