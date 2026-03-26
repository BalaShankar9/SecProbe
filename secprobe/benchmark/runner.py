"""Benchmark runner — invokes SecProbe programmatically and maps results."""

from __future__ import annotations

import time
from typing import Any

from secprobe.benchmark.juice_shop import JuiceShopBenchmark
from secprobe.benchmark.report import BenchmarkReport


class BenchmarkRunner:
    """Run SecProbe against a known-vulnerable target and produce a benchmark report."""

    def __init__(self, target: str = "http://localhost:3000"):
        self.target = target
        self.benchmark = JuiceShopBenchmark()

    def run(self, findings: list[dict] | None = None) -> BenchmarkReport:
        """Run benchmark with provided findings or an empty list.

        In a full integration, this would invoke SecProbe scanners against the
        target and collect findings automatically. For now it accepts pre-collected
        findings for offline benchmarking.

        Args:
            findings: List of finding dicts with keys like title, category, url.
                      If None, an empty list is used (useful for dry-run / scaffolding).

        Returns:
            A populated BenchmarkReport.
        """
        if findings is None:
            findings = []

        start = time.monotonic()
        result = self.benchmark.run_benchmark(findings)
        elapsed = time.monotonic() - start

        report = BenchmarkReport(
            total_challenges=result["total_challenges"],
            detected=result["detected"],
            false_positives=0,
            findings=findings,
            duration_seconds=elapsed,
            target=self.target,
        )
        return report

    def run_and_format(self, findings: list[dict] | None = None) -> str:
        """Run benchmark and return a markdown-formatted report."""
        report = self.run(findings)
        return report.to_markdown()
