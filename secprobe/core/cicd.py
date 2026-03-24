"""
CI/CD Integration Layer — SARIF, JUnit XML, and machine-readable outputs.

Outputs:
  - SARIF 2.1.0: GitHub Advanced Security, GitLab SAST, Azure DevOps
  - JUnit XML: Jenkins, CircleCI, GitHub Actions, any CI system
  - JSON Summary: Machine-readable compact format
  - Exit codes: Configurable severity threshold for pipeline gating

Standards:
  - SARIF: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
  - JUnit XML: https://llg.cubic.org/docs/junit/
"""

from __future__ import annotations

import json
import os
import xml.dom.minidom
from datetime import datetime
from typing import Optional
from xml.etree.ElementTree import Element, SubElement, tostring

from secprobe.models import Finding, ScanResult


# ── SARIF 2.1.0 Output ──────────────────────────────────────────────

class SARIFGenerator:
    """
    Generate SARIF 2.1.0 output for GitHub/GitLab/Azure DevOps integration.

    SARIF is the standard format for static analysis results.
    GitHub Advanced Security, GitLab SAST, and Azure DevOps all support it.
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, tool_name: str = "SecProbe", tool_version: str = "7.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, results: list[ScanResult], target: str,
                 output_file: Optional[str] = None) -> str:
        """Generate SARIF 2.1.0 JSON from scan results."""
        rules = []
        rule_ids = set()
        sarif_results = []

        for scan_result in results:
            for finding in scan_result.findings:
                # Create rule if not already defined
                rule_id = self._finding_to_rule_id(finding)
                if rule_id not in rule_ids:
                    rule_ids.add(rule_id)
                    rules.append(self._build_rule(finding, rule_id))

                sarif_results.append(self._build_result(finding, rule_id, target))

        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/secprobe/secprobe",
                            "rules": rules,
                            "semanticVersion": self.tool_version,
                        }
                    },
                    "results": sarif_results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now().isoformat() + "Z",
                        }
                    ],
                    "properties": {
                        "target": target,
                        "scanType": "dynamic",
                    },
                }
            ],
        }

        content = json.dumps(sarif, indent=2)

        if output_file:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as f:
                f.write(content)

        return content

    def _finding_to_rule_id(self, finding: Finding) -> str:
        """Convert a finding to a unique SARIF rule ID."""
        scanner = finding.scanner.replace(" ", "-").lower()
        cwe = finding.cwe.replace("CWE-", "").replace("cwe-", "") if finding.cwe else "0"
        return f"secprobe/{scanner}/cwe-{cwe}"

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Map SecProbe severity to SARIF level."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return mapping.get(severity, "warning")

    def _severity_to_sarif_security_severity(self, severity: str) -> str:
        """Map severity to SARIF security-severity property (numeric)."""
        mapping = {
            "CRITICAL": "9.5",
            "HIGH": "8.0",
            "MEDIUM": "5.5",
            "LOW": "3.0",
            "INFO": "1.0",
        }
        return mapping.get(severity, "5.0")

    def _build_rule(self, finding: Finding, rule_id: str) -> dict:
        """Build a SARIF rule definition from a finding."""
        rule = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {
                "text": finding.title,
            },
            "fullDescription": {
                "text": finding.description,
            },
            "help": {
                "text": finding.recommendation or "No remediation guidance available.",
                "markdown": f"**Recommendation**: {finding.recommendation}" if finding.recommendation else "",
            },
            "properties": {
                "tags": ["security", finding.category] if finding.category else ["security"],
                "security-severity": self._severity_to_sarif_security_severity(finding.severity),
            },
            "defaultConfiguration": {
                "level": self._severity_to_sarif_level(finding.severity),
            },
        }

        if finding.cwe:
            rule["properties"]["cwe"] = [finding.cwe]
            rule["relationships"] = [
                {
                    "target": {
                        "id": finding.cwe,
                        "toolComponent": {"name": "CWE", "guid": ""},
                    },
                    "kinds": ["superset"],
                }
            ]

        return rule

    def _build_result(self, finding: Finding, rule_id: str, target: str) -> dict:
        """Build a SARIF result from a finding."""
        result = {
            "ruleId": rule_id,
            "level": self._severity_to_sarif_level(finding.severity),
            "message": {
                "text": finding.description,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.url or target,
                        },
                    },
                    "logicalLocations": [
                        {
                            "fullyQualifiedName": finding.url or target,
                            "kind": "url",
                        }
                    ],
                }
            ],
            "properties": {
                "severity": finding.severity,
                "scanner": finding.scanner,
                "category": finding.category,
            },
        }

        if finding.evidence:
            result["codeFlows"] = [
                {
                    "message": {"text": "Evidence"},
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "message": {"text": finding.evidence[:500]},
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": finding.url or target,
                                            },
                                        },
                                    }
                                }
                            ]
                        }
                    ],
                }
            ]

        return result


# ── JUnit XML Output ─────────────────────────────────────────────────

class JUnitGenerator:
    """
    Generate JUnit XML output for CI/CD test framework integration.

    Each scanner becomes a test suite, each finding becomes a test case failure.
    Scanners with no findings show as passed tests.
    """

    def generate(self, results: list[ScanResult], target: str,
                 output_file: Optional[str] = None) -> str:
        """Generate JUnit XML from scan results."""
        testsuites = Element("testsuites")
        testsuites.set("name", f"SecProbe Security Scan - {target}")
        testsuites.set("timestamp", datetime.now().isoformat())

        total_tests = 0
        total_failures = 0
        total_errors = 0
        total_time = 0.0

        for result in results:
            suite = SubElement(testsuites, "testsuite")
            suite.set("name", result.scanner_name)
            suite.set("timestamp", result.start_time.isoformat())
            suite.set("time", f"{result.duration:.2f}")

            failures = 0
            errors = 0

            if result.error:
                errors = 1
                testcase = SubElement(suite, "testcase")
                testcase.set("name", f"{result.scanner_name} execution")
                testcase.set("classname", f"secprobe.{result.scanner_name}")
                testcase.set("time", f"{result.duration:.2f}")
                error_elem = SubElement(testcase, "error")
                error_elem.set("message", result.error)
                error_elem.set("type", "ScannerError")
                error_elem.text = result.error
            elif not result.findings:
                # No findings = passed test
                testcase = SubElement(suite, "testcase")
                testcase.set("name", f"{result.scanner_name} - no vulnerabilities found")
                testcase.set("classname", f"secprobe.{result.scanner_name}")
                testcase.set("time", f"{result.duration:.2f}")
            else:
                for finding in result.findings:
                    testcase = SubElement(suite, "testcase")
                    testcase.set("name", finding.title)
                    testcase.set("classname", f"secprobe.{result.scanner_name}")
                    testcase.set("time", "0.00")

                    if finding.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                        failures += 1
                        failure = SubElement(testcase, "failure")
                        failure.set("message", finding.title)
                        failure.set("type", f"{finding.severity} Vulnerability")
                        failure_text = f"Severity: {finding.severity}\n"
                        if finding.cwe:
                            failure_text += f"CWE: {finding.cwe}\n"
                        failure_text += f"URL: {finding.url}\n"
                        failure_text += f"Description: {finding.description}\n"
                        if finding.recommendation:
                            failure_text += f"Recommendation: {finding.recommendation}\n"
                        if finding.evidence:
                            failure_text += f"Evidence: {finding.evidence[:500]}\n"
                        failure.text = failure_text
                    else:
                        # LOW/INFO as system-out
                        stdout = SubElement(testcase, "system-out")
                        stdout.text = f"[{finding.severity}] {finding.description}"

            test_count = max(len(result.findings), 1)
            suite.set("tests", str(test_count))
            suite.set("failures", str(failures))
            suite.set("errors", str(errors))

            total_tests += test_count
            total_failures += failures
            total_errors += errors
            total_time += result.duration

        testsuites.set("tests", str(total_tests))
        testsuites.set("failures", str(total_failures))
        testsuites.set("errors", str(total_errors))
        testsuites.set("time", f"{total_time:.2f}")

        # Pretty print XML
        raw_xml = tostring(testsuites, encoding="unicode")
        pretty_xml = xml.dom.minidom.parseString(raw_xml).toprettyxml(indent="  ")
        # Remove extra xml declaration
        lines = pretty_xml.split("\n")
        if lines[0].startswith("<?xml"):
            lines[0] = '<?xml version="1.0" encoding="UTF-8"?>'
        content = "\n".join(lines)

        if output_file:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as f:
                f.write(content)

        return content


# ── JSON Summary Output ──────────────────────────────────────────────

class JSONSummaryGenerator:
    """Generate compact machine-readable JSON summary for CI/CD pipelines."""

    def generate(self, results: list[ScanResult], target: str,
                 output_file: Optional[str] = None) -> str:
        """Generate JSON summary."""
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        summary = {
            "secprobe": {
                "version": "7.0.0",
                "scan_type": "dynamic",
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": sum(r.duration for r in results),
                "scanners_run": len(results),
                "total_findings": len(all_findings),
                "severity_counts": severity_counts,
                "critical_count": severity_counts["CRITICAL"],
                "high_count": severity_counts["HIGH"],
                "pass": severity_counts["CRITICAL"] == 0 and severity_counts["HIGH"] == 0,
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "scanner": f.scanner,
                        "cwe": f.cwe,
                        "url": f.url,
                        "description": f.description,
                        "recommendation": f.recommendation,
                    }
                    for f in all_findings
                    if f.severity in ("CRITICAL", "HIGH", "MEDIUM")
                ],
            }
        }

        content = json.dumps(summary, indent=2)

        if output_file:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as f:
                f.write(content)

        return content


# ── Exit Code Manager ────────────────────────────────────────────────

class ExitCodeManager:
    """
    Determine CI/CD exit codes based on severity thresholds.

    Usage:
        manager = ExitCodeManager(fail_on="medium")
        exit_code = manager.get_exit_code(results)
        # Returns 0 (pass) or 1 (fail)
    """

    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def __init__(self, fail_on: str = "high"):
        """
        Args:
            fail_on: Minimum severity to trigger failure.
                     "critical" | "high" | "medium" | "low" | "info"
        """
        self.threshold = self.SEVERITY_ORDER.get(fail_on.upper(), 3)

    def get_exit_code(self, results: list[ScanResult]) -> int:
        """
        Get exit code for CI/CD.

        Returns:
            0 — No findings above threshold (pass)
            1 — Findings above threshold found (fail)
            2 — Scanner errors occurred
        """
        has_errors = any(r.error for r in results)
        max_severity = 0

        for result in results:
            for finding in result.findings:
                sev = self.SEVERITY_ORDER.get(finding.severity, 0)
                if sev > max_severity:
                    max_severity = sev

        if max_severity >= self.threshold:
            return 1
        if has_errors:
            return 2
        return 0

    def get_summary(self, results: list[ScanResult]) -> dict:
        """Get a summary suitable for CI/CD output."""
        exit_code = self.get_exit_code(results)
        threshold_name = next(
            (k for k, v in self.SEVERITY_ORDER.items() if v == self.threshold),
            "HIGH"
        )
        return {
            "exit_code": exit_code,
            "passed": exit_code == 0,
            "threshold": threshold_name,
            "message": "No findings above threshold" if exit_code == 0
            else "Findings exceed severity threshold" if exit_code == 1
            else "Scanner errors occurred",
        }


# ── GitHub Actions Annotation Output ─────────────────────────────────

class GitHubAnnotationGenerator:
    """
    Generate GitHub Actions workflow annotations.

    Creates ::error:: and ::warning:: annotations that show in PR checks.
    """

    def generate(self, results: list[ScanResult]) -> str:
        """Generate GitHub Actions annotation commands."""
        lines = []
        for result in results:
            for finding in result.findings:
                if finding.severity in ("CRITICAL", "HIGH"):
                    level = "error"
                elif finding.severity == "MEDIUM":
                    level = "warning"
                else:
                    level = "notice"

                # GitHub annotation format
                title = finding.title.replace("\n", " ").replace("\r", "")
                desc = finding.description.replace("\n", " ").replace("\r", "")[:200]
                lines.append(
                    f"::{level} title={title}::"
                    f"[{finding.severity}] {desc}"
                    f"{' | CWE: ' + finding.cwe if finding.cwe else ''}"
                    f"{' | URL: ' + finding.url if finding.url else ''}"
                )

        return "\n".join(lines)
