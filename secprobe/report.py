"""
Report Generator — Enterprise-grade HTML, JSON, SARIF, JUnit, and console reports.

Features:
  - Risk score & grade calculation with severity heatmap
  - Per-scanner breakdown with performance metrics
  - Dark-themed HTML report with CVSS scores, compliance matrix, executive summary
  - Remediation priority matrix with effort estimates
  - Technology fingerprint section
  - CVSS score distribution chart (pure CSS)
  - Machine-readable JSON with full v8 metadata
  - SARIF 2.1.0 for CI/CD (GitHub, GitLab, Azure DevOps)
  - JUnit XML for test frameworks
"""

import json
import math
import os
from collections import Counter
from datetime import datetime
from typing import Optional

from secprobe.models import ScanResult
from secprobe.utils import Colors, severity_color, print_section, print_status


class ReportGenerator:
    """Generate reports in multiple formats from scan results."""

    def __init__(self, results: list[ScanResult], target: str, *,
                 tech_profile=None, scan_duration: float = 0.0,
                 scan_config: dict | None = None):
        self.results = results
        self.target = target
        self.timestamp = datetime.now()
        self.tech_profile = tech_profile
        self.scan_duration = scan_duration
        self.scan_config = scan_config or {}

    def generate(self, fmt: str, output_file: str | None = None):
        """Generate a report in the specified format."""
        if fmt == "json":
            return self._generate_json(output_file)
        elif fmt == "html":
            return self._generate_html(output_file)
        elif fmt == "sarif":
            return self._generate_sarif(output_file)
        elif fmt == "junit":
            return self._generate_junit(output_file)
        else:
            return self._generate_console()

    # ── Console Report ───────────────────────────────────────────────

    def _generate_console(self) -> str:
        print_section("SCAN SUMMARY")
        print(f"  Target:    {Colors.BOLD}{self.target}{Colors.RESET}")
        print(f"  Date:      {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Scanners:  {len(self.results)}")
        if self.scan_duration > 0:
            print(f"  Duration:  {self.scan_duration:.1f}s")

        # Technology fingerprint
        if self.tech_profile:
            tp = self.tech_profile
            parts = []
            if hasattr(tp, 'server') and hasattr(tp.server, 'value') and tp.server.value != "Unknown":
                parts.append(tp.server.value)
            if hasattr(tp, 'language') and hasattr(tp.language, 'value') and tp.language.value != "Unknown":
                parts.append(tp.language.value)
            if hasattr(tp, 'framework') and hasattr(tp.framework, 'value') and tp.framework.value != "Unknown":
                parts.append(tp.framework.value)
            if hasattr(tp, 'waf_detected') and tp.waf_detected:
                parts.append(f"WAF:{getattr(tp, 'waf_name', '?')}")
            if parts:
                print(f"  Stack:     {Colors.CYAN}{' / '.join(parts)}{Colors.RESET}")

        total_findings = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        all_findings = []

        for result in self.results:
            for finding in result.findings:
                total_findings[finding.severity] = total_findings.get(finding.severity, 0) + 1
                all_findings.append(finding)

        total = sum(total_findings.values())
        print(f"\n  {Colors.BOLD}Total Findings: {total}{Colors.RESET}")

        bar_width = 40
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = total_findings[sev]
            if total > 0:
                filled = int(bar_width * count / total)
            else:
                filled = 0
            color = severity_color(sev)
            bar = "█" * filled + "░" * (bar_width - filled)
            print(f"    {color}{sev:<10}{Colors.RESET} [{bar}] {count}")

        # Scanner performance table
        if any(r.duration > 0 for r in self.results):
            print(f"\n  {Colors.BOLD}Scanner Performance:{Colors.RESET}")
            print(f"    {'Scanner':<28} {'Time':>7} {'Findings':>8}")
            print(f"    {'─' * 28} {'─' * 7} {'─' * 8}")
            sorted_results = sorted(self.results, key=lambda r: r.duration, reverse=True)
            for r in sorted_results:
                fc = sum(r.finding_count.values())
                time_color = Colors.RED if r.duration > 30 else Colors.YELLOW if r.duration > 10 else Colors.GREEN
                print(f"    {r.scanner_name:<28} {time_color}{r.duration:>6.1f}s{Colors.RESET} {fc:>8}")

        # Top remediation priorities
        critical_high = [f for f in all_findings if f.severity in ("CRITICAL", "HIGH")]
        if critical_high:
            critical_high.sort(key=lambda f: (0 if f.severity == "CRITICAL" else 1,
                                               -(f.cvss_score or 0)))
            print(f"\n  {Colors.BOLD}Top Remediation Priorities:{Colors.RESET}")
            for i, finding in enumerate(critical_high[:10], 1):
                icon = "🔴" if finding.severity == "CRITICAL" else "🟠"
                color = severity_color(finding.severity)
                cvss_tag = f" CVSS:{finding.cvss_score}" if finding.cvss_score else ""
                cwe_tag = f" {finding.cwe}" if finding.cwe else ""
                print(f"    {icon} {color}{i}. {finding.title}{Colors.RESET}{cvss_tag}{cwe_tag}")
                if finding.recommendation:
                    print(f"       💡 {Colors.GRAY}{finding.recommendation}{Colors.RESET}")

        # Print remaining findings  
        remaining = [f for f in all_findings if f.severity not in ("CRITICAL", "HIGH") and f.severity != "INFO"]
        if remaining:
            print(f"\n  {Colors.BOLD}Other Findings:{Colors.RESET}")
            remaining.sort(key=lambda f: ["MEDIUM", "LOW"].index(f.severity)
                           if f.severity in ["MEDIUM", "LOW"] else 99)
            for finding in remaining[:15]:
                icon = {"MEDIUM": "🟡", "LOW": "🔵"}.get(finding.severity, "•")
                color = severity_color(finding.severity)
                cvss_tag = f" (CVSS {finding.cvss_score})" if finding.cvss_score else ""
                print(f"    {icon} {color}[{finding.severity}]{Colors.RESET} {finding.title}{cvss_tag}")

        # CVSS distribution
        cvss_scores = [f.cvss_score for f in all_findings if f.cvss_score]
        if cvss_scores:
            avg_cvss = sum(cvss_scores) / len(cvss_scores)
            max_cvss = max(cvss_scores)
            print(f"\n  {Colors.BOLD}CVSS Distribution:{Colors.RESET}")
            print(f"    Average: {avg_cvss:.1f}  |  Max: {max_cvss:.1f}  |  Scored: {len(cvss_scores)}/{total}")

        # Compliance summary  
        owasp_cats = Counter(f.owasp_category for f in all_findings if f.owasp_category)
        if owasp_cats:
            print(f"\n  {Colors.BOLD}OWASP Top 10 Coverage:{Colors.RESET}")
            for cat, count in owasp_cats.most_common(10):
                print(f"    {Colors.YELLOW}▸{Colors.RESET} {cat}: {count} finding(s)")

        # Risk score
        score = self._calculate_risk_score(total_findings)
        grade, grade_color = self._risk_grade(score)
        print(f"\n  {Colors.BOLD}Risk Score: {grade_color}{score}/100 (Grade: {grade}){Colors.RESET}")
        print()

        return ""

    # ── JSON Report ──────────────────────────────────────────────────

    def _generate_json(self, output_file: str | None) -> str:
        findings_summary = self._total_findings()
        score = self._calculate_risk_score(findings_summary)
        grade, _ = self._risk_grade(score)

        all_findings = []
        for r in self.results:
            all_findings.extend(r.findings)

        # Build remediation priorities
        remediation = []
        critical_high = sorted(
            [f for f in all_findings if f.severity in ("CRITICAL", "HIGH")],
            key=lambda f: (0 if f.severity == "CRITICAL" else 1, -(f.cvss_score or 0))
        )
        for i, f in enumerate(critical_high, 1):
            remediation.append({
                "priority": i,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cwe": f.cwe,
                "recommendation": f.recommendation,
                "url": f.url,
            })

        # CVSS distribution
        cvss_scores = [f.cvss_score for f in all_findings if f.cvss_score]
        cvss_dist = {}
        if cvss_scores:
            cvss_dist = {
                "average": round(sum(cvss_scores) / len(cvss_scores), 1),
                "max": max(cvss_scores),
                "min": min(cvss_scores),
                "scored_count": len(cvss_scores),
                "total_count": len(all_findings),
            }

        # Compliance mapping
        owasp_map = {}
        cwe_list = []
        for f in all_findings:
            if f.owasp_category:
                owasp_map.setdefault(f.owasp_category, []).append(f.title)
            if f.cwe:
                cwe_list.append(f.cwe)

        # Technology fingerprint
        tech_data = {}
        if self.tech_profile:
            tp = self.tech_profile
            tech_data = {
                "server": getattr(tp.server, 'value', str(tp.server)) if hasattr(tp, 'server') else "",
                "language": getattr(tp.language, 'value', str(tp.language)) if hasattr(tp, 'language') else "",
                "framework": getattr(tp.framework, 'value', str(tp.framework)) if hasattr(tp, 'framework') else "",
                "waf_detected": getattr(tp, 'waf_detected', False),
                "waf_name": getattr(tp, 'waf_name', ""),
                "confidence": getattr(tp, 'confidence', 0),
            }

        report = {
            "secprobe_report": {
                "version": "7.0.0",
                "target": self.target,
                "timestamp": self.timestamp.isoformat(),
                "scan_duration_seconds": self.scan_duration,
                "risk_score": score,
                "risk_grade": grade,
                "executive_summary": {
                    "total_findings": sum(findings_summary.values()),
                    "severity_breakdown": findings_summary,
                    "critical_count": findings_summary.get("CRITICAL", 0),
                    "high_count": findings_summary.get("HIGH", 0),
                    "scanners_run": len(self.results),
                    "risk_assessment": self._risk_assessment(score, findings_summary),
                },
                "technology_fingerprint": tech_data,
                "cvss_distribution": cvss_dist,
                "remediation_priorities": remediation,
                "compliance": {
                    "owasp_top_10": owasp_map,
                    "unique_cwes": sorted(set(cwe_list)),
                },
                "scanner_performance": [
                    {
                        "name": r.scanner_name,
                        "duration_seconds": r.duration,
                        "findings": r.finding_count,
                        "error": r.error,
                    }
                    for r in self.results
                ],
                "scanners": [r.to_dict() for r in self.results],
            }
        }

        content = json.dumps(report, indent=2, default=str)

        if output_file:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as f:
                f.write(content)
            print_status(f"JSON report saved to {output_file}", "success")
        return content

    # ── HTML Report ──────────────────────────────────────────────────

    def _generate_html(self, output_file: str | None) -> str:
        findings = self._total_findings()
        score = self._calculate_risk_score(findings)
        grade, _ = self._risk_grade(score)

        all_findings = []
        for result in self.results:
            for f in result.findings:
                all_findings.append(f)

        all_findings.sort(key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f.severity)
                          if f.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else 99)

        total = sum(findings.values())

        # ── Technology fingerprint HTML ──
        tech_html = ""
        if self.tech_profile:
            tp = self.tech_profile
            tech_items = []
            if hasattr(tp, 'server') and hasattr(tp.server, 'value') and tp.server.value != "Unknown":
                tech_items.append(("Server", tp.server.value))
            if hasattr(tp, 'language') and hasattr(tp.language, 'value') and tp.language.value != "Unknown":
                tech_items.append(("Language", tp.language.value))
            if hasattr(tp, 'framework') and hasattr(tp.framework, 'value') and tp.framework.value != "Unknown":
                tech_items.append(("Framework", tp.framework.value))
            if hasattr(tp, 'waf_detected') and tp.waf_detected:
                tech_items.append(("WAF", getattr(tp, 'waf_name', 'Detected')))
            if hasattr(tp, 'js_frameworks') and tp.js_frameworks:
                tech_items.append(("JS Frameworks", ", ".join(tp.js_frameworks)))
            if hasattr(tp, 'cms') and tp.cms:
                tech_items.append(("CMS", tp.cms))

            if tech_items:
                confidence = getattr(tp, 'confidence', 0)
                tech_rows = "".join(
                    f'<tr><td class="tech-label">{self._escape_html(k)}</td>'
                    f'<td>{self._escape_html(v)}</td></tr>'
                    for k, v in tech_items
                )
                tech_html = f"""
    <h2>🔍 Technology Fingerprint <span class="confidence-badge">{confidence:.0%} confidence</span></h2>
    <table class="tech-table"><tbody>{tech_rows}</tbody></table>"""

        # ── Executive summary HTML ──
        risk_text = self._risk_assessment(score, findings)
        duration_text = f" in {self.scan_duration:.1f} seconds" if self.scan_duration > 0 else ""
        exec_html = f"""
    <h2>📋 Executive Summary</h2>
    <div class="exec-summary">
        <p>A security assessment of <strong>{self._escape_html(self.target)}</strong> was conducted
           on {self.timestamp.strftime('%B %d, %Y')} using {len(self.results)} scanner modules{duration_text}.</p>
        <p>The scan identified <strong>{total} findings</strong> across {len(self.results)} scanners,
           including <span class="text-critical">{findings['CRITICAL']} critical</span> and
           <span class="text-high">{findings['HIGH']} high</span> severity issues.</p>
        <p class="risk-text">{self._escape_html(risk_text)}</p>
    </div>"""

        # ── CVSS distribution HTML ──
        cvss_scores = [f.cvss_score for f in all_findings if f.cvss_score]
        cvss_html = ""
        if cvss_scores:
            avg_cvss = sum(cvss_scores) / len(cvss_scores)
            max_cvss = max(cvss_scores)
            # Build distribution buckets: 0-1, 1-2, ..., 9-10
            buckets = [0] * 10
            for s in cvss_scores:
                idx = min(int(s), 9)
                buckets[idx] += 1
            max_bucket = max(buckets) if buckets else 1
            bars = ""
            for i, count in enumerate(buckets):
                height = int(80 * count / max_bucket) if max_bucket > 0 else 0
                label = f"{i}-{i+1}"
                sev_class = "info" if i < 4 else "medium" if i < 7 else "high" if i < 9 else "critical"
                bars += f"""<div class="dist-col">
                    <div class="dist-bar bar-{sev_class}" style="height:{height}px"></div>
                    <div class="dist-label">{label}</div>
                    <div class="dist-count">{count}</div>
                </div>"""
            cvss_html = f"""
    <h2>📊 CVSS Score Distribution</h2>
    <div class="cvss-stats">
        <span>Average: <strong>{avg_cvss:.1f}</strong></span>
        <span>Maximum: <strong>{max_cvss:.1f}</strong></span>
        <span>Scored: <strong>{len(cvss_scores)}/{total}</strong></span>
    </div>
    <div class="dist-chart">{bars}</div>"""

        # ── Remediation priority matrix ──
        critical_high = [f for f in all_findings if f.severity in ("CRITICAL", "HIGH")]
        critical_high.sort(key=lambda f: (0 if f.severity == "CRITICAL" else 1, -(f.cvss_score or 0)))
        remediation_html = ""
        if critical_high:
            rows = ""
            for i, f in enumerate(critical_high[:20], 1):
                sev_class = f.severity.lower()
                cvss_val = f'{f.cvss_score:.1f}' if f.cvss_score else "—"
                rows += f"""<tr>
                    <td>{i}</td>
                    <td><span class="badge badge-{sev_class}">{f.severity}</span></td>
                    <td>{self._escape_html(f.title)}</td>
                    <td>{cvss_val}</td>
                    <td>{self._escape_html(f.cwe) if f.cwe else '—'}</td>
                    <td class="rec">{self._escape_html(f.recommendation) if f.recommendation else '—'}</td>
                </tr>"""
            remediation_html = f"""
    <h2>🎯 Remediation Priorities</h2>
    <table>
        <thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>CVSS</th><th>CWE</th><th>Recommendation</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""

        # ── Compliance matrix ──
        owasp_counts = Counter(f.owasp_category for f in all_findings if f.owasp_category)
        cwe_counts = Counter(f.cwe for f in all_findings if f.cwe)
        compliance_html = ""
        if owasp_counts or cwe_counts:
            sections = ""
            if owasp_counts:
                owasp_rows = "".join(
                    f'<tr><td>{self._escape_html(cat)}</td><td>{count}</td></tr>'
                    for cat, count in owasp_counts.most_common()
                )
                sections += f"""
                <div class="compliance-block">
                    <h3>OWASP Top 10</h3>
                    <table><thead><tr><th>Category</th><th>Findings</th></tr></thead>
                    <tbody>{owasp_rows}</tbody></table>
                </div>"""
            if cwe_counts:
                cwe_rows = "".join(
                    f'<tr><td>{self._escape_html(cwe)}</td><td>{count}</td></tr>'
                    for cwe, count in cwe_counts.most_common(15)
                )
                sections += f"""
                <div class="compliance-block">
                    <h3>Top CWEs</h3>
                    <table><thead><tr><th>CWE</th><th>Findings</th></tr></thead>
                    <tbody>{cwe_rows}</tbody></table>
                </div>"""
            compliance_html = f"""
    <h2>📜 Compliance Mapping</h2>
    <div class="compliance-grid">{sections}</div>"""

        # ── Per-finding cards ──
        findings_html = ""
        for f in all_findings:
            sev_class = f.severity.lower()
            cvss_html_tag = f'<span class="cvss-badge">CVSS {f.cvss_score}</span>' if f.cvss_score else ""
            cwe_html_tag = f'<span class="cwe-badge">{self._escape_html(f.cwe)}</span>' if f.cwe else ""
            owasp_html_tag = f'<span class="owasp-badge">{self._escape_html(f.owasp_category)}</span>' if f.owasp_category else ""
            pci_html = ""
            if hasattr(f, 'pci_dss') and f.pci_dss:
                pci_items = ", ".join(f.pci_dss)
                pci_html = f'<span class="pci-badge">PCI: {self._escape_html(pci_items)}</span>'
            findings_html += f"""
            <div class="finding {sev_class}">
                <div class="finding-header">
                    <span class="badge badge-{sev_class}">{f.severity}</span>
                    {cvss_html_tag}
                    <strong>{self._escape_html(f.title)}</strong>
                    <span class="category">{self._escape_html(f.category)}</span>
                </div>
                <div class="finding-tags">{cwe_html_tag}{owasp_html_tag}{pci_html}</div>
                <p>{self._escape_html(f.description)}</p>
                {"<p class='recommendation'>💡 " + self._escape_html(f.recommendation) + "</p>" if f.recommendation else ""}
                {"<pre class='evidence'>" + self._escape_html(f.evidence) + "</pre>" if f.evidence else ""}
                {"<div class='finding-url'>🔗 " + self._escape_html(f.url) + "</div>" if f.url else ""}
            </div>"""

        # ── Scanner summary table ──
        scanner_summary_html = ""
        total_duration = sum(r.duration for r in self.results)
        for r in sorted(self.results, key=lambda x: x.duration, reverse=True):
            counts = r.finding_count
            status = "✓" if not r.error else "✗"
            pct = (r.duration / total_duration * 100) if total_duration > 0 else 0
            scanner_summary_html += f"""
            <tr>
                <td>{status} {self._escape_html(r.scanner_name)}</td>
                <td>{r.duration:.1f}s <span class="pct">({pct:.0f}%)</span></td>
                <td><span class="badge badge-critical">{counts['CRITICAL']}</span></td>
                <td><span class="badge badge-high">{counts['HIGH']}</span></td>
                <td><span class="badge badge-medium">{counts['MEDIUM']}</span></td>
                <td><span class="badge badge-low">{counts['LOW']}</span></td>
                <td><span class="badge badge-info">{counts['INFO']}</span></td>
            </tr>"""

        grade_class = grade.replace("+", "plus").replace("-", "minus").lower()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecProbe Security Report — {self._escape_html(self.target)}</title>
    <style>
        :root {{
            --bg: #0d1117; --surface: #161b22; --border: #30363d;
            --text: #c9d1d9; --text-muted: #8b949e;
            --critical: #f85149; --high: #f0883e; --medium: #d29922;
            --low: #58a6ff; --info: #79c0ff; --success: #3fb950;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
               background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        h2 {{ font-size: 1.4rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
        h3 {{ font-size: 1.1rem; margin: 1rem 0 0.5rem; color: var(--text); }}
        .meta {{ color: var(--text-muted); margin-bottom: 2rem; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 1rem 0; }}
        .summary-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }}
        .summary-card .number {{ font-size: 2rem; font-weight: bold; }}
        .summary-card.critical .number {{ color: var(--critical); }}
        .summary-card.high .number {{ color: var(--high); }}
        .summary-card.medium .number {{ color: var(--medium); }}
        .summary-card.low .number {{ color: var(--low); }}
        .summary-card.info .number {{ color: var(--info); }}
        .summary-card.score .number {{ font-size: 2.5rem; }}
        .grade {{ font-size: 1.2rem; margin-top: 0.3rem; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; margin-bottom: 1rem; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: #1c2128; font-weight: 600; }}
        td.rec {{ font-size: 0.85rem; color: var(--success); max-width: 300px; }}
        .pct {{ color: var(--text-muted); font-size: 0.8rem; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
        .badge-critical {{ background: var(--critical); color: #fff; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #000; }}
        .badge-info {{ background: var(--info); color: #000; }}
        .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; }}
        .finding.critical {{ border-left: 4px solid var(--critical); }}
        .finding.high {{ border-left: 4px solid var(--high); }}
        .finding.medium {{ border-left: 4px solid var(--medium); }}
        .finding.low {{ border-left: 4px solid var(--low); }}
        .finding.info {{ border-left: 4px solid var(--info); }}
        .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; flex-wrap: wrap; }}
        .finding p {{ color: var(--text-muted); margin: 0.3rem 0; }}
        .finding-url {{ color: var(--low); font-size: 0.8rem; margin-top: 0.3rem; word-break: break-all; }}
        .recommendation {{ color: var(--success) !important; font-style: italic; }}
        .evidence {{ background: #1c2128; padding: 0.75rem; border-radius: 4px; font-size: 0.85rem;
                     overflow-x: auto; color: var(--text-muted); margin-top: 0.5rem; white-space: pre-wrap; }}
        .category {{ color: var(--text-muted); font-size: 0.8rem; margin-left: auto; }}
        .cvss-badge {{ background: #7c3aed; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
        .cwe-badge {{ background: #1e40af; color: #93c5fd; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; margin-right: 0.4rem; }}
        .owasp-badge {{ background: #065f46; color: #6ee7b7; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; margin-right: 0.4rem; }}
        .pci-badge {{ background: #713f12; color: #fbbf24; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; }}
        .finding-tags {{ margin: 0.3rem 0; display: flex; gap: 0.4rem; flex-wrap: wrap; }}
        /* Executive summary */
        .exec-summary {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }}
        .exec-summary p {{ margin: 0.5rem 0; }}
        .text-critical {{ color: var(--critical); font-weight: 600; }}
        .text-high {{ color: var(--high); font-weight: 600; }}
        .risk-text {{ color: var(--text-muted); font-style: italic; margin-top: 0.75rem !important; padding-top: 0.75rem;
                      border-top: 1px solid var(--border); }}
        /* Technology table */
        .tech-table {{ max-width: 500px; }}
        .tech-label {{ font-weight: 600; width: 140px; color: var(--info); }}
        .confidence-badge {{ font-size: 0.75rem; background: #1e40af; color: #93c5fd; padding: 2px 10px;
                             border-radius: 12px; margin-left: 0.5rem; font-weight: normal; }}
        /* CVSS distribution */
        .cvss-stats {{ display: flex; gap: 2rem; margin: 0.5rem 0 1rem; color: var(--text-muted); }}
        .dist-chart {{ display: flex; align-items: flex-end; gap: 4px; height: 100px; padding: 0.5rem 0; }}
        .dist-col {{ display: flex; flex-direction: column; align-items: center; flex: 1; }}
        .dist-bar {{ width: 100%; min-height: 2px; border-radius: 3px 3px 0 0; }}
        .bar-info {{ background: var(--info); }}
        .bar-medium {{ background: var(--medium); }}
        .bar-high {{ background: var(--high); }}
        .bar-critical {{ background: var(--critical); }}
        .dist-label {{ font-size: 0.65rem; color: var(--text-muted); margin-top: 4px; }}
        .dist-count {{ font-size: 0.7rem; color: var(--text); }}
        /* Compliance */
        .compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1.5rem; }}
        .compliance-block {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
        .compliance-block table {{ margin: 0; }}
        .footer {{ text-align: center; color: var(--text-muted); margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ SecProbe Security Report</h1>
    <p class="meta">
        Target: <strong>{self._escape_html(self.target)}</strong> &nbsp;|&nbsp;
        Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
        Scanners: {len(self.results)}
        {"&nbsp;|&nbsp; Duration: " + f"{self.scan_duration:.1f}s" if self.scan_duration > 0 else ""}
    </p>

    <div class="summary-grid">
        <div class="summary-card score">
            <div class="number">{score}</div>
            <div>Risk Score</div>
            <div class="grade">Grade: {grade}</div>
        </div>
        <div class="summary-card critical">
            <div class="number">{findings['CRITICAL']}</div>
            <div>Critical</div>
        </div>
        <div class="summary-card high">
            <div class="number">{findings['HIGH']}</div>
            <div>High</div>
        </div>
        <div class="summary-card medium">
            <div class="number">{findings['MEDIUM']}</div>
            <div>Medium</div>
        </div>
        <div class="summary-card low">
            <div class="number">{findings['LOW']}</div>
            <div>Low</div>
        </div>
        <div class="summary-card info">
            <div class="number">{findings['INFO']}</div>
            <div>Info</div>
        </div>
    </div>

    {exec_html}

    {tech_html}

    {cvss_html}

    {remediation_html}

    <h2>⚡ Scanner Performance</h2>
    <table>
        <thead>
            <tr><th>Scanner</th><th>Duration</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
        </thead>
        <tbody>
            {scanner_summary_html}
        </tbody>
    </table>

    {compliance_html}

    <h2>📝 All Findings ({total})</h2>
    {findings_html}

    <div class="footer">
        Generated by SecProbe v7.0.0 — Enterprise Security Testing Toolkit
    </div>
</div>
</body>
</html>"""

        if output_file:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as f:
                f.write(html)
            print_status(f"HTML report saved to {output_file}", "success")
        return html

    # ── SARIF Report ───────────────────────────────────────────────

    def _generate_sarif(self, output_file: str | None) -> str:
        """Generate SARIF 2.1.0 report for CI/CD integration."""
        try:
            from secprobe.core.cicd import SARIFGenerator
            generator = SARIFGenerator()
            content = generator.generate(self.results, self.target)
        except ImportError:
            # Fallback inline SARIF if cicd module not available
            content = self._generate_sarif_fallback()

        if output_file:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as f:
                f.write(content)
            print_status(f"SARIF report saved to {output_file}", "success")
        return content

    def _generate_sarif_fallback(self) -> str:
        """Minimal SARIF generation without cicd module."""
        all_findings = []
        for result in self.results:
            all_findings.extend(result.findings)

        rules = []
        results_list = []
        rule_ids = set()

        for i, f in enumerate(all_findings):
            rule_id = f.cwe or f"secprobe-{i}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                                  "LOW": "note", "INFO": "note"}.get(f.severity, "note")
                    },
                })

            result_entry = {
                "ruleId": rule_id,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                          "LOW": "note", "INFO": "note"}.get(f.severity, "note"),
                "message": {"text": f.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
            }
            if f.cvss_score:
                result_entry["properties"] = {
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                }
            results_list.append(result_entry)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SecProbe",
                        "version": "7.0.0",
                        "informationUri": "https://github.com/secprobe/secprobe",
                        "rules": rules,
                    }
                },
                "results": results_list,
            }],
        }
        return json.dumps(sarif, indent=2)

    # ── JUnit Report ─────────────────────────────────────────────

    def _generate_junit(self, output_file: str | None) -> str:
        """Generate JUnit XML report for test frameworks."""
        try:
            from secprobe.core.cicd import JUnitGenerator
            generator = JUnitGenerator()
            content = generator.generate(self.results, self.target)
        except ImportError:
            content = self._generate_junit_fallback()

        if output_file:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as f:
                f.write(content)
            print_status(f"JUnit report saved to {output_file}", "success")
        return content

    def _generate_junit_fallback(self) -> str:
        """Minimal JUnit generation without cicd module."""
        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        total_findings = sum(len(r.findings) for r in self.results)
        total_failures = sum(
            1 for r in self.results for f in r.findings
            if f.severity in ("CRITICAL", "HIGH", "MEDIUM")
        )
        lines.append(f'<testsuites tests="{total_findings}" failures="{total_failures}" '
                     f'name="SecProbe Security Scan">')

        for result in self.results:
            failures = sum(1 for f in result.findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM"))
            lines.append(f'  <testsuite name="{result.scanner_name}" '
                        f'tests="{len(result.findings)}" failures="{failures}" '
                        f'time="{result.duration:.1f}">')
            for finding in result.findings:
                test_name = finding.title.replace('"', '&quot;')
                if finding.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                    lines.append(f'    <testcase name="{test_name}" classname="{result.scanner_name}">')
                    lines.append(f'      <failure message="{test_name}" type="{finding.severity}">')
                    lines.append(f'        {finding.description}')
                    lines.append(f'      </failure>')
                    lines.append(f'    </testcase>')
                else:
                    lines.append(f'    <testcase name="{test_name}" classname="{result.scanner_name}" />')
            lines.append('  </testsuite>')

        lines.append('</testsuites>')
        return '\n'.join(lines)

    # ── Helpers ──────────────────────────────────────────────────────

    def _total_findings(self) -> dict:
        totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in self.results:
            for sev, count in r.finding_count.items():
                totals[sev] = totals.get(sev, 0) + count
        return totals

    def _calculate_risk_score(self, findings: dict) -> int:
        """Calculate 0-100 risk score (higher = more risky)."""
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        score = sum(findings.get(sev, 0) * w for sev, w in weights.items())
        return min(score, 100)

    def _risk_grade(self, score: int) -> tuple[str, str]:
        if score == 0:
            return "A+", Colors.GREEN
        elif score <= 10:
            return "A", Colors.GREEN
        elif score <= 25:
            return "B", Colors.CYAN
        elif score <= 40:
            return "C", Colors.YELLOW
        elif score <= 60:
            return "D", Colors.YELLOW
        elif score <= 80:
            return "E", Colors.RED
        else:
            return "F", Colors.RED

    def _risk_assessment(self, score: int, findings: dict) -> str:
        """Generate a human-readable risk assessment paragraph."""
        grade, _ = self._risk_grade(score)
        total = sum(findings.values())
        crits = findings.get("CRITICAL", 0)
        highs = findings.get("HIGH", 0)

        if score == 0:
            return ("No security vulnerabilities were identified. The target demonstrates "
                    "strong security posture. Continue regular assessments to maintain this status.")
        elif score <= 10:
            return (f"The target has a low risk profile (Grade {grade}) with {total} findings. "
                    "Minor informational or low-severity items should be addressed during regular maintenance.")
        elif score <= 40:
            return (f"The target has a moderate risk profile (Grade {grade}) with {total} findings "
                    f"including {highs} high-severity issue(s). "
                    "Remediation of high-severity findings is recommended within the next sprint cycle.")
        elif score <= 60:
            return (f"The target has an elevated risk profile (Grade {grade}) with {total} findings "
                    f"including {crits} critical and {highs} high-severity issue(s). "
                    "Immediate remediation of critical findings is strongly recommended.")
        else:
            return (f"The target has a critical risk profile (Grade {grade}) with {total} findings "
                    f"including {crits} critical and {highs} high-severity issue(s). "
                    "URGENT: Critical vulnerabilities require immediate remediation. "
                    "Consider taking affected services offline until issues are resolved.")

    @staticmethod
    def _escape_html(text: str) -> str:
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))
