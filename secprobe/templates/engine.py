"""
YAML Vulnerability Template Engine — Nuclei-style extensible checks.

Templates define:
  - HTTP requests to send (method, path, headers, body)
  - Matchers: status codes, body strings, regex, header values
  - Extractors: pull data from responses for chaining
  - Severity classification and metadata

This allows users to write their own vulnerability checks in YAML
without touching Python code.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from secprobe.core.exceptions import TemplateError, TemplateParseError, TemplateExecutionError
from secprobe.models import Finding


# ─────────────────────────────────────────────────────────────────
# Template Data Models
# ─────────────────────────────────────────────────────────────────

@dataclass
class RequestSpec:
    """A single HTTP request defined in a template."""
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    follow_redirects: bool = True
    raw: str = ""  # Raw HTTP request (advanced)


@dataclass
class Matcher:
    """Condition that must be true for the template to match."""
    type: str  # "status", "body", "header", "regex", "word", "dsl"
    values: list[str] = field(default_factory=list)
    condition: str = "or"  # "or" | "and"
    negative: bool = False
    part: str = "body"  # "body", "header", "all", "status"


@dataclass
class Extractor:
    """Extracts data from responses for reporting or chaining."""
    type: str  # "regex", "kval" (key-value), "json", "xpath"
    name: str = ""
    values: list[str] = field(default_factory=list)
    part: str = "body"
    group: int = 0  # Regex capture group


@dataclass
class VulnTemplate:
    """A complete vulnerability check template."""
    template_id: str
    name: str
    author: str = "secprobe"
    severity: str = "Info"
    description: str = ""
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    requests: list[RequestSpec] = field(default_factory=list)
    matchers: list[Matcher] = field(default_factory=list)
    matchers_condition: str = "and"  # "and" | "or"
    extractors: list[Extractor] = field(default_factory=list)
    remediation: str = ""
    cve: str = ""
    cwe: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def file_path(self) -> Optional[str]:
        return self.metadata.get("_file_path")

    def to_dict(self) -> dict:
        return {
            "id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "cve": self.cve,
            "tags": self.tags,
            "reference": self.reference,
        }


@dataclass
class TemplateResult:
    """Result of executing a template against a target."""
    template: VulnTemplate
    matched: bool
    target: str
    extracted: dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)

    def to_finding(self) -> Optional[Finding]:
        """Convert a matched result to a Finding."""
        if not self.matched:
            return None
        details = self.template.description
        if self.extracted:
            details += "\nExtracted data:\n"
            for k, v in self.extracted.items():
                details += f"  {k}: {v}\n"
        if self.template.reference:
            details += "\nReferences:\n"
            for ref in self.template.reference:
                details += f"  - {ref}\n"

        return Finding(
            title=f"[{self.template.template_id}] {self.template.name}",
            severity=self.template.severity,
            description=details,
            recommendation=self.template.remediation,
            url=self.target,
            evidence=f"Status: {self.response_status}",
            scanner="template",
            cwe=", ".join(self.template.cwe) if self.template.cwe else "",
        )


# ─────────────────────────────────────────────────────────────────
# Template Parser (YAML → VulnTemplate)
# ─────────────────────────────────────────────────────────────────

class TemplateParser:
    """Parses YAML template files into VulnTemplate objects."""

    def parse_file(self, path: str | Path) -> VulnTemplate:
        """Parse a single YAML template file."""
        path = Path(path)
        if not path.exists():
            raise TemplateParseError(f"Template file not found: {path}")

        try:
            import yaml
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except ImportError:
            data = self._parse_simple_yaml(path)
        except Exception as e:
            raise TemplateParseError(f"Failed to parse {path}: {e}")

        if not isinstance(data, dict):
            raise TemplateParseError(f"Template must be a YAML dict: {path}")

        template = self._build_template(data)
        template.metadata["_file_path"] = str(path)
        return template

    def parse_directory(self, directory: str | Path) -> list[VulnTemplate]:
        """Parse all YAML templates in a directory (recursive)."""
        directory = Path(directory)
        templates = []

        if not directory.exists():
            return templates

        for yaml_file in sorted(directory.rglob("*.yaml")):
            try:
                templates.append(self.parse_file(yaml_file))
            except TemplateParseError:
                continue  # Skip broken templates

        for yml_file in sorted(directory.rglob("*.yml")):
            try:
                templates.append(self.parse_file(yml_file))
            except TemplateParseError:
                continue

        return templates

    def _build_template(self, data: dict) -> VulnTemplate:
        """Build a VulnTemplate from parsed YAML data."""
        info = data.get("info", data)

        template = VulnTemplate(
            template_id=data.get("id", "unknown"),
            name=info.get("name", "Unnamed Template"),
            author=info.get("author", "unknown"),
            severity=info.get("severity", "Info"),
            description=info.get("description", ""),
            reference=self._as_list(info.get("reference", [])),
            tags=self._as_list(info.get("tags", [])),
            remediation=info.get("remediation", ""),
            cve=info.get("cve", ""),
            cwe=self._as_list(info.get("cwe", [])),
            metadata=info.get("metadata", {}),
        )

        # Parse requests
        for req_data in self._as_list(data.get("requests", data.get("http", []))):
            if isinstance(req_data, dict):
                template.requests.append(self._parse_request(req_data))

        # Parse matchers
        matchers_data = data.get("matchers", [])
        if not matchers_data and template.requests:
            # Check matchers inside requests
            for req_data in self._as_list(data.get("requests", data.get("http", []))):
                if isinstance(req_data, dict):
                    matchers_data.extend(req_data.get("matchers", []))

        for matcher_data in self._as_list(matchers_data):
            if isinstance(matcher_data, dict):
                template.matchers.append(self._parse_matcher(matcher_data))

        template.matchers_condition = data.get("matchers-condition", "and")

        # Parse extractors
        extractors_data = data.get("extractors", [])
        if not extractors_data and template.requests:
            for req_data in self._as_list(data.get("requests", data.get("http", []))):
                if isinstance(req_data, dict):
                    extractors_data.extend(req_data.get("extractors", []))

        for ext_data in self._as_list(extractors_data):
            if isinstance(ext_data, dict):
                template.extractors.append(self._parse_extractor(ext_data))

        return template

    def _parse_request(self, data: dict) -> RequestSpec:
        method = data.get("method", "GET").upper()
        paths = self._as_list(data.get("path", data.get("paths", ["/"])))
        path = paths[0] if paths else "/"
        headers = data.get("headers", {})
        body = data.get("body", "")
        follow = data.get("redirects", data.get("follow-redirects", True))
        raw = data.get("raw", "")

        return RequestSpec(
            method=method,
            path=path,
            headers=headers if isinstance(headers, dict) else {},
            body=str(body),
            follow_redirects=bool(follow),
            raw=str(raw) if raw else "",
        )

    def _parse_matcher(self, data: dict) -> Matcher:
        return Matcher(
            type=data.get("type", "word"),
            values=self._as_list(data.get("words", data.get("status", data.get("regex", [])))),
            condition=data.get("condition", "or"),
            negative=data.get("negative", False),
            part=data.get("part", "body"),
        )

    def _parse_extractor(self, data: dict) -> Extractor:
        return Extractor(
            type=data.get("type", "regex"),
            name=data.get("name", ""),
            values=self._as_list(data.get("regex", data.get("kval", data.get("json", [])))),
            part=data.get("part", "body"),
            group=data.get("group", 0),
        )

    @staticmethod
    def _as_list(val: Any) -> list:
        if val is None:
            return []
        if isinstance(val, list):
            return val
        if isinstance(val, str) and "," in val:
            return [v.strip() for v in val.split(",") if v.strip()]
        return [val]

    @staticmethod
    def _parse_simple_yaml(path: Path) -> dict:
        """Fallback minimal parser when PyYAML is not installed."""
        data: dict = {}
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip()
                    val = val.strip()
                    if val:
                        data[key] = val
        return data


# ─────────────────────────────────────────────────────────────────
# Template Executor
# ─────────────────────────────────────────────────────────────────

class TemplateEngine:
    """Loads, manages, and executes vulnerability templates."""

    def __init__(self, template_dirs: Optional[list[str | Path]] = None):
        self.parser = TemplateParser()
        self.templates: list[VulnTemplate] = []

        # Load built-in templates
        builtin_dir = Path(__file__).parent / "cves"
        if builtin_dir.exists():
            self.templates.extend(self.parser.parse_directory(builtin_dir))

        misconfig_dir = Path(__file__).parent / "misconfigs"
        if misconfig_dir.exists():
            self.templates.extend(self.parser.parse_directory(misconfig_dir))

        # Load user-supplied template directories
        for d in (template_dirs or []):
            self.templates.extend(self.parser.parse_directory(d))

    def load_template(self, path: str | Path) -> VulnTemplate:
        """Load a single template file."""
        t = self.parser.parse_file(path)
        self.templates.append(t)
        return t

    def load_directory(self, directory: str | Path) -> int:
        """Load all templates from a directory. Returns count loaded."""
        new = self.parser.parse_directory(directory)
        self.templates.extend(new)
        return len(new)

    def filter_templates(
        self,
        tags: Optional[list[str]] = None,
        severity: Optional[list[str]] = None,
        ids: Optional[list[str]] = None,
    ) -> list[VulnTemplate]:
        """Filter templates by tags, severity, or ID."""
        result = self.templates
        if tags:
            tag_set = {t.lower() for t in tags}
            result = [t for t in result if tag_set.intersection(t_.lower() for t_ in t.tags)]
        if severity:
            sev_set = {s.lower() for s in severity}
            result = [t for t in result if t.severity.lower() in sev_set]
        if ids:
            id_set = {i.lower() for i in ids}
            result = [t for t in result if t.template_id.lower() in id_set]
        return result

    def execute(
        self,
        template: VulnTemplate,
        target: str,
        http_client=None,
    ) -> TemplateResult:
        """Execute a single template against a target.
        
        Args:
            template: The template to execute
            target: Base URL of the target
            http_client: Optional HTTPClient instance (from core.http_client)
        """
        try:
            import requests as _requests
        except ImportError:
            raise TemplateExecutionError("requests library required for template execution")

        result = TemplateResult(
            template=template,
            matched=False,
            target=target,
        )

        target = target.rstrip("/")

        for req_spec in template.requests:
            try:
                url = target + req_spec.path

                if http_client is not None:
                    resp = http_client.request(
                        method=req_spec.method,
                        url=url,
                        headers=req_spec.headers or None,
                        data=req_spec.body or None,
                    )
                else:
                    resp = _requests.request(
                        method=req_spec.method,
                        url=url,
                        headers=req_spec.headers or None,
                        data=req_spec.body or None,
                        allow_redirects=req_spec.follow_redirects,
                        verify=False,
                        timeout=10,
                    )

                result.response_status = resp.status_code
                result.response_body = resp.text[:50000]  # Cap at 50KB
                result.response_headers = dict(resp.headers)

                # Evaluate matchers
                matched = self._evaluate_matchers(template, result)
                result.matched = matched

                # Run extractors if matched
                if matched:
                    result.extracted = self._run_extractors(template, result)

            except Exception:
                continue  # Request failed — template doesn't match

        return result

    def execute_all(
        self,
        target: str,
        http_client=None,
        tags: Optional[list[str]] = None,
        severity: Optional[list[str]] = None,
    ) -> list[TemplateResult]:
        """Execute all (or filtered) templates against a target.
        
        Returns only matched results.
        """
        templates = self.filter_templates(tags=tags, severity=severity) if (tags or severity) else self.templates
        results = []

        for template in templates:
            result = self.execute(template, target, http_client)
            if result.matched:
                results.append(result)

        return results

    def _evaluate_matchers(self, template: VulnTemplate, result: TemplateResult) -> bool:
        """Evaluate all matchers against a response."""
        if not template.matchers:
            # No matchers = match on non-error status
            return 200 <= result.response_status < 400

        matcher_results = []
        for matcher in template.matchers:
            match = self._evaluate_single_matcher(matcher, result)
            matcher_results.append(match)

        if template.matchers_condition == "and":
            return all(matcher_results)
        else:  # "or"
            return any(matcher_results)

    def _evaluate_single_matcher(self, matcher: Matcher, result: TemplateResult) -> bool:
        """Evaluate a single matcher."""
        matched = False

        # Get the response part to match against
        if matcher.part == "status":
            content = str(result.response_status)
        elif matcher.part == "header":
            content = "\n".join(f"{k}: {v}" for k, v in result.response_headers.items())
        elif matcher.part == "all":
            header_str = "\n".join(f"{k}: {v}" for k, v in result.response_headers.items())
            content = header_str + "\n\n" + result.response_body
        else:
            content = result.response_body

        if matcher.type == "status":
            matched = any(str(result.response_status) == str(v) for v in matcher.values)

        elif matcher.type == "word":
            if matcher.condition == "and":
                matched = all(str(v) in content for v in matcher.values)
            else:
                matched = any(str(v) in content for v in matcher.values)

        elif matcher.type == "regex":
            for pattern in matcher.values:
                try:
                    if re.search(str(pattern), content, re.IGNORECASE | re.DOTALL):
                        matched = True
                        if matcher.condition == "or":
                            break
                except re.error:
                    continue
            if matcher.condition == "and":
                matched = all(
                    bool(re.search(str(p), content, re.IGNORECASE | re.DOTALL))
                    for p in matcher.values
                )

        elif matcher.type == "body":
            if matcher.condition == "and":
                matched = all(str(v) in content for v in matcher.values)
            else:
                matched = any(str(v) in content for v in matcher.values)

        # Handle negative matching
        if matcher.negative:
            matched = not matched

        return matched

    def _run_extractors(self, template: VulnTemplate, result: TemplateResult) -> dict[str, str]:
        """Run extractors on the matched response."""
        extracted = {}

        for extractor in template.extractors:
            content = result.response_body if extractor.part == "body" else \
                "\n".join(f"{k}: {v}" for k, v in result.response_headers.items())

            if extractor.type == "regex":
                for pattern in extractor.values:
                    try:
                        m = re.search(str(pattern), content, re.IGNORECASE)
                        if m:
                            name = extractor.name or f"extract_{len(extracted)}"
                            extracted[name] = m.group(extractor.group) if extractor.group <= len(m.groups()) else m.group(0)
                    except re.error:
                        continue

            elif extractor.type == "kval":
                for key in extractor.values:
                    # Extract from headers
                    val = result.response_headers.get(str(key), "")
                    if val:
                        extracted[str(key)] = val

        return extracted

    def get_stats(self) -> dict:
        """Get template engine statistics."""
        severity_counts = {}
        tag_counts: dict[str, int] = {}
        for t in self.templates:
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1
            for tag in t.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "total_templates": len(self.templates),
            "by_severity": severity_counts,
            "top_tags": dict(sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        }
