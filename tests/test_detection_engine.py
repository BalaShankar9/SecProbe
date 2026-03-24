"""
Comprehensive tests for secprobe.core.detection — the false-positive
elimination engine.

Tests cover:
  - BaselineProfile  (statistical methods)
  - ResponseAnalyzer (normalize, structural_diff, contains_new)
  - ReflectionTracker (encoding transforms, context detection, exploitability)
  - ErrorPatternMatcher (SQL, NoSQL, template, command, file, SSRF patterns + baseline subtraction)
  - TimingAnalyzer (z-score, delay matching)
  - ConfidenceScorer (multi-factor scoring)
  - FindingDeduplicator (root-cause grouping)
  - DetectionEngine (orchestrator: profile, test_error_based, test_template_eval, test_boolean)
"""

import unittest
from unittest.mock import MagicMock

from secprobe.core.detection import (
    Confidence, VulnType,
    BaselineProfile, DetectionResult,
    ResponseAnalyzer,
    ReflectionTracker, ReflectionContext,
    ErrorPatternMatcher,
    ConfidenceScorer,
    FindingDeduplicator,
    DetectionEngine,
    _strip_dynamic, _dom_structure_hash,
)


# ═══════════════════════════════════════════════════════════════════════
# BaselineProfile Tests
# ═══════════════════════════════════════════════════════════════════════

class TestBaselineProfile(unittest.TestCase):

    def _make_profile(self, sizes=None, timings=None, stable_text=""):
        p = BaselineProfile(url="http://test.local", method="GET")
        p.sizes = sizes or [100, 105, 95, 102, 98]
        p.timings = timings or [0.1, 0.12, 0.09, 0.11, 0.1]
        p.sample_count = len(p.sizes)
        p.size_mean = sum(p.sizes) / len(p.sizes)
        import statistics
        p.size_stdev = statistics.stdev(p.sizes) if len(p.sizes) > 1 else 0
        p.timing_mean = sum(p.timings) / len(p.timings)
        p.timing_stdev = statistics.stdev(p.timings) if len(p.timings) > 1 else 0
        p.stable_text = stable_text
        p.status_codes = [200] * len(p.sizes)
        p.primary_status = 200
        return p

    def test_size_anomalous_beyond_3sigma(self):
        p = self._make_profile(sizes=[100, 100, 100, 100, 100])
        # With zero stdev, falls back to 30% deviation
        self.assertTrue(p.is_size_anomalous(200))

    def test_size_normal_within_range(self):
        p = self._make_profile()
        self.assertFalse(p.is_size_anomalous(103))

    def test_size_anomalous_with_stdev(self):
        p = self._make_profile(sizes=[100, 102, 98, 101, 99])
        # Stdev ≈ 1.58, 3σ ≈ 4.74, so 110 should be anomalous
        self.assertTrue(p.is_size_anomalous(120))

    def test_timing_anomalous(self):
        p = self._make_profile(timings=[0.1, 0.1, 0.1, 0.1, 0.1])
        # Zero stdev fallback: 3 * mean = 0.3
        self.assertTrue(p.is_timing_anomalous(0.5))

    def test_timing_normal(self):
        p = self._make_profile()
        self.assertFalse(p.is_timing_anomalous(0.12))

    def test_contains_in_baseline_true(self):
        p = self._make_profile(stable_text="Welcome to our website. Price: $50")
        self.assertTrue(p.contains_in_baseline("welcome"))

    def test_contains_in_baseline_false(self):
        p = self._make_profile(stable_text="Welcome to our website")
        self.assertFalse(p.contains_in_baseline("121401"))

    def test_contains_in_baseline_empty(self):
        p = self._make_profile(stable_text="")
        self.assertFalse(p.contains_in_baseline("test"))


# ═══════════════════════════════════════════════════════════════════════
# DetectionResult Tests
# ═══════════════════════════════════════════════════════════════════════

class TestDetectionResult(unittest.TestCase):

    def test_is_positive_firm(self):
        r = DetectionResult(payload="'", url="http://x", confidence=Confidence.FIRM)
        self.assertTrue(r.is_positive)

    def test_is_positive_confirmed(self):
        r = DetectionResult(payload="'", url="http://x", confidence=Confidence.CONFIRMED)
        self.assertTrue(r.is_positive)

    def test_not_positive_tentative(self):
        r = DetectionResult(payload="'", url="http://x", confidence=Confidence.TENTATIVE)
        self.assertFalse(r.is_positive)

    def test_not_positive_none(self):
        r = DetectionResult(payload="'", url="http://x", confidence=Confidence.NONE)
        self.assertFalse(r.is_positive)

    def test_dedup_key(self):
        r = DetectionResult(
            payload="'", url="http://test.local?id=1",
            parameter="id", vuln_type=VulnType.ERROR_BASED)
        self.assertEqual(r.dedup_key, "id|ERROR_BASED|http://test.local")


# ═══════════════════════════════════════════════════════════════════════
# Dynamic Content Stripping Tests
# ═══════════════════════════════════════════════════════════════════════

class TestDynamicStripping(unittest.TestCase):

    def test_strips_csrf_token(self):
        html = '<input type="hidden" name="csrf_token" value="abc123xyz">'
        stripped = _strip_dynamic(html)
        self.assertNotIn("abc123xyz", stripped)
        self.assertIn("__DYN__", stripped)

    def test_strips_unix_timestamps(self):
        text = "Generated at 1703123456789"
        stripped = _strip_dynamic(text)
        self.assertNotIn("1703123456789", stripped)

    def test_strips_uuids(self):
        text = "Request-ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        stripped = _strip_dynamic(text)
        self.assertNotIn("a1b2c3d4-e5f6-7890-abcd-ef1234567890", stripped)

    def test_strips_prices(self):
        text = "Room price: $150.00 per night"
        stripped = _strip_dynamic(text)
        self.assertNotIn("$150.00", stripped)

    def test_dom_structure_hash_same(self):
        html1 = "<html><body><h1>Hello</h1><p>World</p></body></html>"
        html2 = "<html><body><h1>Goodbye</h1><p>Earth</p></body></html>"
        self.assertEqual(_dom_structure_hash(html1), _dom_structure_hash(html2))

    def test_dom_structure_hash_different(self):
        html1 = "<html><body><h1>Hello</h1></body></html>"
        html2 = "<html><body><h1>Hello</h1><script>evil()</script></body></html>"
        self.assertNotEqual(_dom_structure_hash(html1), _dom_structure_hash(html2))


# ═══════════════════════════════════════════════════════════════════════
# ResponseAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════

class TestResponseAnalyzer(unittest.TestCase):

    def test_contains_new_positive(self):
        baseline = "Welcome to our website"
        injected = "Welcome to our website\n121401"
        self.assertTrue(ResponseAnalyzer.contains_new(baseline, injected, "121401"))

    def test_contains_new_false_in_baseline(self):
        """Key FP-killer: '49' in baseline → NOT new."""
        baseline = "Hotel room from $49 per night"
        injected = "Hotel room from $49 per night"
        self.assertFalse(ResponseAnalyzer.contains_new(baseline, injected, "49"))

    def test_contains_new_not_present(self):
        baseline = "Welcome"
        injected = "Welcome"
        self.assertFalse(ResponseAnalyzer.contains_new(baseline, injected, "121401"))

    def test_contains_new_case_insensitive(self):
        baseline = "hello"
        injected = "hello NEWDATA"
        self.assertTrue(ResponseAnalyzer.contains_new(baseline, injected, "newdata"))

    def test_structural_diff_no_change(self):
        base = "Line 1\nLine 2\nLine 3"
        diff = ResponseAnalyzer.structural_diff(base, base)
        self.assertFalse(diff["changed"])
        self.assertEqual(diff["size_delta"], 0)

    def test_structural_diff_new_content(self):
        base = "Line 1\nLine 2"
        injected = "Line 1\nLine 2\nYou have an error in your SQL syntax"
        diff = ResponseAnalyzer.structural_diff(base, injected)
        self.assertIn("SQL syntax", diff["new_content"])

    def test_structural_diff_dom_change(self):
        base = "<html><body><p>Hello</p></body></html>"
        injected = "<html><body><p>Hello</p><script>alert(1)</script></body></html>"
        diff = ResponseAnalyzer.structural_diff(base, injected)
        self.assertTrue(diff["structural_change"])


# ═══════════════════════════════════════════════════════════════════════
# ReflectionTracker Tests
# ═══════════════════════════════════════════════════════════════════════

class TestReflectionTracker(unittest.TestCase):

    def test_raw_reflection(self):
        payload = '<script>alert(1)</script>'
        response = f'<html><body>Search results for: {payload}</body></html>'
        reflections = ReflectionTracker.find_reflection(response, payload)
        self.assertTrue(len(reflections) > 0)
        self.assertEqual(reflections[0]["transform"], "raw")

    def test_html_entity_reflection(self):
        payload = '<img src=x onerror=alert(1)>'
        response = '<html><body>&lt;img src=x onerror=alert(1)&gt;</body></html>'
        reflections = ReflectionTracker.find_reflection(response, payload)
        transforms = [r["transform"] for r in reflections]
        self.assertIn("html_entity", transforms)

    def test_url_encoded_reflection(self):
        payload = '<script>'
        response = 'Search=%3Cscript%3E is not allowed'
        reflections = ReflectionTracker.find_reflection(response, payload)
        transforms = [r["transform"] for r in reflections]
        self.assertIn("url_encoded", transforms)

    def test_no_reflection(self):
        payload = '<script>alert(1)</script>'
        response = '<html><body>No results found</body></html>'
        reflections = ReflectionTracker.find_reflection(response, payload)
        self.assertEqual(len(reflections), 0)

    def test_baseline_subtraction(self):
        """If payload text is already in baseline, don't report reflection."""
        payload = 'test'
        baseline = '<html><body>test page</body></html>'
        response = '<html><body>test page</body></html>'
        reflections = ReflectionTracker.find_reflection(response, payload, baseline)
        self.assertEqual(len(reflections), 0)

    def test_context_html_body(self):
        payload = '<script>alert(1)</script>'
        response = f'<html><body><p>{payload}</p></body></html>'
        reflections = ReflectionTracker.find_reflection(response, payload)
        self.assertEqual(reflections[0]["context"], ReflectionContext.HTML_BODY)

    def test_context_html_attribute(self):
        payload = '" onmouseover="alert(1)"'
        response = f'<html><body><input value="{payload}"></body></html>'
        reflections = ReflectionTracker.find_reflection(response, payload)
        # Should detect attribute context
        self.assertTrue(any(r["context"] == ReflectionContext.HTML_ATTRIBUTE
                            for r in reflections))

    def test_context_javascript(self):
        payload = "'; alert(1); //"
        response = f"<html><script>var x = '{payload}';</script></html>"
        reflections = ReflectionTracker.find_reflection(response, payload)
        contexts = [r["context"] for r in reflections]
        self.assertTrue(any(c in (ReflectionContext.JAVASCRIPT,
                                   ReflectionContext.JAVASCRIPT_STRING)
                            for c in contexts))

    def test_exploitable_html_body(self):
        payload = '<img src=x onerror=alert(1)>'
        response = f'<html><body>{payload}</body></html>'
        reflections = ReflectionTracker.find_reflection(response, payload)
        self.assertTrue(any(r["exploitable"] for r in reflections))


# ═══════════════════════════════════════════════════════════════════════
# ErrorPatternMatcher Tests
# ═══════════════════════════════════════════════════════════════════════

class TestErrorPatternMatcher(unittest.TestCase):

    # ── SQL Errors ──────────────────────────────────────────────────
    def test_mysql_error(self):
        text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        matches = ErrorPatternMatcher.match_sql_errors(text)
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0].confidence, Confidence.CONFIRMED)

    def test_postgresql_error(self):
        text = 'ERROR: syntax error at or near "test"'
        matches = ErrorPatternMatcher.match_sql_errors(text)
        self.assertTrue(len(matches) > 0)
        self.assertIn("PostgreSQL", matches[0].technology)

    def test_mssql_error(self):
        text = "ODBC SQL Server Driver error"
        matches = ErrorPatternMatcher.match_sql_errors(text)
        self.assertTrue(len(matches) > 0)

    def test_oracle_error(self):
        text = "ORA-01756: quoted string not properly terminated"
        matches = ErrorPatternMatcher.match_sql_errors(text)
        self.assertTrue(len(matches) > 0)

    def test_sqlite_error(self):
        text = 'sqlite3.OperationalError: near "x": syntax error'
        matches = ErrorPatternMatcher.match_sql_errors(text)
        self.assertTrue(len(matches) > 0)

    def test_sql_baseline_subtraction(self):
        """SQL error that's in the baseline should NOT be reported."""
        text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        baseline = text  # Same content in baseline
        matches = ErrorPatternMatcher.match_sql_errors(text, baseline)
        self.assertEqual(len(matches), 0)

    def test_sql_no_false_positive(self):
        text = "Welcome to our hotel booking site"
        matches = ErrorPatternMatcher.match_sql_errors(text)
        self.assertEqual(len(matches), 0)

    # ── NoSQL Errors ────────────────────────────────────────────────
    def test_mongodb_error(self):
        text = "MongoError: failed to execute query"
        matches = ErrorPatternMatcher.match_nosql_errors(text)
        self.assertTrue(len(matches) > 0)

    def test_castexception(self):
        text = "CastError: Cast to ObjectId failed for value"
        matches = ErrorPatternMatcher.match_nosql_errors(text)
        self.assertTrue(len(matches) > 0)

    def test_nosql_baseline_subtraction(self):
        text = "MongoError: failed to execute query"
        matches = ErrorPatternMatcher.match_nosql_errors(text, text)
        self.assertEqual(len(matches), 0)

    # ── Template Errors ─────────────────────────────────────────────
    def test_jinja2_error(self):
        text = "jinja2.exceptions.TemplateSyntaxError: unexpected token"
        matches = ErrorPatternMatcher.match_template_errors(text)
        self.assertTrue(len(matches) > 0)

    def test_twig_error(self):
        text = "Twig_Error_Syntax: Unexpected token"
        matches = ErrorPatternMatcher.match_template_errors(text)
        self.assertTrue(len(matches) > 0)

    def test_template_baseline_subtraction(self):
        text = "jinja2.exceptions.TemplateSyntaxError: unexpected"
        matches = ErrorPatternMatcher.match_template_errors(text, text)
        self.assertEqual(len(matches), 0)

    # ── Command Output ──────────────────────────────────────────────
    def test_id_output(self):
        text = "uid=0(root) gid=0(root) groups=0(root)"
        matches = ErrorPatternMatcher.match_command_output(text)
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0].confidence, Confidence.CONFIRMED)

    def test_passwd_output(self):
        text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
        matches = ErrorPatternMatcher.match_command_output(text)
        self.assertTrue(len(matches) > 0)

    def test_command_output_baseline_subtraction(self):
        text = "uid=0(root) gid=0(root)"
        matches = ErrorPatternMatcher.match_command_output(text, text)
        self.assertEqual(len(matches), 0)

    # ── Command Errors ──────────────────────────────────────────────
    def test_shell_error(self):
        text = "sh: line 1: foo: command not found"
        matches = ErrorPatternMatcher.match_command_errors(text)
        self.assertTrue(len(matches) > 0)

    # ── File Disclosure ─────────────────────────────────────────────
    def test_etc_passwd(self):
        text = "root:x:0:0:root:/root:/bin/bash"
        matches = ErrorPatternMatcher.match_file_disclosure(text)
        self.assertTrue(len(matches) > 0)

    def test_win_ini(self):
        text = "; for 16-bit app support\n[fonts]\n[extensions]"
        matches = ErrorPatternMatcher.match_file_disclosure(text)
        self.assertTrue(len(matches) > 0)

    def test_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ"
        matches = ErrorPatternMatcher.match_file_disclosure(text)
        self.assertTrue(len(matches) > 0)

    def test_file_baseline_subtraction(self):
        text = "root:x:0:0:root:/root:/bin/bash"
        matches = ErrorPatternMatcher.match_file_disclosure(text, text)
        self.assertEqual(len(matches), 0)

    # ── SSRF Indicators ─────────────────────────────────────────────
    def test_aws_ami_id(self):
        text = "ami-0abcdef1234567890"
        matches = ErrorPatternMatcher.match_ssrf_indicators(text)
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0].confidence, Confidence.CONFIRMED)

    def test_aws_arn(self):
        text = "arn:aws:iam:us-east-1:123456789012:role/admin"
        matches = ErrorPatternMatcher.match_ssrf_indicators(text)
        self.assertTrue(len(matches) > 0)

    def test_ssrf_baseline_subtraction(self):
        text = "ami-0abcdef1234567890"
        matches = ErrorPatternMatcher.match_ssrf_indicators(text, text)
        self.assertEqual(len(matches), 0)

    def test_ssrf_no_false_positive(self):
        text = "Welcome to our booking website"
        matches = ErrorPatternMatcher.match_ssrf_indicators(text)
        self.assertEqual(len(matches), 0)


# ═══════════════════════════════════════════════════════════════════════
# ConfidenceScorer Tests
# ═══════════════════════════════════════════════════════════════════════

class TestConfidenceScorer(unittest.TestCase):

    def test_confirmed_with_error_match(self):
        match = ErrorPatternMatcher.PatternMatch(
            pattern="test", matched_text="MySQL error",
            category="sql_error", technology="MySQL",
            confidence=Confidence.CONFIRMED,
            description="SQL error (MySQL)",
        )
        conf, breakdown = ConfidenceScorer.score_injection(
            error_matches=[match])
        # error_score = 3 * 30 = 90 → CONFIRMED
        self.assertEqual(conf, Confidence.CONFIRMED)
        self.assertEqual(breakdown["error_score"], 90)

    def test_firm_with_firm_error(self):
        match = ErrorPatternMatcher.PatternMatch(
            pattern="test", matched_text="DB error",
            category="sql_error", technology="Generic",
            confidence=Confidence.FIRM,
            description="SQL error",
        )
        conf, breakdown = ConfidenceScorer.score_injection(
            error_matches=[match])
        # error_score = 2 * 30 = 60 → FIRM
        self.assertEqual(conf, Confidence.FIRM)
        self.assertEqual(breakdown["error_score"], 60)

    def test_tentative_with_tentative_error(self):
        match = ErrorPatternMatcher.PatternMatch(
            pattern="test", matched_text="error",
            category="sql_error", technology="Generic",
            confidence=Confidence.TENTATIVE,
            description="Possible error",
        )
        conf, breakdown = ConfidenceScorer.score_injection(
            error_matches=[match])
        # error_score = 1 * 30 = 30 → TENTATIVE
        self.assertEqual(conf, Confidence.TENTATIVE)

    def test_none_with_no_evidence(self):
        conf, breakdown = ConfidenceScorer.score_injection()
        self.assertEqual(conf, Confidence.NONE)
        self.assertEqual(breakdown["total"], 0)

    def test_reflection_exploitable_score(self):
        refl = [{"transform": "raw", "context": "html_body",
                 "exploitable": True}]
        conf, breakdown = ConfidenceScorer.score_injection(
            reflection=refl, vuln_type=VulnType.REFLECTION)
        self.assertEqual(breakdown["reflection_score"], 90)
        self.assertEqual(conf, Confidence.CONFIRMED)

    def test_reflection_non_exploitable_score(self):
        refl = [{"transform": "html_entity", "context": "html_body",
                 "exploitable": False}]
        conf, breakdown = ConfidenceScorer.score_injection(
            reflection=refl, vuln_type=VulnType.REFLECTION)
        self.assertEqual(breakdown["reflection_score"], 30)

    def test_size_anomaly_score(self):
        import statistics
        profile = BaselineProfile(url="http://test.local")
        profile.sizes = [100, 100, 100, 100, 100]
        profile.sample_count = 5
        profile.size_mean = 100
        profile.size_stdev = 0
        profile.primary_status = 200
        conf, breakdown = ConfidenceScorer.score_injection(
            baseline=profile, response_size=200, response_status=200)
        self.assertEqual(breakdown["size_score"], 15)

    def test_status_change_score(self):
        profile = BaselineProfile(url="http://test.local")
        profile.sample_count = 5
        profile.sizes = [100] * 5
        profile.size_mean = 100
        profile.size_stdev = 0
        profile.primary_status = 200
        conf, breakdown = ConfidenceScorer.score_injection(
            baseline=profile, response_size=100, response_status=500)
        self.assertEqual(breakdown["status_score"], 20)


# ═══════════════════════════════════════════════════════════════════════
# FindingDeduplicator Tests
# ═══════════════════════════════════════════════════════════════════════

class TestFindingDeduplicator(unittest.TestCase):

    def test_add_first(self):
        dedup = FindingDeduplicator()
        r = DetectionResult(payload="'", url="http://x?id=1",
                            parameter="id", confidence=Confidence.FIRM,
                            vuln_type=VulnType.ERROR_BASED)
        self.assertTrue(dedup.add(r))

    def test_keeps_highest_confidence(self):
        dedup = FindingDeduplicator()
        r1 = DetectionResult(payload="'", url="http://x?id=1",
                             parameter="id", confidence=Confidence.TENTATIVE,
                             vuln_type=VulnType.ERROR_BASED)
        r2 = DetectionResult(payload='"', url="http://x?id=1",
                             parameter="id", confidence=Confidence.CONFIRMED,
                             vuln_type=VulnType.ERROR_BASED)
        dedup.add(r1)
        dedup.add(r2)
        results = dedup.get_results()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].confidence, Confidence.CONFIRMED)

    def test_different_params_kept_separate(self):
        dedup = FindingDeduplicator()
        r1 = DetectionResult(payload="'", url="http://x?id=1",
                             parameter="id", confidence=Confidence.FIRM,
                             vuln_type=VulnType.ERROR_BASED)
        r2 = DetectionResult(payload="'", url="http://x?name=test",
                             parameter="name", confidence=Confidence.FIRM,
                             vuln_type=VulnType.ERROR_BASED)
        dedup.add(r1)
        dedup.add(r2)
        self.assertEqual(len(dedup.get_results()), 2)

    def test_different_vuln_types_kept_separate(self):
        dedup = FindingDeduplicator()
        r1 = DetectionResult(payload="'", url="http://x?id=1",
                             parameter="id", confidence=Confidence.FIRM,
                             vuln_type=VulnType.ERROR_BASED)
        r2 = DetectionResult(payload="' AND SLEEP(3)--", url="http://x?id=1",
                             parameter="id", confidence=Confidence.FIRM,
                             vuln_type=VulnType.TIME_BASED)
        dedup.add(r1)
        dedup.add(r2)
        self.assertEqual(len(dedup.get_results()), 2)

    def test_get_confirmed(self):
        dedup = FindingDeduplicator()
        dedup.add(DetectionResult(payload="'", url="http://x",
                                  parameter="id", confidence=Confidence.CONFIRMED,
                                  vuln_type=VulnType.ERROR_BASED))
        dedup.add(DetectionResult(payload='"', url="http://x",
                                  parameter="name", confidence=Confidence.TENTATIVE,
                                  vuln_type=VulnType.ERROR_BASED))
        confirmed = dedup.get_confirmed()
        self.assertEqual(len(confirmed), 1)

    def test_get_firm_or_better(self):
        dedup = FindingDeduplicator()
        dedup.add(DetectionResult(payload="'", url="http://x",
                                  parameter="id", confidence=Confidence.CONFIRMED,
                                  vuln_type=VulnType.ERROR_BASED))
        dedup.add(DetectionResult(payload='"', url="http://x",
                                  parameter="name", confidence=Confidence.FIRM,
                                  vuln_type=VulnType.ERROR_BASED))
        dedup.add(DetectionResult(payload='x', url="http://x",
                                  parameter="q", confidence=Confidence.TENTATIVE,
                                  vuln_type=VulnType.ERROR_BASED))
        firm_plus = dedup.get_firm_or_better()
        self.assertEqual(len(firm_plus), 2)

    def test_count(self):
        dedup = FindingDeduplicator()
        dedup.add(DetectionResult(payload="'", url="http://x",
                                  parameter="id", confidence=Confidence.CONFIRMED,
                                  vuln_type=VulnType.ERROR_BASED))
        dedup.add(DetectionResult(payload='"', url="http://x",
                                  parameter="name", confidence=Confidence.NONE,
                                  vuln_type=VulnType.ERROR_BASED))
        counts = dedup.count()
        self.assertEqual(counts["CONFIRMED"], 1)
        self.assertEqual(counts["NONE"], 1)

    def test_clear(self):
        dedup = FindingDeduplicator()
        dedup.add(DetectionResult(payload="'", url="http://x",
                                  parameter="id", confidence=Confidence.FIRM,
                                  vuln_type=VulnType.ERROR_BASED))
        dedup.clear()
        self.assertEqual(len(dedup.get_results()), 0)


# ═══════════════════════════════════════════════════════════════════════
# DetectionEngine Integration Tests
# ═══════════════════════════════════════════════════════════════════════

def _mock_response(text="", status_code=200):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = {}
    return resp


class TestDetectionEngine(unittest.TestCase):

    def _make_engine(self, get_responses=None):
        client = MagicMock()
        if get_responses:
            client.get.side_effect = get_responses
        else:
            clean = _mock_response("Normal page content")
            client.get.return_value = clean
        client.post.return_value = _mock_response("Normal page content")

        engine = DetectionEngine(
            client, baseline_samples=3, baseline_delay=0,
            min_confidence=Confidence.FIRM)
        return engine

    def test_profile_creates_baseline(self):
        engine = self._make_engine()
        baseline = engine.profile("http://test.local?id=1", params={"id": "1"})
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline.sample_count, 3)

    def test_get_baseline_after_profile(self):
        engine = self._make_engine()
        engine.profile("http://test.local?id=1", params={"id": "1"})
        baseline = engine.get_baseline("http://test.local?id=1")
        self.assertIsNotNone(baseline)

    def test_test_error_based_detects_sqli(self):
        engine = self._make_engine()
        engine.profile("http://test.local?id=1", params={"id": "1"})
        result = engine.test_error_based(
            url="http://test.local?id=1",
            parameter="id",
            payload="'",
            response_text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            response_status=200,
            vuln_category="sqli",
        )
        self.assertTrue(result.is_positive)
        self.assertEqual(result.confidence, Confidence.CONFIRMED)

    def test_test_error_based_no_sqli_on_clean(self):
        engine = self._make_engine()
        engine.profile("http://test.local?id=1", params={"id": "1"})
        result = engine.test_error_based(
            url="http://test.local?id=1",
            parameter="id",
            payload="'",
            response_text="Product: Widget XL",
            response_status=200,
            vuln_category="sqli",
        )
        self.assertFalse(result.is_positive)

    def test_test_error_based_baseline_subtraction(self):
        """If error text is in the profiled baseline, it should be rejected."""
        error = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        engine = self._make_engine(
            get_responses=[_mock_response(error)] * 10)
        engine.profile("http://test.local?id=1", params={"id": "1"})
        result = engine.test_error_based(
            url="http://test.local?id=1",
            parameter="id",
            payload="'",
            response_text=error,
            response_status=200,
            vuln_category="sqli",
        )
        # The error is in stable_text → baseline subtraction kills it
        self.assertFalse(result.is_positive)

    def test_test_template_eval_detected(self):
        engine = self._make_engine()
        engine.profile("http://test.local?name=test", params={"name": "test"})
        result = engine.test_template_eval(
            url="http://test.local?name=test",
            parameter="name",
            expression="{{987*123}}",
            expected="121401",
            response_text="Result: 121401",
            baseline_text="Normal page content",
        )
        self.assertTrue(result.is_positive)

    def test_test_template_eval_in_baseline(self):
        """121401 already in baseline → FP killed."""
        engine = self._make_engine(
            get_responses=[_mock_response("Page with 121401 data")] * 10)
        engine.profile("http://test.local?name=test", params={"name": "test"})
        result = engine.test_template_eval(
            url="http://test.local?name=test",
            parameter="name",
            expression="{{987*123}}",
            expected="121401",
            response_text="Page with 121401 data",
            baseline_text="Page with 121401 data",
        )
        self.assertFalse(result.is_positive)

    def test_test_error_based_nosql(self):
        engine = self._make_engine()
        engine.profile("http://test.local?username=admin", params={"username": "admin"})
        result = engine.test_error_based(
            url="http://test.local?username=admin",
            parameter="username",
            payload="[$ne]=",
            response_text="MongoError: failed to execute query",
            response_status=500,
            vuln_category="nosql",
        )
        self.assertTrue(result.is_positive)

    def test_stats(self):
        engine = self._make_engine()
        engine.profile("http://test.local?id=1", params={"id": "1"})
        engine.test_error_based(
            url="http://test.local?id=1", parameter="id", payload="'",
            response_text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            vuln_category="sqli")
        engine.test_error_based(
            url="http://test.local?id=1", parameter="id", payload='"',
            response_text="Normal page", vuln_category="sqli")
        stats = engine.stats
        self.assertIn("total_tested", stats)
        self.assertTrue(stats["total_tested"] > 0)

    def test_get_findings(self):
        engine = self._make_engine()
        engine.profile("http://test.local?id=1", params={"id": "1"})
        engine.test_error_based(
            url="http://test.local?id=1", parameter="id", payload="'",
            response_text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            vuln_category="sqli")
        findings = engine.get_findings()
        self.assertTrue(len(findings) > 0)
        self.assertTrue(findings[0].confidence >= Confidence.FIRM)


# ═══════════════════════════════════════════════════════════════════════
# False Positive Regression Tests
# ═══════════════════════════════════════════════════════════════════════

class TestFalsePositiveKillers(unittest.TestCase):
    """
    Tests that verify specific false positive scenarios are correctly
    rejected by the detection engine.
    """

    def test_hotel_price_49_not_ssti(self):
        """booking.com showed '49' everywhere as hotel prices. Must NOT flag as SSTI."""
        self.assertFalse(
            ResponseAnalyzer.contains_new(
                "Rooms from $49 per night. Budget hotel $49.",
                "Rooms from $49 per night. Budget hotel $49.",
                "49"))

    def test_dynamic_page_size_not_sqli(self):
        """Dynamic pages vary in size naturally. Must NOT flag as boolean SQLi."""
        profile = BaselineProfile(url="http://test.local")
        profile.sizes = [5000, 5200, 4800, 5100, 4900]
        profile.sample_count = 5
        import statistics as stat
        profile.size_mean = stat.mean(profile.sizes)
        profile.size_stdev = stat.stdev(profile.sizes)
        # 5300 is within normal variance
        self.assertFalse(profile.is_size_anomalous(5300, sigma_threshold=3.0))

    def test_sql_error_in_documentation_not_vuln(self):
        """A page that always shows SQL error examples shouldn't flag."""
        baseline = "Example: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        text = baseline
        matches = ErrorPatternMatcher.match_sql_errors(text, baseline)
        self.assertEqual(len(matches), 0)

    def test_normal_xml_page_not_xxe(self):
        """XML content pages shouldn't flag as XXE."""
        text = '<?xml version="1.0"?><catalog><book><title>Harry Potter</title></book></catalog>'
        matches = ErrorPatternMatcher.match_file_disclosure(text)
        self.assertEqual(len(matches), 0)

    def test_booking_page_not_ssrf(self):
        """Normal booking page HTML shouldn't trigger SSRF."""
        text = "<html><head><title>Hotel Booking</title></head><body><p>Book your room</p></body></html>"
        matches = ErrorPatternMatcher.match_ssrf_indicators(text)
        self.assertEqual(len(matches), 0)


if __name__ == "__main__":
    unittest.main()
