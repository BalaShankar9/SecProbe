"""
Tests for secprobe.core.scan_intelligence — adaptive scanning behavior.

Tests cover:
  - TechProfile (server, language, framework, WAF, JS framework detection)
  - ScanPlanner (technology-based scanner ordering, WAF skipping)
  - InsertionPointScorer (param name, value, context scoring)
  - ScanScorecard (metrics tracking)
"""

import unittest
from collections import Counter

from secprobe.core.scan_intelligence import (
    TechProfile, ServerType, Language, Framework,
    ScanPlanner, ScanPlan,
    InsertionPointScorer, ScoredParam,
    ScanScorecard,
    SUSPICIOUS_PARAMS,
)


# ═══════════════════════════════════════════════════════════════════════
# TechProfile
# ═══════════════════════════════════════════════════════════════════════

class TestTechProfile(unittest.TestCase):

    def test_detect_apache(self):
        p = TechProfile.from_response({"Server": "Apache/2.4.51"})
        self.assertEqual(p.server, ServerType.APACHE)

    def test_detect_nginx(self):
        p = TechProfile.from_response({"Server": "nginx/1.21"})
        self.assertEqual(p.server, ServerType.NGINX)

    def test_detect_iis(self):
        p = TechProfile.from_response({"Server": "Microsoft-IIS/10.0"})
        self.assertEqual(p.server, ServerType.IIS)

    def test_detect_php_from_powered_by(self):
        p = TechProfile.from_response({"X-Powered-By": "PHP/8.1"})
        self.assertEqual(p.language, Language.PHP)

    def test_detect_dotnet_from_powered_by(self):
        p = TechProfile.from_response({"X-Powered-By": "ASP.NET"})
        self.assertEqual(p.language, Language.DOTNET)

    def test_detect_dotnet_from_aspnet_version(self):
        p = TechProfile.from_response({"X-AspNet-Version": "4.0"})
        self.assertEqual(p.language, Language.DOTNET)

    def test_detect_nodejs_from_express(self):
        p = TechProfile.from_response({"X-Powered-By": "Express"})
        self.assertEqual(p.language, Language.NODEJS)

    def test_detect_python_from_body(self):
        p = TechProfile.from_response({}, body='<input name="csrfmiddlewaretoken">')
        self.assertEqual(p.language, Language.PYTHON)

    def test_detect_wordpress(self):
        p = TechProfile.from_response({}, body='<link rel="stylesheet" href="/wp-content/themes/test.css">')
        self.assertEqual(p.framework, Framework.WORDPRESS)

    def test_detect_django(self):
        p = TechProfile.from_response({}, body='<input type="hidden" name="csrfmiddlewaretoken" value="abc">')
        self.assertEqual(p.framework, Framework.DJANGO)

    def test_detect_laravel(self):
        p = TechProfile.from_response({}, cookies=["laravel_session=abc123"])
        self.assertEqual(p.framework, Framework.LARAVEL)

    def test_detect_aspnet(self):
        p = TechProfile.from_response({}, body='<input type="hidden" name="__VIEWSTATE" value="abc">')
        self.assertEqual(p.framework, Framework.ASP_NET)

    def test_detect_express_framework(self):
        p = TechProfile.from_response({"X-Powered-By": "Express"})
        self.assertEqual(p.framework, Framework.EXPRESS)

    def test_detect_cloudflare_waf(self):
        p = TechProfile.from_response({"cf-ray": "abc123", "Server": "cloudflare"})
        self.assertTrue(p.waf_detected)
        self.assertEqual(p.waf_name, "cloudflare")

    def test_no_waf(self):
        p = TechProfile.from_response({"Server": "nginx"})
        self.assertFalse(p.waf_detected)

    def test_detect_react(self):
        p = TechProfile.from_response({}, body='<div data-reactroot>App</div>')
        self.assertIn("React", p.js_frameworks)

    def test_detect_vue(self):
        p = TechProfile.from_response({}, body='<div v-if="visible">Hello</div>')
        self.assertIn("Vue.js", p.js_frameworks)

    def test_detect_angular(self):
        p = TechProfile.from_response({}, body='<div ng-app="myApp"></div>')
        self.assertIn("Angular", p.js_frameworks)

    def test_detect_jquery(self):
        p = TechProfile.from_response({}, body='<script src="jquery.min.js"></script>')
        self.assertIn("jQuery", p.js_frameworks)

    def test_confidence_with_full_info(self):
        p = TechProfile.from_response(
            {"Server": "Apache", "X-Powered-By": "PHP/8.1", "cf-ray": "abc"},
            body='<link href="/wp-content/style.css"><script src="jquery.min.js"></script>',
        )
        self.assertGreater(p.confidence, 0.8)

    def test_confidence_unknown(self):
        p = TechProfile.from_response({})
        self.assertEqual(p.confidence, 0.0)

    def test_unknown_server(self):
        p = TechProfile.from_response({"Server": "CustomServer/1.0"})
        self.assertEqual(p.server, ServerType.UNKNOWN)


# ═══════════════════════════════════════════════════════════════════════
# ScanPlanner
# ═══════════════════════════════════════════════════════════════════════

class TestScanPlanner(unittest.TestCase):

    def _php_profile(self):
        return TechProfile(server=ServerType.APACHE, language=Language.PHP, framework=Framework.WORDPRESS)

    def _nodejs_profile(self):
        return TechProfile(server=ServerType.NGINX, language=Language.NODEJS, framework=Framework.EXPRESS)

    def test_always_run_scanners_first(self):
        plan = ScanPlanner.plan(
            self._php_profile(),
            ["xss", "header", "sqli", "cors", "cookie"],
        )
        # header, cors, cookie should come before xss, sqli
        always = {"header", "cors", "cookie"}
        first_three = set(plan.ordered_scanners[:3])
        self.assertEqual(first_three, always)

    def test_php_prioritizes_sqli_over_nosql(self):
        plan = ScanPlanner.plan(
            self._php_profile(),
            ["nosql", "sqli"],
        )
        sqli_idx = plan.ordered_scanners.index("sqli")
        nosql_idx = plan.ordered_scanners.index("nosql")
        self.assertLess(sqli_idx, nosql_idx)

    def test_nodejs_prioritizes_nosql_over_xxe(self):
        plan = ScanPlanner.plan(
            self._nodejs_profile(),
            ["xxe", "nosql"],
        )
        nosql_idx = plan.ordered_scanners.index("nosql")
        xxe_idx = plan.ordered_scanners.index("xxe")
        self.assertLess(nosql_idx, xxe_idx)

    def test_waf_skips_fuzzer(self):
        profile = TechProfile(waf_detected=True, waf_name="cloudflare")
        plan = ScanPlanner.plan(profile, ["xss", "fuzzer", "sqli"])
        self.assertNotIn("fuzzer", plan.ordered_scanners)
        skipped_names = [s[0] for s in plan.skipped_scanners]
        self.assertIn("fuzzer", skipped_names)

    def test_skip_passive_flag(self):
        plan = ScanPlanner.plan(
            self._php_profile(),
            ["passive", "header", "xss", "sqli"],
            skip_passive=True,
        )
        self.assertNotIn("passive", plan.ordered_scanners)
        self.assertNotIn("header", plan.ordered_scanners)

    def test_priority_reasons_populated(self):
        plan = ScanPlanner.plan(
            self._php_profile(),
            ["xss", "sqli", "header"],
        )
        self.assertIn("header", plan.priority_reasons)
        self.assertIn("xss", plan.priority_reasons)

    def test_empty_scanners_list(self):
        plan = ScanPlanner.plan(self._php_profile(), [])
        self.assertEqual(plan.ordered_scanners, [])

    def test_unknown_language_gets_medium_priority(self):
        profile = TechProfile(language=Language.UNKNOWN)
        plan = ScanPlanner.plan(profile, ["xss", "sqli", "nosql"])
        # All should be medium priority (default)
        self.assertEqual(len(plan.ordered_scanners), 3)


# ═══════════════════════════════════════════════════════════════════════
# InsertionPointScorer
# ═══════════════════════════════════════════════════════════════════════

class TestInsertionPointScorer(unittest.TestCase):

    def test_suspicious_param_high_score(self):
        scored = InsertionPointScorer.score_param("id", "42")
        self.assertGreaterEqual(scored.score, 0.9)

    def test_search_param_high_score(self):
        scored = InsertionPointScorer.score_param("q", "hello")
        self.assertGreaterEqual(scored.score, 0.9)

    def test_url_param_highest_score(self):
        scored = InsertionPointScorer.score_param("redirect", "http://evil.com")
        self.assertGreaterEqual(scored.score, 0.9)

    def test_unknown_param_minimum_score(self):
        scored = InsertionPointScorer.score_param("xyz_unknown", "abc")
        self.assertEqual(scored.score, 0.3)

    def test_numeric_value_suggests_sqli(self):
        scored = InsertionPointScorer.score_param("foo", "123")
        self.assertIn("sqli", scored.vuln_types)

    def test_url_value_suggests_ssrf(self):
        scored = InsertionPointScorer.score_param("target", "http://internal.corp/api")
        self.assertIn("ssrf", scored.vuln_types)

    def test_path_value_suggests_lfi(self):
        scored = InsertionPointScorer.score_param("tpl", "templates/main.html")
        self.assertIn("lfi", scored.vuln_types)

    def test_search_context_boosts_score(self):
        scored = InsertionPointScorer.score_param("foo", "bar", context="search results page")
        self.assertGreaterEqual(scored.score, 0.8)

    def test_rank_params_ordered(self):
        ranked = InsertionPointScorer.rank_params({
            "foo": "bar",
            "id": "42",
            "q": "hello",
        })
        # id and q should rank higher than foo
        self.assertEqual(ranked[0].name in ("id", "q"), True)
        self.assertEqual(ranked[-1].name, "foo")

    def test_rank_params_empty(self):
        ranked = InsertionPointScorer.rank_params({})
        self.assertEqual(ranked, [])

    def test_file_param_high_score(self):
        scored = InsertionPointScorer.score_param("file", "/etc/passwd")
        self.assertGreaterEqual(scored.score, 0.9)


# ═══════════════════════════════════════════════════════════════════════
# ScanScorecard
# ═══════════════════════════════════════════════════════════════════════

class TestScanScorecard(unittest.TestCase):

    def test_initial_state(self):
        card = ScanScorecard()
        self.assertEqual(card.total_requests, 0)
        self.assertEqual(card.total_findings, 0)

    def test_record_finding(self):
        card = ScanScorecard()
        card.record_finding("xss", "HIGH", "xss_reflected")
        self.assertEqual(card.total_findings, 1)
        self.assertEqual(card.findings_by_scanner["xss"], 1)
        self.assertEqual(card.findings_by_severity["HIGH"], 1)
        self.assertEqual(card.findings_by_type["xss_reflected"], 1)

    def test_efficiency(self):
        card = ScanScorecard(total_requests=1000)
        card.record_finding("sqli", "CRITICAL", "sqli")
        card.record_finding("sqli", "HIGH", "sqli")
        self.assertAlmostEqual(card.efficiency, 0.2)

    def test_efficiency_zero_requests(self):
        card = ScanScorecard()
        self.assertEqual(card.efficiency, 0.0)

    def test_false_positive_rate(self):
        card = ScanScorecard(verified_findings=9, false_positives=1)
        self.assertAlmostEqual(card.false_positive_rate, 10.0)

    def test_false_positive_rate_no_data(self):
        card = ScanScorecard()
        self.assertEqual(card.false_positive_rate, 0.0)

    def test_vulnerability_rate(self):
        card = ScanScorecard(params_tested=10, params_vulnerable=3)
        self.assertAlmostEqual(card.vulnerability_rate, 30.0)

    def test_record_scanner_duration(self):
        card = ScanScorecard()
        card.record_scanner_duration("xss", 12.5)
        self.assertEqual(card.scanner_durations["xss"], 12.5)

    def test_summary_structure(self):
        card = ScanScorecard(total_requests=100)
        card.record_finding("xss", "HIGH", "xss")
        s = card.summary()
        self.assertIn("total_requests", s)
        self.assertIn("total_findings", s)
        self.assertIn("efficiency", s)
        self.assertIn("top_scanners", s)
        self.assertIn("severity_breakdown", s)


if __name__ == "__main__":
    unittest.main()
