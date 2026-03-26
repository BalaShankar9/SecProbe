import pytest
from secprobe.remediation.fix_generator import FixGenerator, FIX_TEMPLATES, CATEGORY_TO_CWE


class FakeFinding:
    def __init__(self, title, category, severity="HIGH", cwe=""):
        self.title = title
        self.category = category
        self.severity = severity
        self.cwe = cwe


class TestFixGenerator:
    def setup_method(self):
        self.gen = FixGenerator()

    def test_generate_sqli_fix(self):
        f = FakeFinding("SQL Injection", "sqli", "CRITICAL", "CWE-89")
        plan = self.gen.generate_plan(f)
        assert len(plan.code_fixes) >= 1
        assert any("parameterized" in fix.description.lower() for fix in plan.code_fixes)
        assert len(plan.waf_rules) >= 1

    def test_generate_xss_fix(self):
        f = FakeFinding("XSS", "xss", "HIGH", "CWE-79")
        plan = self.gen.generate_plan(f)
        assert len(plan.code_fixes) >= 1
        assert any("sanitize" in fix.description.lower() or "escape" in fix.description.lower()
                   for fix in plan.code_fixes)

    def test_generate_header_fix(self):
        f = FakeFinding("Missing HSTS", "headers", "HIGH", "CWE-693")
        plan = self.gen.generate_plan(f)
        assert len(plan.header_configs) >= 1
        assert any("Strict-Transport-Security" in c for c in plan.header_configs)

    def test_tech_stack_filtering(self):
        f = FakeFinding("SQLi", "sqli", "CRITICAL", "CWE-89")
        plan = self.gen.generate_plan(f, tech_stack=["Django", "Python"])
        # Should prioritize Django fix
        assert any(fix.framework == "Django" for fix in plan.code_fixes)

    def test_generate_all_deduplicates(self):
        findings = [
            FakeFinding("SQLi 1", "sqli", "CRITICAL", "CWE-89"),
            FakeFinding("SQLi 2", "sqli", "HIGH", "CWE-89"),  # Same CWE
            FakeFinding("XSS", "xss", "HIGH", "CWE-79"),
        ]
        plans = self.gen.generate_all(findings)
        assert len(plans) == 2  # Deduplicated by CWE

    def test_unknown_category(self):
        f = FakeFinding("Unknown", "unknown_type", "LOW")
        plan = self.gen.generate_plan(f)
        assert plan.code_fixes == []

    def test_priority_assessment(self):
        critical = FakeFinding("", "", "CRITICAL")
        assert FixGenerator._assess_priority(critical) == "IMMEDIATE"
        low = FakeFinding("", "", "LOW")
        assert FixGenerator._assess_priority(low) == "LOW"

    def test_category_to_cwe_mapping(self):
        assert CATEGORY_TO_CWE["sqli"] == "CWE-89"
        assert CATEGORY_TO_CWE["xss"] == "CWE-79"
        assert len(CATEGORY_TO_CWE) >= 10

    def test_waf_rule_format(self):
        f = FakeFinding("SQLi", "sqli", "CRITICAL", "CWE-89")
        plan = self.gen.generate_plan(f)
        assert any("SecRule" in rule for rule in plan.waf_rules)

    def test_fix_has_before_after(self):
        f = FakeFinding("SQLi", "sqli", "CRITICAL", "CWE-89")
        plan = self.gen.generate_plan(f)
        for fix in plan.code_fixes:
            assert fix.before_code  # Has vulnerable code example
            assert fix.after_code   # Has fixed code example
