"""
Auto-remediation — generates framework-specific code fixes and WAF rules.

For each vulnerability finding, generates:
1. Code fix snippet in the target's language/framework
2. WAF virtual patch rule (ModSecurity/AWS WAF format)
3. Security header configuration
"""

from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class RemediationPlan:
    finding_title: str
    cwe: str
    code_fixes: list[CodeFix] = field(default_factory=list)
    waf_rules: list[str] = field(default_factory=list)
    header_configs: list[str] = field(default_factory=list)
    priority: str = "HIGH"  # How urgently to fix
    effort: str = "LOW"     # Implementation effort

@dataclass
class CodeFix:
    framework: str      # express, django, flask, spring, laravel, etc.
    language: str        # javascript, python, java, php
    description: str
    before_code: str     # Vulnerable code example
    after_code: str      # Fixed code example
    dependencies: list[str] = field(default_factory=list)  # npm/pip packages needed


# Fix templates per CWE
FIX_TEMPLATES: dict[str, dict] = {
    "CWE-89": {  # SQL Injection
        "name": "SQL Injection",
        "fixes": {
            "express": CodeFix(
                framework="Express.js", language="javascript",
                description="Use parameterized queries instead of string concatenation",
                before_code='db.query("SELECT * FROM users WHERE id = " + req.params.id)',
                after_code='db.query("SELECT * FROM users WHERE id = $1", [req.params.id])',
                dependencies=[],
            ),
            "django": CodeFix(
                framework="Django", language="python",
                description="Use Django ORM or parameterized queries",
                before_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                after_code='cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])',
            ),
            "flask": CodeFix(
                framework="Flask/SQLAlchemy", language="python",
                description="Use SQLAlchemy ORM or parameterized queries",
                before_code='db.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                after_code='db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})',
                dependencies=["sqlalchemy"],
            ),
            "spring": CodeFix(
                framework="Spring Boot", language="java",
                description="Use JPA/Hibernate or PreparedStatement",
                before_code='String sql = "SELECT * FROM users WHERE id = " + userId;',
                after_code='@Query("SELECT u FROM User u WHERE u.id = :id")\nUser findById(@Param("id") Long id);',
            ),
            "laravel": CodeFix(
                framework="Laravel", language="php",
                description="Use Eloquent ORM or query builder bindings",
                before_code='DB::select("SELECT * FROM users WHERE id = " . $id);',
                after_code='DB::select("SELECT * FROM users WHERE id = ?", [$id]);',
            ),
        },
        "waf_rule": 'SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,msg:\'SQL Injection Attempt\'"',
    },
    "CWE-79": {  # XSS
        "name": "Cross-Site Scripting",
        "fixes": {
            "express": CodeFix(
                framework="Express.js", language="javascript",
                description="Sanitize output with DOMPurify or escape HTML entities",
                before_code='res.send("<div>" + userInput + "</div>")',
                after_code='const DOMPurify = require("dompurify");\nres.send("<div>" + DOMPurify.sanitize(userInput) + "</div>")',
                dependencies=["dompurify", "jsdom"],
            ),
            "django": CodeFix(
                framework="Django", language="python",
                description="Use Django template auto-escaping (enabled by default)",
                before_code='return HttpResponse(f"<div>{user_input}</div>")',
                after_code='from django.utils.html import escape\nreturn HttpResponse(f"<div>{escape(user_input)}</div>")',
            ),
            "react": CodeFix(
                framework="React", language="javascript",
                description="Avoid dangerouslySetInnerHTML; use text content instead",
                before_code='<div dangerouslySetInnerHTML={{__html: userInput}} />',
                after_code='<div>{userInput}</div>  // React auto-escapes by default',
            ),
        },
        "waf_rule": 'SecRule ARGS "@detectXSS" "id:1002,phase:2,deny,status:403,msg:\'XSS Attempt\'"',
    },
    "CWE-78": {  # Command Injection
        "name": "OS Command Injection",
        "fixes": {
            "express": CodeFix(
                framework="Express.js", language="javascript",
                description="Use child_process.execFile with array arguments instead of exec with string",
                before_code='exec("ping " + userInput)',
                after_code='execFile("ping", ["-c", "1", userInput])',
            ),
            "python": CodeFix(
                framework="Python", language="python",
                description="Use subprocess with list arguments, never shell=True",
                before_code='os.system(f"ping {user_input}")',
                after_code='subprocess.run(["ping", "-c", "1", user_input], shell=False)',
            ),
        },
        "waf_rule": 'SecRule ARGS "@detectRCE" "id:1003,phase:2,deny,status:403,msg:\'Command Injection Attempt\'"',
    },
    "CWE-918": {  # SSRF
        "name": "Server-Side Request Forgery",
        "fixes": {
            "express": CodeFix(
                framework="Express.js", language="javascript",
                description="Validate and allowlist target URLs, block internal IPs",
                before_code='const resp = await fetch(req.body.url)',
                after_code='const url = new URL(req.body.url);\nconst blocked = ["127.0.0.1", "169.254.169.254", "localhost"];\nif (blocked.some(h => url.hostname.includes(h))) throw new Error("Blocked");\nconst resp = await fetch(url.toString())',
            ),
        },
        "waf_rule": 'SecRule ARGS "@rx (?:127\\.0\\.0\\.1|169\\.254\\.169\\.254|localhost)" "id:1004,phase:2,deny,status:403,msg:\'SSRF Attempt\'"',
    },
    "CWE-352": {  # CSRF
        "name": "Cross-Site Request Forgery",
        "fixes": {
            "express": CodeFix(
                framework="Express.js", language="javascript",
                description="Add CSRF token middleware",
                before_code='app.post("/transfer", handleTransfer)',
                after_code='const csrf = require("csurf");\napp.use(csrf({ cookie: true }));\napp.post("/transfer", handleTransfer)',
                dependencies=["csurf"],
            ),
            "django": CodeFix(
                framework="Django", language="python",
                description="Ensure CsrfViewMiddleware is enabled (default in Django)",
                before_code='# @csrf_exempt was added incorrectly',
                after_code='# Remove @csrf_exempt and ensure {% csrf_token %} in forms',
            ),
        },
    },
    "CWE-693": {  # Missing Security Headers
        "name": "Missing Security Headers",
        "header_configs": {
            "nginx": """# Add to nginx server block:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;""",
            "apache": """# Add to .htaccess or Apache config:
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()" """,
            "express": """// Add helmet middleware:
const helmet = require('helmet');
app.use(helmet());
// This sets: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, and more""",
        },
    },
}

# Map finding categories to CWE
CATEGORY_TO_CWE = {
    "sqli": "CWE-89", "sql injection": "CWE-89",
    "xss": "CWE-79", "cross-site scripting": "CWE-79",
    "cmdi": "CWE-78", "command injection": "CWE-78",
    "ssrf": "CWE-918", "csrf": "CWE-352",
    "headers": "CWE-693", "header": "CWE-693",
    "lfi": "CWE-22", "ssti": "CWE-1336",
    "idor": "CWE-639", "jwt": "CWE-347",
}


class FixGenerator:
    """Generate remediation plans for scan findings."""

    def generate_plan(self, finding, tech_stack: list[str] = None) -> RemediationPlan:
        category = (getattr(finding, 'category', '') or '').lower()
        cwe = getattr(finding, 'cwe', '') or CATEGORY_TO_CWE.get(category, '')
        title = getattr(finding, 'title', '') or ''

        plan = RemediationPlan(finding_title=title, cwe=cwe)

        template = FIX_TEMPLATES.get(cwe)
        if not template:
            return plan

        # Add code fixes for detected frameworks
        if "fixes" in template:
            for framework, fix in template["fixes"].items():
                if tech_stack and not self._matches_tech(framework, tech_stack):
                    continue
                plan.code_fixes.append(fix)
            # If no tech detected, include all fixes
            if not plan.code_fixes:
                plan.code_fixes = list(template["fixes"].values())

        # Add WAF rule
        if "waf_rule" in template:
            plan.waf_rules.append(template["waf_rule"])

        # Add header configs
        if "header_configs" in template:
            for server, config in template["header_configs"].items():
                plan.header_configs.append(f"# {server.upper()}\n{config}")

        plan.priority = self._assess_priority(finding)
        plan.effort = self._assess_effort(cwe)

        return plan

    def generate_all(self, findings: list, tech_stack: list[str] = None) -> list[RemediationPlan]:
        plans = []
        seen_cwes = set()
        for f in findings:
            cwe = getattr(f, 'cwe', '') or ''
            category = (getattr(f, 'category', '') or '').lower()
            key = cwe or CATEGORY_TO_CWE.get(category, category)
            if key and key not in seen_cwes:
                seen_cwes.add(key)
                plans.append(self.generate_plan(f, tech_stack))
        return [p for p in plans if p.code_fixes or p.waf_rules or p.header_configs]

    @staticmethod
    def _matches_tech(framework: str, tech_stack: list[str]) -> bool:
        tech_lower = [t.lower() for t in tech_stack]
        fw = framework.lower()
        return any(fw in t or t in fw for t in tech_lower)

    @staticmethod
    def _assess_priority(finding) -> str:
        sev = str(getattr(finding, 'severity', '')).upper()
        if 'CRITICAL' in sev: return "IMMEDIATE"
        if 'HIGH' in sev: return "HIGH"
        if 'MEDIUM' in sev: return "MEDIUM"
        return "LOW"

    @staticmethod
    def _assess_effort(cwe: str) -> str:
        low_effort = {"CWE-693", "CWE-352"}  # Headers, CSRF tokens
        high_effort = {"CWE-89", "CWE-918"}  # Need code refactoring
        if cwe in low_effort: return "LOW"
        if cwe in high_effort: return "MEDIUM"
        return "LOW"
