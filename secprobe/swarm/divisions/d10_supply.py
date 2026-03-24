"""
Division 10 — Supply Chain & Dependencies
============================================
25 agents covering CVE scanning across language ecosystems, dependency
confusion, typosquatting, SBOM generation, license risk, malware
detection, infrastructure CVEs, CI/CD pipeline security, and build
integrity verification.
"""

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


# ═══════════════════════════════════════════════════════════════════════
# CVE Scanners per Language (6)
# ═══════════════════════════════════════════════════════════════════════

_lang_cve = [
    _s("supply-cve-python", "Python Dependency CVE Scanner", 10,
       {Cap.PATTERN_MATCHING, Cap.TECH_FINGERPRINT},
       description="Scans requirements.txt, Pipfile.lock, and poetry.lock for Python packages with known CVEs in the NVD and PyPI advisory databases",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("python", "pip", "pipenv", "poetry"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=200, timeout=600,
       detection_patterns=(r"requirements\.txt", r"Pipfile\.lock", r"poetry\.lock"),
       tags=("supply-chain", "cve", "python", "pip")),

    _s("supply-cve-node", "Node.js Dependency CVE Scanner", 10,
       {Cap.PATTERN_MATCHING, Cap.TECH_FINGERPRINT},
       description="Scans package-lock.json, yarn.lock, and pnpm-lock.yaml for npm packages with known CVEs cross-referenced against npm audit and Snyk databases",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("nodejs", "npm", "yarn", "pnpm"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=200, timeout=600,
       detection_patterns=(r"package-lock\.json", r"yarn\.lock", r"pnpm-lock\.yaml"),
       tags=("supply-chain", "cve", "nodejs", "npm")),

    _s("supply-cve-java", "Java Dependency CVE Scanner", 10,
       {Cap.PATTERN_MATCHING, Cap.TECH_FINGERPRINT},
       description="Scans pom.xml, build.gradle, and gradle.lockfile for Java/Kotlin dependencies with known CVEs via OSS Index and Maven Central advisories",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("java", "maven", "gradle", "kotlin"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=200, timeout=600,
       detection_patterns=(r"pom\.xml", r"build\.gradle", r"\.jar"),
       tags=("supply-chain", "cve", "java", "maven")),

    _s("supply-cve-php", "PHP Dependency CVE Scanner", 10,
       {Cap.PATTERN_MATCHING, Cap.TECH_FINGERPRINT},
       description="Scans composer.lock for PHP packages with known vulnerabilities using the FriendsOfPHP security advisories database and Packagist metadata",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("php", "composer", "laravel", "symfony"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=150, timeout=600,
       detection_patterns=(r"composer\.lock", r"composer\.json", r"vendor/"),
       tags=("supply-chain", "cve", "php", "composer")),

    _s("supply-cve-ruby", "Ruby Dependency CVE Scanner", 10,
       {Cap.PATTERN_MATCHING, Cap.TECH_FINGERPRINT},
       description="Scans Gemfile.lock for Ruby gems with known CVEs using the ruby-advisory-db and RubySec feeds",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("ruby", "rails", "bundler"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=150, timeout=600,
       detection_patterns=(r"Gemfile\.lock", r"Gemfile", r"\.gemspec"),
       tags=("supply-chain", "cve", "ruby", "bundler")),

    _s("supply-cve-dotnet", ".NET Dependency CVE Scanner", 10,
       {Cap.PATTERN_MATCHING, Cap.TECH_FINGERPRINT},
       description="Scans packages.config, .csproj PackageReference, and NuGet lock files for .NET packages with known CVEs from GitHub Advisory Database",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("dotnet", "csharp", "nuget", "aspnet"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=150, timeout=600,
       detection_patterns=(r"packages\.config", r"PackageReference", r"\.csproj"),
       tags=("supply-chain", "cve", "dotnet", "nuget")),
]

# ═══════════════════════════════════════════════════════════════════════
# Specialized CVE Scanners (3)
# ═══════════════════════════════════════════════════════════════════════

_specialized_cve = [
    _s("supply-cve-wordpress", "WordPress Plugin/Theme CVE Scanner", 10,
       {Cap.PATTERN_MATCHING, Cap.TECH_FINGERPRINT, Cap.HTTP_PROBE},
       description="Identifies installed WordPress plugins and themes, then cross-references versions against WPScan Vulnerability Database for known exploits",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("wordpress",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=300, timeout=600,
       detection_patterns=(r"wp-content/plugins/", r"wp-content/themes/", r"readme\.txt"),
       tags=("supply-chain", "cve", "wordpress", "plugin")),

    _s("supply-cve-jslib", "JavaScript Frontend Library CVE Scanner", 10,
       {Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING, Cap.HTTP_PROBE},
       description="Fingerprints client-side JavaScript libraries (jQuery, Lodash, Moment, Bootstrap) and maps detected versions to known CVEs via Retire.js database",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("jquery", "lodash", "moment", "bootstrap", "angular"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"jQuery\s+v?\d+\.\d+", r"lodash\s+\d+\.\d+", r"Bootstrap\s+v?\d+"),
       tags=("supply-chain", "cve", "javascript", "frontend")),

    _s("supply-cve-infra-server", "Apache/Nginx CVE Scanner", 10,
       {Cap.TECH_FINGERPRINT, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Fingerprints Apache httpd and Nginx versions from headers and error pages, then maps to known CVEs including path traversal and request smuggling",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("apache", "nginx"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=300,
       detection_patterns=(r"Server:\s*(Apache|nginx)/[\d.]+", r"Apache/2\.\d", r"nginx/\d"),
       tags=("supply-chain", "cve", "apache", "nginx", "webserver")),
]

# ═══════════════════════════════════════════════════════════════════════
# Dependency Attack Vectors (2)
# ═══════════════════════════════════════════════════════════════════════

_dep_attacks = [
    _s("supply-dep-confusion", "Dependency Confusion Detector", 10,
       {Cap.PATTERN_MATCHING, Cap.API_INTERACTION},
       description="Detects dependency confusion risks by identifying private package names that could be claimed on public registries (npm, PyPI, RubyGems, NuGet)",
       attack_types=("dependency-confusion",), cwe_ids=("CWE-427",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"@[a-z0-9-]+/", r"--index-url", r"registry\s*="),
       tags=("supply-chain", "dependency-confusion", "namespace")),

    _s("supply-typosquat", "Typosquatting Package Detector", 10,
       {Cap.PATTERN_MATCHING, Cap.STATISTICAL_ANALYSIS},
       description="Computes Levenshtein distance and character swap permutations of declared dependencies to detect potential typosquatting packages in use",
       attack_types=("typosquatting",), cwe_ids=("CWE-427",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=100, timeout=300,
       tags=("supply-chain", "typosquatting", "package-name")),
]

# ═══════════════════════════════════════════════════════════════════════
# Package & License Auditing (4)
# ═══════════════════════════════════════════════════════════════════════

_audit = [
    _s("supply-lockfile-audit", "Lock File Integrity Auditor", 10,
       {Cap.PATTERN_MATCHING, Cap.STATISTICAL_ANALYSIS},
       description="Verifies lock file integrity: detects missing lock files, stale locks diverged from manifests, and tampered integrity hashes",
       attack_types=("lock-file-tampering",), cwe_ids=("CWE-345",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=20, timeout=180,
       detection_patterns=(r"integrity\s*:", r"resolved\s*:", r"sha512-"),
       tags=("supply-chain", "lockfile", "integrity", "hash")),

    _s("supply-sbom-gen", "SBOM Generator Agent", 10,
       {Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
       description="Generates Software Bill of Materials in CycloneDX/SPDX format from detected manifests, providing full transitive dependency inventory",
       attack_types=(),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=50, timeout=300,
       tags=("supply-chain", "sbom", "cyclonedx", "spdx", "inventory")),

    _s("supply-outdated", "Outdated Package Detector", 10,
       {Cap.PATTERN_MATCHING, Cap.API_INTERACTION},
       description="Identifies packages more than one major version behind latest, flagging those with missing security patches and EOL runtimes",
       attack_types=("outdated-dependency",), cwe_ids=("CWE-1104",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=200, timeout=600,
       tags=("supply-chain", "outdated", "version", "eol")),

    _s("supply-license-risk", "License Compliance Risk Agent", 10,
       {Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
       description="Scans dependency tree for restrictive licenses (GPL, AGPL, SSPL) that conflict with project licensing and flags unknown/missing licenses",
       attack_types=("license-violation",),
       min_mode=Mode.RECON, priority=Pri.LOW, max_requests=50, timeout=300,
       tags=("supply-chain", "license", "compliance", "gpl")),
]

# ═══════════════════════════════════════════════════════════════════════
# Malware & Infrastructure CVEs (4)
# ═══════════════════════════════════════════════════════════════════════

_infra = [
    _s("supply-malware-detect", "Dependency Malware Detector", 10,
       {Cap.PATTERN_MATCHING, Cap.JS_ANALYSIS, Cap.STATISTICAL_ANALYSIS},
       description="Detects suspicious patterns in dependencies: install scripts executing network calls, obfuscated code, environment variable exfiltration, and known malware signatures",
       attack_types=("malicious-package",), cwe_ids=("CWE-506",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=100, timeout=600,
       detection_patterns=(
           r"preinstall\s*:",
           r"postinstall\s*:",
           r"eval\s*\(\s*Buffer\.from",
           r"child_process",
       ),
       tags=("supply-chain", "malware", "backdoor", "install-script")),

    _s("supply-cve-openssl", "OpenSSL CVE Scanner", 10,
       {Cap.TECH_FINGERPRINT, Cap.PATTERN_MATCHING},
       description="Detects OpenSSL versions via TLS handshake fingerprinting and banner analysis, mapping to critical CVEs like Heartbleed, CCS injection, and padding oracle",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395", "CWE-326"),
       target_technologies=("openssl", "libressl", "boringssl"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=30, timeout=300,
       detection_patterns=(r"OpenSSL/[\d.]+[a-z]?", r"LibreSSL/[\d.]+"),
       tags=("supply-chain", "cve", "openssl", "tls")),

    _s("supply-cve-framework", "Web Framework CVE Scanner", 10,
       {Cap.TECH_FINGERPRINT, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Fingerprints web frameworks (Django, Rails, Spring Boot, Express, Laravel) and maps versions to known CVEs for RCE, auth bypass, and deserialization",
       attack_types=("known-vulnerability",), cwe_ids=("CWE-1395",),
       target_technologies=("django", "rails", "spring", "express", "laravel", "flask"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(
           r"django/[\d.]+", r"Rails\s+[\d.]+", r"Spring Boot\s+[\d.]+",
           r"X-Powered-By:\s*Express",
       ),
       tags=("supply-chain", "cve", "framework", "rce")),

    _s("supply-docker-image", "Docker Image Vulnerability Scanner", 10,
       {Cap.PATTERN_MATCHING, Cap.TECH_FINGERPRINT},
       description="Analyzes Dockerfiles and image manifests for base images with known CVEs, running as root, exposed secrets, and unpatched OS packages",
       attack_types=("container-vulnerability",), cwe_ids=("CWE-1395", "CWE-250"),
       target_technologies=("docker", "containerd", "podman"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=600,
       detection_patterns=(r"FROM\s+\S+:\S+", r"USER\s+root", r"COPY.*\.env"),
       tags=("supply-chain", "docker", "container", "base-image")),
]

# ═══════════════════════════════════════════════════════════════════════
# CI/CD & Build Pipeline Security (4)
# ═══════════════════════════════════════════════════════════════════════

_cicd = [
    _s("supply-gha-audit", "GitHub Actions Security Auditor", 10,
       {Cap.PATTERN_MATCHING, Cap.CRAWL},
       description="Audits GitHub Actions workflows for unpinned third-party actions, script injection via untrusted inputs, excessive permissions, and secret exposure risks",
       attack_types=("cicd-misconfiguration",), cwe_ids=("CWE-78", "CWE-829"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=300,
       detection_patterns=(
           r"uses:\s+\S+@(?!sha256:)[a-zA-Z]",
           r"\$\{\{\s*github\.event\.",
           r"permissions:\s*write-all",
       ),
       tags=("supply-chain", "github-actions", "cicd", "workflow")),

    _s("supply-ci-pipeline", "CI Pipeline Security Agent", 10,
       {Cap.PATTERN_MATCHING, Cap.CRAWL},
       description="Audits CI pipeline configs (Jenkinsfile, .gitlab-ci.yml, CircleCI, Travis) for secret leakage, untrusted script execution, and insecure artifact storage",
       attack_types=("cicd-misconfiguration",), cwe_ids=("CWE-522", "CWE-829"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=300,
       detection_patterns=(
           r"Jenkinsfile", r"\.gitlab-ci\.yml", r"\.circleci/config",
           r"echo\s+\$\{?[A-Z_]*SECRET",
       ),
       tags=("supply-chain", "ci", "jenkins", "gitlab", "pipeline")),

    _s("supply-registry-confusion", "Package Registry Confusion Agent", 10,
       {Cap.API_INTERACTION, Cap.PATTERN_MATCHING},
       description="Tests for registry confusion attacks where internal .npmrc/.pypirc configurations allow substitution from untrusted public registries",
       attack_types=("registry-confusion",), cwe_ids=("CWE-427",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=50, timeout=300,
       detection_patterns=(r"\.npmrc", r"\.pypirc", r"registry\s*=\s*http"),
       tags=("supply-chain", "registry", "confusion", "npmrc")),

    _s("supply-build-integrity", "Build Artifact Integrity Agent", 10,
       {Cap.PATTERN_MATCHING, Cap.STATISTICAL_ANALYSIS},
       description="Verifies build reproducibility and artifact integrity: checks for signed releases, provenance attestations (SLSA), and tampered build outputs",
       attack_types=("build-tampering",), cwe_ids=("CWE-345", "CWE-494"),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=30, timeout=300,
       detection_patterns=(r"cosign", r"sigstore", r"in-toto", r"slsa-provenance"),
       tags=("supply-chain", "build", "integrity", "slsa", "signing")),
]

# ═══════════════════════════════════════════════════════════════════════
# Version Pinning & Commander (2)
# ═══════════════════════════════════════════════════════════════════════

_control = [
    _s("supply-version-pinning", "Version Pinning Auditor", 10,
       {Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
       description="Audits dependency manifests for unpinned versions (^, ~, >=, *) that allow silent upgrades to potentially compromised releases",
       attack_types=("unpinned-dependency",), cwe_ids=("CWE-1104",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=20, timeout=180,
       detection_patterns=(r"[\"'][\^~>=*]", r"latest", r"\*"),
       tags=("supply-chain", "version-pinning", "semver")),

    _s("supply-commander", "Supply Chain Division Commander", 10,
       {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
       description="Orchestrates Division 10 agents, correlates cross-ecosystem CVE findings, prioritizes by exploitability, and produces unified supply chain risk reports",
       attack_types=(),
       min_mode=Mode.RECON, priority=Pri.CRITICAL, max_requests=0, timeout=3600,
       tags=("commander", "coordination", "division-10")),
]


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def agents() -> list[AgentSpec]:
    """Return all 25 Division 10 (Supply Chain & Dependencies) agents."""
    all_agents = (
        _lang_cve
        + _specialized_cve
        + _dep_attacks
        + _audit
        + _infra
        + _cicd
        + _control
    )
    assert len(all_agents) == 25, f"Division 10 must have exactly 25 agents, got {len(all_agents)}"
    return all_agents
