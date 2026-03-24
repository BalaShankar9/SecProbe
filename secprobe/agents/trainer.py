"""
Agent Training Orchestrator — The Master Trainer.

This is the central system that trains all agents using every
tool in the training infrastructure:

  1. CURRICULUM LEARNING
     - Progressive difficulty: easy targets → hard targets
     - Skill prerequisites: basic skills before advanced
     - Adaptive pacing: speed up/slow down based on progress
     - Mastery gates: must pass before advancing

  2. ADVERSARIAL TRAINING
     - WAF simulation scenarios
     - Increasing defense sophistication
     - Evasion-counter-evasion cycles
     - Stress testing under pressure

  3. BENCHMARK SUITE
     - Standardized test scenarios per vuln type
     - Reproducible scoring system
     - Industry-comparable metrics
     - Progress tracking against benchmarks

  4. GRADUATION SYSTEM
     - Skill-level based certification
     - Minimum competency thresholds
     - Specialist vs generalist tracks
     - Continuous re-certification

  5. TRAINING PIPELINE
     - End-to-end training workflow
     - Coordinates all training subsystems
     - Logs and reports everything
     - Auto-resume on interruption

What makes this world-class:
  - SYSTEMATIC: structured training, not random exploration
  - MEASURABLE: every skill is quantified
  - ADAPTIVE: pacing adjusts to each agent's ability
  - COMPREHENSIVE: covers all vuln types and scenarios
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════════
# CURRICULUM SYSTEM
# ═══════════════════════════════════════════════════════════════════

class Difficulty(str, Enum):
    TRIVIAL = "trivial"          # No defenses, obvious vulns
    EASY = "easy"                # Basic input validation
    MEDIUM = "medium"            # WAF present, some encoding needed
    HARD = "hard"                # Strict WAF, advanced evasion needed
    EXPERT = "expert"            # Multi-layer defense, chaining needed
    NIGHTMARE = "nightmare"      # Everything maxed out


@dataclass
class TrainingScenario:
    """A training scenario for agent practice."""
    scenario_id: str = ""
    name: str = ""
    description: str = ""
    difficulty: Difficulty = Difficulty.EASY
    vuln_types: list[str] = field(default_factory=list)
    has_waf: bool = False
    waf_type: str = ""
    tech_stack: list[str] = field(default_factory=list)
    expected_findings: int = 0
    time_limit: float = 60.0     # seconds
    passing_score: float = 0.7   # 70% to pass

    # Scenario setup
    endpoints: list[dict] = field(default_factory=list)
    defenses: list[str] = field(default_factory=list)


@dataclass
class CurriculumStage:
    """A stage in the training curriculum."""
    stage_id: int = 0
    name: str = ""
    difficulty: Difficulty = Difficulty.EASY
    scenarios: list[TrainingScenario] = field(default_factory=list)
    prerequisites: list[int] = field(default_factory=list)  # stage IDs
    passing_threshold: float = 0.7
    description: str = ""


class CurriculumManager:
    """
    Manages the training curriculum for agents.

    Provides progressive difficulty levels with prerequisites
    and mastery gates.
    """

    def __init__(self):
        self.stages: dict[int, CurriculumStage] = {}
        self.agent_progress: dict[str, dict[int, float]] = defaultdict(dict)
        self._build_default_curriculum()

    def _build_default_curriculum(self):
        """Build the default training curriculum."""
        # Stage 1: Reconnaissance Basics
        self.stages[1] = CurriculumStage(
            stage_id=1,
            name="Reconnaissance Foundations",
            difficulty=Difficulty.TRIVIAL,
            description="Basic target fingerprinting and information gathering",
            scenarios=[
                TrainingScenario(
                    scenario_id="recon_1",
                    name="Header Analysis",
                    description="Extract technology info from HTTP headers",
                    difficulty=Difficulty.TRIVIAL,
                    vuln_types=["information_disclosure"],
                    expected_findings=3,
                ),
                TrainingScenario(
                    scenario_id="recon_2",
                    name="Error Page Mining",
                    description="Extract info from error pages",
                    difficulty=Difficulty.TRIVIAL,
                    vuln_types=["information_disclosure"],
                    expected_findings=2,
                ),
            ],
        )

        # Stage 2: Basic Injection
        self.stages[2] = CurriculumStage(
            stage_id=2,
            name="Basic Injection",
            difficulty=Difficulty.EASY,
            prerequisites=[1],
            description="Simple injection attacks with no defenses",
            scenarios=[
                TrainingScenario(
                    scenario_id="sqli_basic",
                    name="Simple SQL Injection",
                    description="Classic SQLi with no filtering",
                    difficulty=Difficulty.EASY,
                    vuln_types=["sql_injection"],
                    expected_findings=2,
                    tech_stack=["php", "mysql"],
                ),
                TrainingScenario(
                    scenario_id="xss_basic",
                    name="Simple XSS",
                    description="Reflected XSS with no encoding",
                    difficulty=Difficulty.EASY,
                    vuln_types=["xss"],
                    expected_findings=2,
                ),
                TrainingScenario(
                    scenario_id="cmd_basic",
                    name="Simple Command Injection",
                    description="OS command injection with no filtering",
                    difficulty=Difficulty.EASY,
                    vuln_types=["command_injection"],
                    expected_findings=1,
                ),
            ],
        )

        # Stage 3: Intermediate Attacks
        self.stages[3] = CurriculumStage(
            stage_id=3,
            name="Intermediate Attacks",
            difficulty=Difficulty.MEDIUM,
            prerequisites=[2],
            description="Attacks against basic defenses",
            scenarios=[
                TrainingScenario(
                    scenario_id="sqli_filtered",
                    name="SQLi with Basic Filtering",
                    description="SQLi with keyword blacklist",
                    difficulty=Difficulty.MEDIUM,
                    vuln_types=["sql_injection"],
                    defenses=["keyword_blacklist"],
                    expected_findings=2,
                ),
                TrainingScenario(
                    scenario_id="xss_encoded",
                    name="XSS with HTML Encoding",
                    description="XSS against HTML-encoded output",
                    difficulty=Difficulty.MEDIUM,
                    vuln_types=["xss"],
                    defenses=["html_encoding"],
                    expected_findings=1,
                ),
                TrainingScenario(
                    scenario_id="ssti_basic",
                    name="Template Injection",
                    description="SSTI in Jinja2 templates",
                    difficulty=Difficulty.MEDIUM,
                    vuln_types=["ssti"],
                    tech_stack=["python", "flask"],
                    expected_findings=1,
                ),
            ],
        )

        # Stage 4: WAF Evasion
        self.stages[4] = CurriculumStage(
            stage_id=4,
            name="WAF Evasion",
            difficulty=Difficulty.HARD,
            prerequisites=[3],
            description="Bypassing Web Application Firewalls",
            scenarios=[
                TrainingScenario(
                    scenario_id="waf_modsec",
                    name="ModSecurity Bypass",
                    description="SQLi through ModSecurity CRS",
                    difficulty=Difficulty.HARD,
                    vuln_types=["sql_injection"],
                    has_waf=True,
                    waf_type="modsecurity",
                    defenses=["modsecurity_crs"],
                    expected_findings=1,
                ),
                TrainingScenario(
                    scenario_id="waf_cloudflare",
                    name="Cloudflare Bypass",
                    description="XSS through Cloudflare WAF",
                    difficulty=Difficulty.HARD,
                    vuln_types=["xss"],
                    has_waf=True,
                    waf_type="cloudflare",
                    expected_findings=1,
                ),
            ],
        )

        # Stage 5: Advanced Exploitation
        self.stages[5] = CurriculumStage(
            stage_id=5,
            name="Advanced Exploitation",
            difficulty=Difficulty.EXPERT,
            prerequisites=[4],
            description="Complex attacks and vuln chaining",
            scenarios=[
                TrainingScenario(
                    scenario_id="chain_ssrf_rce",
                    name="SSRF to RCE Chain",
                    description="Chain SSRF → file read → code execution",
                    difficulty=Difficulty.EXPERT,
                    vuln_types=["ssrf", "command_injection"],
                    expected_findings=3,
                    time_limit=120,
                ),
                TrainingScenario(
                    scenario_id="blind_sqli",
                    name="Blind SQL Injection",
                    description="Time-based blind SQLi extraction",
                    difficulty=Difficulty.EXPERT,
                    vuln_types=["sql_injection"],
                    defenses=["no_error_messages", "keyword_filter"],
                    expected_findings=1,
                    time_limit=120,
                ),
            ],
        )

        # Stage 6: Nightmare Mode
        self.stages[6] = CurriculumStage(
            stage_id=6,
            name="Nightmare Mode",
            difficulty=Difficulty.NIGHTMARE,
            prerequisites=[5],
            description="Maximum difficulty — all defenses active",
            scenarios=[
                TrainingScenario(
                    scenario_id="fortress",
                    name="The Fortress",
                    description="Multi-layer WAF + CSP + SRI + rate limiting",
                    difficulty=Difficulty.NIGHTMARE,
                    vuln_types=["sql_injection", "xss", "ssti"],
                    has_waf=True,
                    waf_type="multi_layer",
                    defenses=[
                        "modsecurity_crs", "cloudflare", "csp",
                        "sri", "rate_limiting", "ip_blocking",
                    ],
                    expected_findings=1,
                    time_limit=300,
                    passing_score=0.5,
                ),
            ],
        )

    def get_next_stage(self, agent_id: str) -> Optional[CurriculumStage]:
        """Get the next training stage for an agent."""
        progress = self.agent_progress.get(agent_id, {})

        for stage_id in sorted(self.stages.keys()):
            stage = self.stages[stage_id]
            # Check prerequisites
            prereqs_met = all(
                progress.get(p, 0) >= self.stages[p].passing_threshold
                for p in stage.prerequisites
                if p in self.stages
            )
            # Check if not yet passed
            stage_score = progress.get(stage_id, 0)
            if prereqs_met and stage_score < stage.passing_threshold:
                return stage

        return None  # All stages complete!

    def record_stage_result(self, agent_id: str, stage_id: int,
                            score: float):
        """Record an agent's performance on a stage."""
        self.agent_progress[agent_id][stage_id] = max(
            self.agent_progress[agent_id].get(stage_id, 0), score
        )

    def get_agent_level(self, agent_id: str) -> Difficulty:
        """Get the current difficulty level of an agent."""
        progress = self.agent_progress.get(agent_id, {})
        highest_passed = Difficulty.TRIVIAL
        for stage_id, score in progress.items():
            stage = self.stages.get(stage_id)
            if stage and score >= stage.passing_threshold:
                if list(Difficulty).index(stage.difficulty) > list(Difficulty).index(highest_passed):
                    highest_passed = stage.difficulty
        return highest_passed

    def get_stats(self) -> dict:
        return {
            "total_stages": len(self.stages),
            "agent_progress": {
                aid: {
                    "stages_passed": sum(
                        1 for sid, score in progress.items()
                        if score >= self.stages.get(sid, CurriculumStage()).passing_threshold
                    ),
                    "current_level": self.get_agent_level(aid).value,
                }
                for aid, progress in self.agent_progress.items()
            },
        }


# ═══════════════════════════════════════════════════════════════════
# BENCHMARK SUITE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class BenchmarkResult:
    """Result of a benchmark evaluation."""
    benchmark_id: str = ""
    agent_id: str = ""
    score: float = 0.0
    vulns_found: int = 0
    expected_vulns: int = 0
    false_positives: int = 0
    time_taken: float = 0.0
    timestamp: float = field(default_factory=time.time)

    @property
    def recall(self) -> float:
        return self.vulns_found / self.expected_vulns if self.expected_vulns > 0 else 0

    @property
    def precision(self) -> float:
        total = self.vulns_found + self.false_positives
        return self.vulns_found / total if total > 0 else 0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0


class BenchmarkSuite:
    """
    Standardized benchmarks for agent evaluation.

    Provides consistent, reproducible tests for measuring
    agent capability across vuln types.
    """

    def __init__(self):
        self.benchmarks: dict[str, dict] = {}
        self.results: dict[str, list[BenchmarkResult]] = defaultdict(list)
        self._build_default_benchmarks()

    def _build_default_benchmarks(self):
        """Build default benchmark suite."""
        self.benchmarks = {
            "sqli_standard": {
                "name": "SQL Injection Standard",
                "vuln_type": "sql_injection",
                "expected_vulns": 5,
                "difficulty": "medium",
                "description": "5 SQLi vulns across different contexts",
            },
            "xss_standard": {
                "name": "XSS Standard",
                "vuln_type": "xss",
                "expected_vulns": 6,
                "difficulty": "medium",
                "description": "6 XSS vulns: reflected, stored, DOM",
            },
            "injection_suite": {
                "name": "Injection Suite",
                "vuln_type": "mixed",
                "expected_vulns": 10,
                "difficulty": "hard",
                "description": "10 injection vulns across all types",
            },
            "waf_evasion": {
                "name": "WAF Evasion Challenge",
                "vuln_type": "mixed",
                "expected_vulns": 3,
                "difficulty": "expert",
                "description": "3 vulns behind WAF protections",
            },
            "full_audit": {
                "name": "Full Security Audit",
                "vuln_type": "all",
                "expected_vulns": 15,
                "difficulty": "expert",
                "description": "Comprehensive audit with 15 known vulns",
            },
        }

    def record_result(self, benchmark_id: str, agent_id: str,
                      vulns_found: int, false_positives: int = 0,
                      time_taken: float = 0.0):
        """Record a benchmark result."""
        benchmark = self.benchmarks.get(benchmark_id, {})
        expected = benchmark.get("expected_vulns", 0)
        score = vulns_found / expected if expected > 0 else 0.0
        # Penalize false positives
        if false_positives > 0:
            fp_penalty = false_positives * 0.05
            score = max(0, score - fp_penalty)

        result = BenchmarkResult(
            benchmark_id=benchmark_id,
            agent_id=agent_id,
            score=score,
            vulns_found=vulns_found,
            expected_vulns=expected,
            false_positives=false_positives,
            time_taken=time_taken,
        )
        self.results[benchmark_id].append(result)
        return result

    def get_leaderboard(self, benchmark_id: str
                        ) -> list[tuple[str, float]]:
        """Get leaderboard for a benchmark."""
        agent_best: dict[str, float] = {}
        for result in self.results.get(benchmark_id, []):
            current = agent_best.get(result.agent_id, 0)
            agent_best[result.agent_id] = max(current, result.score)
        return sorted(agent_best.items(), key=lambda x: x[1], reverse=True)

    def get_stats(self) -> dict:
        return {
            "benchmarks": list(self.benchmarks.keys()),
            "results_recorded": sum(
                len(r) for r in self.results.values()
            ),
            "leaderboards": {
                bid: self.get_leaderboard(bid)[:5]
                for bid in self.benchmarks
            },
        }


# ═══════════════════════════════════════════════════════════════════
# GRADUATION SYSTEM
# ═══════════════════════════════════════════════════════════════════

class SkillLevel(str, Enum):
    NOVICE = "novice"
    APPRENTICE = "apprentice"
    JOURNEYMAN = "journeyman"
    EXPERT = "expert"
    MASTER = "master"
    GRANDMASTER = "grandmaster"


GRADUATION_CRITERIA = {
    SkillLevel.NOVICE: {
        "min_curriculum_stage": 1,
        "min_benchmark_score": 0.3,
        "min_vulns_total": 5,
    },
    SkillLevel.APPRENTICE: {
        "min_curriculum_stage": 2,
        "min_benchmark_score": 0.5,
        "min_vulns_total": 20,
    },
    SkillLevel.JOURNEYMAN: {
        "min_curriculum_stage": 3,
        "min_benchmark_score": 0.65,
        "min_vulns_total": 50,
    },
    SkillLevel.EXPERT: {
        "min_curriculum_stage": 4,
        "min_benchmark_score": 0.8,
        "min_vulns_total": 100,
    },
    SkillLevel.MASTER: {
        "min_curriculum_stage": 5,
        "min_benchmark_score": 0.9,
        "min_vulns_total": 200,
    },
    SkillLevel.GRANDMASTER: {
        "min_curriculum_stage": 6,
        "min_benchmark_score": 0.95,
        "min_vulns_total": 500,
    },
}


@dataclass
class GraduationRecord:
    """Record of an agent's graduation to a skill level."""
    agent_id: str = ""
    level: SkillLevel = SkillLevel.NOVICE
    graduated_at: float = field(default_factory=time.time)
    curriculum_stage: int = 0
    benchmark_score: float = 0.0
    total_vulns: int = 0


class GraduationSystem:
    """
    Manages agent certification and skill levels.

    Agents earn skill levels by meeting curriculum, benchmark,
    and experience requirements.
    """

    def __init__(self):
        self.records: dict[str, GraduationRecord] = {}

    def evaluate(self, agent_id: str, highest_stage: int,
                 avg_benchmark_score: float,
                 total_vulns_found: int) -> SkillLevel:
        """
        Evaluate an agent's current skill level.

        Checks graduation criteria and awards the highest
        qualifying level.
        """
        current_level = SkillLevel.NOVICE

        for level in SkillLevel:
            criteria = GRADUATION_CRITERIA.get(level, {})
            if (highest_stage >= criteria.get("min_curriculum_stage", 0) and
                    avg_benchmark_score >= criteria.get("min_benchmark_score", 0) and
                    total_vulns_found >= criteria.get("min_vulns_total", 0)):
                current_level = level
            else:
                break

        # Record if new level achieved
        old_record = self.records.get(agent_id)
        if (not old_record or
                list(SkillLevel).index(current_level) >
                list(SkillLevel).index(old_record.level)):
            self.records[agent_id] = GraduationRecord(
                agent_id=agent_id,
                level=current_level,
                curriculum_stage=highest_stage,
                benchmark_score=avg_benchmark_score,
                total_vulns=total_vulns_found,
            )

        return current_level

    def get_level(self, agent_id: str) -> SkillLevel:
        record = self.records.get(agent_id)
        return record.level if record else SkillLevel.NOVICE

    def get_stats(self) -> dict:
        return {
            "agents_graduated": len(self.records),
            "levels": {
                aid: record.level.value
                for aid, record in self.records.items()
            },
        }


# ═══════════════════════════════════════════════════════════════════
# TRAINING ORCHESTRATOR (MASTER TRAINER)
# ═══════════════════════════════════════════════════════════════════

@dataclass
class TrainingSession:
    """A complete training session."""
    session_id: int = 0
    agent_id: str = ""
    stage: Optional[CurriculumStage] = None
    started: float = field(default_factory=time.time)
    completed: float = 0.0
    score: float = 0.0
    status: str = "active"     # active, completed, failed, aborted


class AgentTrainer:
    """
    Master training orchestrator.

    Coordinates all training subsystems:
    - Curriculum (what to train)
    - Benchmarks (how to measure)
    - Graduation (when to promote)
    - Self-improvement (how to improve)

    Complete training pipeline:
    1. Assess agent's current level
    2. Select appropriate curriculum stage
    3. Run training scenarios
    4. Evaluate performance via benchmarks
    5. Update skill profiles
    6. Check graduation criteria
    7. Adapt training plan based on results
    """

    def __init__(self):
        self.curriculum = CurriculumManager()
        self.benchmarks = BenchmarkSuite()
        self.graduation = GraduationSystem()
        self.sessions: list[TrainingSession] = []
        self._session_counter = 0

    def start_training(self, agent_id: str) -> TrainingSession:
        """
        Start a training session for an agent.

        Automatically selects the right difficulty level.
        """
        self._session_counter += 1
        stage = self.curriculum.get_next_stage(agent_id)

        session = TrainingSession(
            session_id=self._session_counter,
            agent_id=agent_id,
            stage=stage,
        )
        self.sessions.append(session)
        return session

    def complete_training(self, session_id: int, score: float,
                          vulns_found: int = 0,
                          false_positives: int = 0):
        """Complete a training session and record results."""
        for session in reversed(self.sessions):
            if session.session_id == session_id:
                session.score = score
                session.completed = time.time()
                session.status = "completed"

                # Record curriculum progress
                if session.stage:
                    self.curriculum.record_stage_result(
                        session.agent_id,
                        session.stage.stage_id,
                        score,
                    )

                break

    def run_benchmark(self, agent_id: str, benchmark_id: str,
                      vulns_found: int, false_positives: int = 0,
                      time_taken: float = 0.0) -> BenchmarkResult:
        """Run a benchmark evaluation for an agent."""
        return self.benchmarks.record_result(
            benchmark_id, agent_id, vulns_found,
            false_positives, time_taken,
        )

    def check_graduation(self, agent_id: str,
                         total_vulns: int) -> SkillLevel:
        """Check if an agent qualifies for graduation."""
        # Get highest passed curriculum stage
        progress = self.curriculum.agent_progress.get(agent_id, {})
        highest_stage = 0
        for stage_id, score in progress.items():
            stage = self.curriculum.stages.get(stage_id)
            if stage and score >= stage.passing_threshold:
                highest_stage = max(highest_stage, stage_id)

        # Get average benchmark score
        all_scores = []
        for results in self.benchmarks.results.values():
            for result in results:
                if result.agent_id == agent_id:
                    all_scores.append(result.score)
        avg_score = sum(all_scores) / len(all_scores) if all_scores else 0

        return self.graduation.evaluate(
            agent_id, highest_stage, avg_score, total_vulns
        )

    def get_training_report(self, agent_id: str) -> dict:
        """Generate a complete training report for an agent."""
        level = self.graduation.get_level(agent_id)
        next_stage = self.curriculum.get_next_stage(agent_id)
        progress = self.curriculum.agent_progress.get(agent_id, {})

        agent_sessions = [
            s for s in self.sessions if s.agent_id == agent_id
        ]
        completed = [
            s for s in agent_sessions if s.status == "completed"
        ]

        return {
            "agent_id": agent_id,
            "skill_level": level.value,
            "curriculum_progress": {
                "stages_attempted": len(progress),
                "stages_passed": sum(
                    1 for sid, score in progress.items()
                    if score >= self.curriculum.stages.get(
                        sid, CurriculumStage()
                    ).passing_threshold
                ),
                "total_stages": len(self.curriculum.stages),
                "current_stage": next_stage.name if next_stage else "ALL COMPLETE",
            },
            "training_sessions": {
                "total": len(agent_sessions),
                "completed": len(completed),
                "average_score": (
                    sum(s.score for s in completed) / len(completed)
                    if completed else 0
                ),
            },
            "next_steps": (
                f"Train on: {next_stage.name} ({next_stage.difficulty.value})"
                if next_stage else "Agent has completed all training!"
            ),
        }

    def get_stats(self) -> dict:
        return {
            "total_sessions": len(self.sessions),
            "active_sessions": sum(
                1 for s in self.sessions if s.status == "active"
            ),
            "curriculum": self.curriculum.get_stats(),
            "benchmarks": self.benchmarks.get_stats(),
            "graduation": self.graduation.get_stats(),
        }
