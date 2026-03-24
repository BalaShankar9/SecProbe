"""
SecProbe Agent Swarm — Autonomous multi-agent security testing.

This package implements the agent swarm architecture that makes
SecProbe fundamentally different from every other scanner:

  Traditional Scanner:
    for scanner in scanners:
      for url in urls:
        for payload in payloads:
          send(payload)
          check(response)

  SecProbe Agent Swarm:
    coordinator.deploy(target)
      → ReconAgent maps attack surface
      → InjectionAgent tests high-value targets first
      → EvasionAgent adapts when WAF blocks
      → ExploitAgent chains findings into attack paths
      → All agents share knowledge in real-time
      → NeuralMemory retains & consolidates experience
      → RLSystem learns optimal strategies via reinforcement
      → EvolutionEngine breeds WAF-bypassing payloads
      → BehavioralProfiler models target behavior
      → KnowledgeTransferEngine shares knowledge across targets
      → SelfImprovementEngine auto-tunes everything
      → AgentTrainer orchestrates curriculum-based training

Components:
  base.py            — BaseAgent, AgentMessage, AgentMemory, MessageBus
  knowledge.py       — KnowledgeGraph (shared intelligence)
  reasoning.py       — ReasoningEngine (hypothesis → action pipeline)
  swarm.py           — SwarmCoordinator (multi-agent orchestration)
  recon_agent.py     — ReconAgent (attack surface mapping)
  injection_agent.py — InjectionAgent (adaptive injection testing)
  exploit_agent.py   — ExploitAgent (vulnerability chaining)
  evasion_agent.py   — EvasionAgent (defense adaptation)

Training & Fine-tuning:
  neural_memory.py   — Multi-layer cognitive memory (episodic/semantic/procedural/working)
  reinforcement.py   — Reinforcement learning (Q-learning, bandits, policy gradient)
  evolution.py       — Genetic payload evolution (19 mutation types, fitness selection)
  profiler.py        — Behavioral profiling (timing, WAF model, response fingerprinting)
  transfer.py        — Cross-target knowledge transfer (similarity, payload DB, strategies)
  self_improve.py    — Self-improvement engine (A/B testing, meta-learning, skill assessment)
  trainer.py         — Training orchestrator (curriculum, benchmarks, graduation)
"""

from secprobe.agents.base import (
    AgentGoal,
    AgentMemory,
    AgentMessage,
    AgentState,
    Action,
    ActionResult,
    ActionType,
    BaseAgent,
    GoalStatus,
    Hypothesis,
    MessageBus,
    MessageType,
    Observation,
    Severity,
)
from secprobe.agents.knowledge import (
    EntityType,
    KnowledgeEntity,
    KnowledgeGraph,
    KnowledgeRelation,
    RelationType,
)
from secprobe.agents.reasoning import (
    ActionPlanner,
    HypothesisGenerator,
    PriorityScorer,
    ReasoningEngine,
    RiskEvaluator,
    RiskLevel,
    Strategy,
    StrategyAdapter,
)
from secprobe.agents.swarm import (
    SwarmConfig,
    SwarmCoordinator,
    SwarmMode,
    SwarmResult,
)
from secprobe.agents.recon_agent import ReconAgent
from secprobe.agents.injection_agent import InjectionAgent
from secprobe.agents.exploit_agent import ExploitAgent
from secprobe.agents.evasion_agent import EvasionAgent

# Training & Fine-tuning
from secprobe.agents.neural_memory import (
    EpisodicMemory,
    FeatureExtractor,
    MemoryEntry,
    NeuralMemory,
    ProceduralMemory,
    SemanticConcept,
    SemanticMemory,
    WorkingMemory,
)
from secprobe.agents.reinforcement import (
    ExperienceReplayBuffer,
    MultiArmedBandit,
    PolicyGradient,
    QLearningEngine,
    RLSystem,
    RewardShaper,
    RewardSignal,
    ScanAction,
    ScanState,
)
from secprobe.agents.evolution import (
    CrossoverOperator,
    EvolutionEngine,
    FitnessFunction,
    MutationOperator,
    MutationType,
    PayloadGenome,
    PayloadSelector,
    SelectionStrategy,
)
from secprobe.agents.profiler import (
    BehavioralProfiler,
    ResponseFingerprinter,
    TimingProfile,
    TimingProfiler,
    WAFBehaviorModel,
)
from secprobe.agents.transfer import (
    KnowledgeTransferEngine,
    PayloadDatabase,
    SimilarityEngine,
    StrategyLibrary,
    TargetFingerprint,
)
from secprobe.agents.self_improve import (
    ABTestingFramework,
    HyperparameterTuner,
    MetaLearner,
    PerformanceTracker,
    SelfImprovementEngine,
    SkillAssessor,
)
from secprobe.agents.trainer import (
    AgentTrainer,
    BenchmarkSuite,
    CurriculumManager,
    Difficulty,
    GraduationSystem,
    SkillLevel,
    TrainingScenario,
)


AGENT_REGISTRY: dict[str, type[BaseAgent]] = {
    "recon": ReconAgent,
    "injection": InjectionAgent,
    "exploit": ExploitAgent,
    "evasion": EvasionAgent,
}


__all__ = [
    # Base
    "AgentGoal", "AgentMemory", "AgentMessage", "AgentState",
    "Action", "ActionResult", "ActionType", "BaseAgent",
    "GoalStatus", "Hypothesis", "MessageBus", "MessageType",
    "Observation", "Severity",
    # Knowledge
    "EntityType", "KnowledgeEntity", "KnowledgeGraph",
    "KnowledgeRelation", "RelationType",
    # Reasoning
    "ActionPlanner", "HypothesisGenerator", "PriorityScorer",
    "ReasoningEngine", "RiskEvaluator", "RiskLevel",
    "Strategy", "StrategyAdapter",
    # Swarm
    "SwarmConfig", "SwarmCoordinator", "SwarmMode", "SwarmResult",
    # Agents
    "ReconAgent", "InjectionAgent", "ExploitAgent", "EvasionAgent",
    # Neural Memory
    "EpisodicMemory", "FeatureExtractor", "MemoryEntry",
    "NeuralMemory", "ProceduralMemory", "SemanticConcept",
    "SemanticMemory", "WorkingMemory",
    # Reinforcement Learning
    "ExperienceReplayBuffer", "MultiArmedBandit", "PolicyGradient",
    "QLearningEngine", "RLSystem", "RewardShaper", "RewardSignal",
    "ScanAction", "ScanState",
    # Evolution
    "CrossoverOperator", "EvolutionEngine", "FitnessFunction",
    "MutationOperator", "MutationType", "PayloadGenome",
    "PayloadSelector", "SelectionStrategy",
    # Profiler
    "BehavioralProfiler", "ResponseFingerprinter",
    "TimingProfile", "TimingProfiler", "WAFBehaviorModel",
    # Transfer
    "KnowledgeTransferEngine", "PayloadDatabase",
    "SimilarityEngine", "StrategyLibrary", "TargetFingerprint",
    # Self-Improvement
    "ABTestingFramework", "HyperparameterTuner", "MetaLearner",
    "PerformanceTracker", "SelfImprovementEngine", "SkillAssessor",
    # Trainer
    "AgentTrainer", "BenchmarkSuite", "CurriculumManager",
    "Difficulty", "GraduationSystem", "SkillLevel", "TrainingScenario",
    # Registry
    "AGENT_REGISTRY",
]
