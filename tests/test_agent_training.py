"""
Comprehensive tests for the Agent Training & Fine-tuning infrastructure.

Tests cover all 7 new training modules:
  1. neural_memory.py — Multi-layer cognitive memory
  2. reinforcement.py — Reinforcement learning system
  3. evolution.py     — Genetic payload evolution
  4. profiler.py      — Behavioral profiling
  5. transfer.py      — Cross-target knowledge transfer
  6. self_improve.py  — Self-improvement engine
  7. trainer.py       — Training orchestrator
"""

import math
import random
import time

import pytest

# ═══════════════════════════════════════════════════════════════════
# NEURAL MEMORY TESTS
# ═══════════════════════════════════════════════════════════════════

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
from secprobe.agents.base import Observation, Action, ActionType, ActionResult


class TestFeatureExtractor:
    def test_observation_vector(self):
        ext = FeatureExtractor()
        obs = Observation(
            observation_type="response",
            url="http://test.com/login",
            raw_response_code=200,
        )
        vec = ext.extract(obs)
        assert len(vec) == 64
        assert all(isinstance(v, float) for v in vec)

    def test_different_observation_vector(self):
        ext = FeatureExtractor()
        obs = Observation(
            observation_type="vulnerability",
            url="http://test.com/admin",
            parameter="id",
            raw_response_code=500,
            detail="sql injection detected",
        )
        vec = ext.extract(obs)
        assert len(vec) == 64
        assert all(isinstance(v, float) for v in vec)
        # SQL signal should be detected in detail
        assert vec[40] == 1.0  # "sql" in detail

    def test_cosine_similarity(self):
        ext = FeatureExtractor()
        a = [1.0, 0.0, 0.0]
        b = [1.0, 0.0, 0.0]
        assert ext.cosine_similarity(a, b) == pytest.approx(1.0)

        c = [0.0, 1.0, 0.0]
        assert ext.cosine_similarity(a, c) == pytest.approx(0.0)

    def test_cosine_similarity_zero_vectors(self):
        ext = FeatureExtractor()
        assert ext.cosine_similarity([0, 0, 0], [0, 0, 0]) == 0.0


class TestMemoryEntry:
    def test_strength_decays(self):
        entry = MemoryEntry(
            id="test_1",
            content={"test": True},
            vector=[1.0] * 64,
            importance=1.0,
        )
        initial = entry.strength
        assert initial > 0

        # Simulate age by manipulating creation_time
        entry.creation_time -= 7200  # 2 hours ago
        aged = entry.strength
        assert aged < initial

    def test_reinforce_boosts_strength(self):
        entry = MemoryEntry(
            id="test_2",
            content={"test": True},
            vector=[1.0] * 64,
            importance=0.5,
        )
        before = entry.strength
        entry.reinforce(0.3)
        after = entry.strength
        assert after >= before

    def test_is_alive(self):
        entry = MemoryEntry(
            id="test_3",
            content={"test": True},
            vector=[1.0] * 64,
            importance=1.0,
        )
        assert entry.is_alive


class TestEpisodicMemory:
    def test_store_and_recall(self):
        mem = EpisodicMemory(capacity=100)
        obs = Observation(
            observation_type="response",
            url="http://test.com",
            raw_response_code=200,
        )
        entry_id = mem.store(obs)
        assert len(mem.entries) == 1
        assert entry_id

    def test_recall_similar(self):
        mem = EpisodicMemory(capacity=100)
        for i in range(5):
            obs = Observation(
                observation_type="response",
                url=f"http://test.com/page{i}",
                raw_response_code=200,
            )
            mem.store(obs)

        query = Observation(
            observation_type="response",
            url="http://test.com/page0",
            raw_response_code=200,
        )
        results = mem.recall_similar(query, top_k=3)
        assert len(results) <= 3

    def test_recall_by_category(self):
        mem = EpisodicMemory(capacity=100)
        obs1 = Observation(observation_type="response", url="http://a.com")
        obs2 = Observation(observation_type="error", url="http://b.com")
        mem.store(obs1)
        mem.store(obs2)
        results = mem.recall_by_category("response")
        assert len(results) >= 1

    def test_garbage_collect(self):
        mem = EpisodicMemory(capacity=10)
        for i in range(15):
            obs = Observation(observation_type="response", url=f"http://t.com/{i}")
            mem.store(obs)
        removed = mem.garbage_collect()
        assert isinstance(removed, int)


class TestSemanticMemory:
    def test_learn_concept(self):
        mem = SemanticMemory()
        obs = Observation(observation_type="technology", url="http://t.com")
        concept_id = mem.learn(obs)
        assert isinstance(concept_id, str)

    def test_classify(self):
        mem = SemanticMemory(similarity_threshold=0.3)
        # Learn enough observations to build concepts
        for i in range(10):
            obs = Observation(
                observation_type="response",
                url=f"http://test.com/{i}",
                raw_response_code=200,
            )
            mem.learn(obs)
        # Classify takes an Observation, returns list of (concept_id, similarity)
        query = Observation(
            observation_type="response",
            url="http://test.com/0",
            raw_response_code=200,
        )
        result = mem.classify(query)
        assert isinstance(result, list)

    def test_get_strong_concepts(self):
        mem = SemanticMemory(similarity_threshold=0.3)
        for i in range(15):
            obs = Observation(
                observation_type="response",
                url=f"http://test.com/{i}",
                raw_response_code=200,
            )
            mem.learn(obs)
        strong = mem.get_strong_concepts()
        assert isinstance(strong, list)


class TestProceduralMemory:
    def test_store_sequence(self):
        mem = ProceduralMemory(max_sequences=100)
        actions = [
            Action(action_type=ActionType.FUZZ, target_url="t", payload="p"),
        ]
        seq_id = mem.store_sequence(
            actions, outcome="success", vuln_type="sql_injection"
        )
        assert len(mem.sequences) == 1
        assert isinstance(seq_id, str)

    def test_recall_for_context(self):
        mem = ProceduralMemory(max_sequences=100)
        actions = [
            Action(action_type=ActionType.FUZZ, target_url="t", payload="p"),
        ]
        mem.store_sequence(
            actions, outcome="success", vuln_type="sql_injection"
        )
        results = mem.recall_for_context(vuln_type="sql_injection")
        assert len(results) >= 1


class TestWorkingMemory:
    def test_slot_management(self):
        wm = WorkingMemory(capacity=5)
        for i in range(7):
            wm.focus(f"item_{i}", {"data": i}, priority=float(i))
        # Should not exceed capacity
        assert len(wm.slots) <= 5

    def test_goal_stack(self):
        wm = WorkingMemory()
        wm.push_goal({"type": "find_vulns"})
        wm.push_goal({"type": "test_sqli"})
        top = wm.peek_goal()
        assert top["type"] == "test_sqli"
        wm.pop_goal()
        top = wm.peek_goal()
        assert top["type"] == "find_vulns"

    def test_context_window(self):
        wm = WorkingMemory()
        wm.add_context("item1")
        wm.add_context("item2")
        assert len(wm.context_window) == 2


class TestNeuralMemory:
    def test_full_pipeline(self):
        nm = NeuralMemory()
        obs = Observation(observation_type="response", raw_response_code=200)
        nm.observe(obs)
        assert nm.episodic.entries  # Something was stored

    def test_recall(self):
        nm = NeuralMemory()
        for i in range(5):
            obs = Observation(
                observation_type="response",
                url=f"http://test.com/{i}",
            )
            nm.observe(obs)
        query = Observation(observation_type="response", url="http://test.com/0")
        results = nm.recall(query, top_k=3)
        assert isinstance(results, dict)


# ═══════════════════════════════════════════════════════════════════
# REINFORCEMENT LEARNING TESTS
# ═══════════════════════════════════════════════════════════════════

from secprobe.agents.reinforcement import (
    Experience,
    ExperienceReplayBuffer,
    MultiArmedBandit,
    PolicyGradient,
    QLearningEngine,
    RLSystem,
    RewardShaper,
    RewardSignal,
    ScanAction,
    ScanPhase,
    ScanState,
)


class TestScanState:
    def test_to_key(self):
        state = ScanState()
        key = state.to_key()
        assert isinstance(key, str)

    def test_to_vector(self):
        state = ScanState(phase=ScanPhase.ACTIVE, waf_type="cloudflare")
        vec = state.to_vector()
        assert len(vec) == 11
        assert all(isinstance(v, float) for v in vec)


class TestScanAction:
    def test_all_actions(self):
        actions = ScanAction.all_actions()
        assert len(actions) > 0
        assert all(isinstance(a, ScanAction) for a in actions)

    def test_to_key(self):
        action = ScanAction(scan_type="xss", strategy="balanced")
        key = action.to_key()
        assert "xss" in key


class TestRewardShaper:
    def test_compute_reward_with_vulns(self):
        shaper = RewardShaper()
        result = ActionResult(
            success=True,
            findings=[{"severity": "CRITICAL", "type": "sqli"}],
            observations=[],
            requests_made=1,
        )
        reward = shaper.compute_reward(result)
        assert reward > 0

    def test_compute_reward_with_signals(self):
        shaper = RewardShaper()
        result = ActionResult(success=False, observations=[], requests_made=1)
        reward = shaper.compute_reward(result, [RewardSignal.WAF_BLOCKED])
        assert reward < 0

    def test_reward_table_values(self):
        shaper = RewardShaper()
        assert RewardShaper.REWARD_TABLE[RewardSignal.VULN_CONFIRMED] == 10.0
        assert RewardShaper.REWARD_TABLE[RewardSignal.FALSE_POSITIVE] == -8.0


class TestExperienceReplayBuffer:
    def test_add_and_sample(self):
        buf = ExperienceReplayBuffer(capacity=100)
        for i in range(20):
            exp = Experience(
                state=ScanState(phase=ScanPhase.RECON),
                action=ScanAction(scan_type="xss"),
                reward=1.0,
                next_state=ScanState(phase=ScanPhase.CANARY),
                done=False,
            )
            buf.add(exp)
        batch = buf.sample(5)
        assert len(batch) == 5

    def test_capacity_limit(self):
        buf = ExperienceReplayBuffer(capacity=10)
        for i in range(20):
            exp = Experience(
                state=ScanState(),
                action=ScanAction(),
                reward=1.0,
                next_state=ScanState(),
            )
            buf.add(exp)
        assert len(buf.buffer) <= 10


class TestQLearningEngine:
    def test_select_action(self):
        q = QLearningEngine()
        state = ScanState(phase=ScanPhase.ACTIVE)
        actions = [ScanAction(scan_type="xss"), ScanAction(scan_type="sqli")]
        action = q.select_action(state, actions)
        assert isinstance(action, ScanAction)

    def test_update(self):
        q = QLearningEngine(learning_rate=0.5)
        state = ScanState()
        action = ScanAction(scan_type="xss")
        next_state = ScanState(phase=ScanPhase.CANARY)
        q.update(state, action, 10.0, next_state, False)
        # Q-value should be updated
        key = state.to_key()
        assert key in q.q_table

    def test_export_and_load(self):
        q = QLearningEngine()
        state = ScanState()
        action = ScanAction(scan_type="xss")
        q.update(state, action, 5.0, state, False)
        data = q.export()
        q2 = QLearningEngine()
        q2.load(data)
        assert q2.q_table == q.q_table


class TestMultiArmedBandit:
    def test_select_and_update(self):
        bandit = MultiArmedBandit(algorithm="ucb1")
        bandit.add_arm("a")
        bandit.add_arm("b")
        bandit.add_arm("c")
        arm = bandit.select("default")
        assert arm in ["a", "b", "c"]
        bandit.update(arm, 1.0, context="default")
        # Verify the arm was updated
        arm_obj = bandit.arms["default"][arm]
        assert arm_obj.pulls == 1

    def test_thompson_sampling(self):
        bandit = MultiArmedBandit(algorithm="thompson")
        bandit.add_arm("x")
        bandit.add_arm("y")
        arm = bandit.select("default")
        assert arm in ["x", "y"]

    def test_contextual_bandit(self):
        bandit = MultiArmedBandit()
        bandit.add_arm("a", context="php")
        bandit.add_arm("b", context="php")
        arm = bandit.select(context="php")
        bandit.update(arm, 1.0, context="php")
        assert "php" in bandit.arms


class TestPolicyGradient:
    def test_select_mutation(self):
        pg = PolicyGradient()
        mutation = pg.select_mutation()
        assert isinstance(mutation, str)

    def test_update(self):
        pg = PolicyGradient()
        mutation = pg.select_mutation(context="default")
        pg.update("default", mutation, 1.0)
        # Should not crash, and stats should reflect update
        stats = pg.get_stats()
        assert stats["total_updates"] == 1


class TestRLSystem:
    def test_integration(self):
        rl = RLSystem()
        scanner = rl.select_scanner(tech="php")
        assert isinstance(scanner, str)

    def test_observe_result(self):
        rl = RLSystem()
        state = ScanState()
        action = ScanAction(scan_type="xss")
        result = ActionResult(
            success=True,
            findings=[{"severity": "HIGH", "type": "xss"}],
            observations=[],
            requests_made=1,
        )
        reward = rl.observe_result(state, action, result, ScanState(phase=ScanPhase.CANARY))
        assert isinstance(reward, float)

    def test_export_load(self):
        rl = RLSystem()
        data = rl.export()
        assert "q_table" in data
        assert "policy_theta" in data
        rl2 = RLSystem()
        rl2.load(data)


# ═══════════════════════════════════════════════════════════════════
# EVOLUTION TESTS
# ═══════════════════════════════════════════════════════════════════

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


class TestPayloadGenome:
    def test_creation(self):
        g = PayloadGenome(payload="' OR 1=1--")
        assert g.payload == "' OR 1=1--"
        assert g.generation == 0
        assert g.fitness == 0.0

    def test_record_test_updates_fitness(self):
        g = PayloadGenome(payload="test")
        g.record_test(bypassed_waf=True, triggered_vuln=True, was_blocked=False)
        g.record_test(bypassed_waf=True, triggered_vuln=True, was_blocked=False)
        g.record_test(bypassed_waf=False, triggered_vuln=False, was_blocked=True)
        assert g.tests_run == 3
        assert g.triggers == 2
        assert g.bypasses == 2
        assert g.blocks == 1
        assert g.fitness > 0

    def test_bypass_rate(self):
        g = PayloadGenome(payload="test")
        g.record_test(bypassed_waf=True, triggered_vuln=False, was_blocked=False)
        g.record_test(bypassed_waf=False, triggered_vuln=False, was_blocked=False)
        assert g.bypass_rate == pytest.approx(0.5)


class TestMutationOperator:
    def test_mutate_url_encode(self):
        # URL_ENCODE has a random chance to encode special chars
        # Use a payload with many special chars to guarantee mutation
        result = MutationOperator.mutate("'<>\";&|$()'", MutationType.URL_ENCODE)
        assert isinstance(result, str)
        assert len(result) >= 1

    def test_mutate_case_swap(self):
        result = MutationOperator.mutate("SELECT * FROM users", MutationType.CASE_SWAP)
        assert result.lower() == "select * from users"

    def test_all_mutation_types_dont_crash(self):
        payload = "' OR 1=1--"
        for mt in MutationType:
            result = MutationOperator.mutate(payload, mt)
            assert isinstance(result, str)
            assert len(result) > 0


class TestCrossoverOperator:
    def test_single_point(self):
        c1, c2 = CrossoverOperator.single_point("AAAA BBBB", "CCCC DDDD")
        assert isinstance(c1, str)
        assert isinstance(c2, str)
        assert len(c1) > 0
        assert len(c2) > 0

    def test_uniform(self):
        c1, c2 = CrossoverOperator.uniform("ABCDEF", "123456")
        assert len(c1) > 0
        assert len(c2) > 0


class TestFitnessFunction:
    def test_evaluate(self):
        ff = FitnessFunction()
        g = PayloadGenome(payload="' OR 1=1--")
        g.record_test(bypassed_waf=True, triggered_vuln=True, was_blocked=False)
        g.record_test(bypassed_waf=True, triggered_vuln=True, was_blocked=False)
        g.record_test(bypassed_waf=False, triggered_vuln=False, was_blocked=True)
        score = ff.evaluate(g)
        assert score > 0

    def test_novelty_score(self):
        ff = FitnessFunction()
        g = PayloadGenome(payload="unique_test_payload")
        pop = [PayloadGenome(payload="other")]
        score = FitnessFunction._novelty_score(g, pop)
        assert score >= 0


class TestPayloadSelector:
    def test_tournament(self):
        pop = [PayloadGenome(payload=f"p{i}") for i in range(10)]
        for i, g in enumerate(pop):
            g.fitness = float(i)
        winner = PayloadSelector.tournament(pop, k=3)
        assert isinstance(winner, PayloadGenome)

    def test_roulette(self):
        pop = [PayloadGenome(payload=f"p{i}") for i in range(10)]
        for i, g in enumerate(pop):
            g.fitness = float(i) + 0.1
        winner = PayloadSelector.roulette(pop)
        assert isinstance(winner, PayloadGenome)

    def test_rank(self):
        pop = [PayloadGenome(payload=f"p{i}") for i in range(10)]
        for i, g in enumerate(pop):
            g.fitness = float(i)
        winner = PayloadSelector.rank(pop)
        assert isinstance(winner, PayloadGenome)


class TestEvolutionEngine:
    def test_seed(self):
        engine = EvolutionEngine(population_size=10)
        engine.seed(["' OR 1=1--", "<script>alert(1)</script>"])
        assert len(engine.population) == 10

    def test_evolve(self):
        engine = EvolutionEngine(population_size=10)
        engine.seed(["' OR 1=1--", "<script>alert(1)</script>"])
        # Simulate some fitness via record_test
        for g in engine.population:
            g.record_test(bypassed_waf=True, triggered_vuln=True, was_blocked=False)
        new_gen = engine.evolve()
        assert len(new_gen) == 10
        assert engine.generation == 1

    def test_get_best(self):
        engine = EvolutionEngine(population_size=5)
        engine.seed(["test1", "test2"])
        for i, g in enumerate(engine.population):
            g.fitness = float(i)
        best = engine.get_best()
        assert best is not None
        assert best.fitness == max(g.fitness for g in engine.population)

    def test_get_elite(self):
        engine = EvolutionEngine(population_size=10)
        engine.seed(["test1", "test2", "test3"])
        for i, g in enumerate(engine.population):
            g.fitness = float(i)
        elite = engine.get_elite(3)
        assert len(elite) == 3
        assert elite[0].fitness >= elite[1].fitness


# ═══════════════════════════════════════════════════════════════════
# PROFILER TESTS
# ═══════════════════════════════════════════════════════════════════

from secprobe.agents.profiler import (
    BehavioralProfiler,
    ResponseFingerprinter,
    TimingProfile,
    TimingProfiler,
    WAFBehaviorModel,
)


class TestTimingProfile:
    def test_basic_stats(self):
        tp = TimingProfile(endpoint="/test")
        for t in [0.1, 0.15, 0.12, 0.11, 0.13]:
            tp.add_sample(t)
        assert tp.mean == pytest.approx(0.122, abs=0.01)
        assert tp.sample_count == 5

    def test_percentile(self):
        tp = TimingProfile()
        for i in range(100):
            tp.add_sample(float(i))
        p50 = tp.percentile(50)
        assert 45 <= p50 <= 55

    def test_anomaly_detection(self):
        tp = TimingProfile()
        # Need at least 5 samples for anomaly detection, with some variance
        for val in [0.10, 0.11, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10,
                     0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10]:
            tp.add_sample(val)
        assert not tp.is_anomalous(0.12)
        assert tp.is_anomalous(10.0)  # Way outside normal

    def test_anomaly_requires_min_samples(self):
        tp = TimingProfile()
        tp.add_sample(0.1)
        tp.add_sample(0.1)
        # Less than 5 samples — always returns False
        assert not tp.is_anomalous(100.0)

    def test_blind_injection_threshold(self):
        tp = TimingProfile()
        for val in [0.10, 0.11, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10,
                     0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10]:
            tp.add_sample(val)
        threshold = tp.get_blind_injection_threshold()
        assert threshold > 0.1


class TestTimingProfiler:
    def test_record_and_check(self):
        profiler = TimingProfiler()
        for val in [0.10, 0.11, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10,
                     0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10]:
            profiler.record("/api/users", val)
        assert profiler.endpoint_count == 1
        assert not profiler.is_anomalous("/api/users", 0.12)
        assert profiler.is_anomalous("/api/users", 50.0)

    def test_global_mean(self):
        profiler = TimingProfiler()
        profiler.record("/a", 0.1)
        profiler.record("/b", 0.2)
        assert profiler.global_mean == pytest.approx(0.15)


class TestWAFBehaviorModel:
    def test_record_and_predict(self):
        waf = WAFBehaviorModel()
        # Simulate: single quotes always blocked
        for _ in range(10):
            waf.record_request("' OR 1=1", 403, True)
        for _ in range(10):
            waf.record_request("normal input", 200, False)

        block_prob = waf.predict_block("test ' value")
        assert block_prob > 0.5

    def test_safe_and_blocked_patterns(self):
        waf = WAFBehaviorModel()
        for _ in range(10):
            waf.record_request("<script>alert(1)</script>", 403, True)
        for _ in range(10):
            waf.record_request("hello world", 200, False)
        blocked = waf.get_blocked_patterns()
        assert "script_tag" in blocked

    def test_waf_detection(self):
        waf = WAFBehaviorModel()
        for _ in range(5):
            waf.record_request("test", 200, False)
        assert not waf.is_waf_detected

        for _ in range(10):
            waf.record_request("attack", 403, True)
        assert waf.is_waf_detected

    def test_suggest_bypass(self):
        waf = WAFBehaviorModel()
        suggestions = waf.suggest_bypass("single_quote")
        assert isinstance(suggestions, list)
        assert len(suggestions) > 0


class TestResponseFingerprinter:
    def test_record_and_detect(self):
        fp = ResponseFingerprinter()
        for _ in range(10):
            fp.record_response("/api", 200, 1500)
        is_anom, reason = fp.is_anomalous_response("/api", 200, 1500)
        assert not is_anom

        is_anom, reason = fp.is_anomalous_response("/api", 500, 1500)
        assert is_anom

    def test_tech_detection(self):
        fp = ResponseFingerprinter()
        fp.record_response(
            "/test", 200, 500,
            headers={"X-Powered-By": "PHP/8.2"},
            body_snippet="PHPSESSID=abc123",
        )
        assert "php" in fp.detected_tech


class TestBehavioralProfiler:
    def test_full_pipeline(self):
        bp = BehavioralProfiler()
        for val in [0.10, 0.11, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10,
                     0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10]:
            bp.record(
                endpoint="/api", payload="test", status_code=200,
                content_length=1000, response_time=val,
            )
        analysis = bp.analyze("/api", payload="test",
                              status_code=200, content_length=1000,
                              response_time=0.1)
        assert "timing_anomaly" in analysis
        assert not analysis["timing_anomaly"]

    def test_anomaly_detection(self):
        bp = BehavioralProfiler()
        for val in [0.10, 0.11, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10,
                     0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10]:
            bp.record(endpoint="/api", response_time=val)
        analysis = bp.analyze("/api", response_time=50.0)
        assert analysis["timing_anomaly"]

    def test_evasion_suggestion(self):
        bp = BehavioralProfiler()
        # Train WAF model
        for _ in range(10):
            bp.record(endpoint="/api", payload="' OR 1=1", was_blocked=True)
        suggestions = bp.suggest_evasion("' OR 1=1")
        assert isinstance(suggestions, list)


# ═══════════════════════════════════════════════════════════════════
# TRANSFER TESTS
# ═══════════════════════════════════════════════════════════════════

from secprobe.agents.transfer import (
    KnowledgeTransferEngine,
    PayloadDatabase,
    SimilarityEngine,
    StrategyLibrary,
    TargetFingerprint,
)


class TestTargetFingerprint:
    def test_feature_vector(self):
        fp = TargetFingerprint(
            technologies=["php", "mysql"],
            waf_type="cloudflare",
            waf_detected=True,
        )
        features = fp.feature_vector()
        assert features["tech_php"] == 1.0
        assert features["tech_mysql"] == 1.0
        assert features["tech_python"] == 0.0
        assert features["waf_present"] == 1.0

    def test_to_dict(self):
        fp = TargetFingerprint(url="http://test.com", technologies=["php"])
        d = fp.to_dict()
        assert d["url"] == "http://test.com"


class TestSimilarityEngine:
    def test_identical_targets(self):
        se = SimilarityEngine()
        fp1 = TargetFingerprint(technologies=["php", "mysql"])
        fp2 = TargetFingerprint(technologies=["php", "mysql"])
        sim = se.compute_similarity(fp1, fp2)
        assert sim > 0.8

    def test_different_targets(self):
        se = SimilarityEngine()
        fp1 = TargetFingerprint(
            technologies=["php", "mysql"],
            waf_type="modsecurity",
            waf_detected=True,
        )
        fp2 = TargetFingerprint(
            technologies=["nodejs", "mongodb"],
            waf_type="cloudflare",
            waf_detected=True,
        )
        sim = se.compute_similarity(fp1, fp2)
        # They share waf_present=1, but differ on tech and waf_type
        assert sim < 0.9

    def test_find_most_similar(self):
        se = SimilarityEngine()
        target = TargetFingerprint(technologies=["php", "mysql"])
        candidates = [
            TargetFingerprint(technologies=["php", "mysql"]),
            TargetFingerprint(technologies=["nodejs"]),
            TargetFingerprint(technologies=["php"]),
        ]
        results = se.find_most_similar(target, candidates)
        assert len(results) >= 1
        assert results[0][1] >= results[-1][1]  # Sorted desc


class TestPayloadDatabase:
    def test_record_and_retrieve(self):
        db = PayloadDatabase()
        db.record("' OR 1=1--", "sql_injection", True, tech_context="php")
        db.record("' OR 1=1--", "sql_injection", True, tech_context="php")
        db.record("' OR 1=1--", "sql_injection", False, tech_context="php")
        results = db.get_best_payloads("sql_injection", tech_context="php")
        assert len(results) >= 1

    def test_stats(self):
        db = PayloadDatabase()
        db.record("p1", "xss", True)
        db.record("p2", "sqli", False)
        stats = db.get_stats()
        assert stats["total_payloads"] == 2


class TestStrategyLibrary:
    def test_default_strategies(self):
        lib = StrategyLibrary()
        assert lib.strategies  # Has defaults

    def test_find_strategy(self):
        lib = StrategyLibrary()
        results = lib.find_strategy(tech_stack=["php", "mysql"])
        assert len(results) >= 1

    def test_find_by_waf(self):
        lib = StrategyLibrary()
        results = lib.find_strategy(waf_type="cloudflare")
        assert len(results) >= 1


class TestKnowledgeTransferEngine:
    def test_transfer(self):
        engine = KnowledgeTransferEngine()
        # Register prior target
        old = TargetFingerprint(
            target_id="old1",
            technologies=["php", "mysql"],
        )
        engine.register_target(old)

        # Transfer to similar target
        new = TargetFingerprint(
            target_id="new1",
            technologies=["php", "mysql"],
        )
        result = engine.transfer_knowledge(new)
        assert result.similarity > 0

    def test_payload_recommendations(self):
        engine = KnowledgeTransferEngine()
        engine.payload_db.record("' OR 1=1--", "sql_injection", True,
                                 tech_context="php")
        engine.payload_db.record("' OR 1=1--", "sql_injection", True,
                                 tech_context="php")
        target = TargetFingerprint(technologies=["php"], language="php")
        payloads = engine.get_recommended_payloads("sql_injection", target)
        assert len(payloads) >= 1


# ═══════════════════════════════════════════════════════════════════
# SELF-IMPROVEMENT TESTS
# ═══════════════════════════════════════════════════════════════════

from secprobe.agents.self_improve import (
    ABTestingFramework,
    HyperparameterTuner,
    MetaLearner,
    PerformanceTracker,
    SelfImprovementEngine,
    SkillAssessor,
)


class TestPerformanceTracker:
    def test_record_and_snapshot(self):
        pt = PerformanceTracker()
        pt.record("agent_1", "vulns_found", 5)
        pt.record("agent_1", "requests_sent", 100)
        snap = pt.snapshot("agent_1")
        assert snap.metrics["vulns_found"] == 5
        assert snap.effectiveness > 0

    def test_trend(self):
        pt = PerformanceTracker()
        for i in range(5):
            pt.record("agent_1", "vulns_found", float(i))
            pt.snapshot("agent_1")
        trend = pt.get_trend("agent_1", "vulns_found")
        assert len(trend) == 5

    def test_regression_detection(self):
        pt = PerformanceTracker()
        # Good performance
        for _ in range(5):
            pt.record("agent_1", "vulns_found", 10)
            pt.record("agent_1", "requests_sent", 100)
            pt.snapshot("agent_1")
        # Bad performance
        for _ in range(5):
            pt.record("agent_1", "vulns_found", 0)
            pt.record("agent_1", "false_positives", 0)
            pt.record("agent_1", "requests_sent", 100)
            pt.snapshot("agent_1")
        assert pt.detect_regression("agent_1")


class TestABTestingFramework:
    def test_create_and_record(self):
        ab = ABTestingFramework()
        test = ab.create_test(
            "test_1", "Compare evasion strategies",
            [{"strategy": "A"}, {"strategy": "B"}],
            min_samples=5,
        )
        assert len(test.variants) == 2

        # Record results
        for _ in range(10):
            ab.record_result("test_1", 0, True, 1.0)
        for _ in range(10):
            ab.record_result("test_1", 1, False, 0.0)

    def test_significance(self):
        ab = ABTestingFramework()
        test = ab.create_test(
            "sig_test", "Significance test",
            [{"a": 1}, {"b": 2}],
            min_samples=30,
        )
        # Variant 0 always wins
        for _ in range(40):
            ab.record_result("sig_test", 0, True)
        for _ in range(40):
            ab.record_result("sig_test", 1, False)
        assert test.is_significant()


class TestHyperparameterTuner:
    def test_suggest_config(self):
        tuner = HyperparameterTuner()
        config = tuner.suggest_config(["learning_rate", "exploration_rate"])
        assert "learning_rate" in config
        assert "exploration_rate" in config

    def test_report_performance(self):
        tuner = HyperparameterTuner()
        for i in range(15):
            config = tuner.suggest_config()
            tuner.report_performance(config, float(i) / 15)
        assert tuner.best_performance > 0

    def test_perturb_best(self):
        tuner = HyperparameterTuner()
        # Build up enough configs to trigger perturbation
        for i in range(12):
            config = tuner.suggest_config(["learning_rate"])
            tuner.report_performance(config, float(i))
        # Next suggestion should work fine
        config = tuner.suggest_config(["learning_rate"])
        assert "learning_rate" in config


class TestSkillAssessor:
    def test_assess_and_profile(self):
        sa = SkillAssessor()
        sa.assess("agent_1", "sql_injection", 0.9)
        sa.assess("agent_1", "xss", 0.5)
        sa.assess("agent_1", "ssti", 0.3)

        profile = sa.get_profile("agent_1")
        assert profile is not None
        assert profile.overall_skill > 0

        weak = profile.get_weakest_skills(1)
        assert weak[0][0] == "ssti"

    def test_recommend_training(self):
        sa = SkillAssessor()
        sa.assess("agent_1", "sql_injection", 0.9)
        sa.assess("agent_1", "xss", 0.2)
        recs = sa.recommend_training("agent_1")
        assert "xss" in recs

    def test_find_best_agent(self):
        sa = SkillAssessor()
        sa.assess("agent_1", "sql_injection", 0.9)
        sa.assess("agent_2", "sql_injection", 0.5)
        best = sa.find_best_agent_for("sql_injection")
        assert best == "agent_1"


class TestMetaLearner:
    def test_episode_lifecycle(self):
        ml = MetaLearner()
        eid = ml.start_episode("aggressive", 0.1, 0.5, "php_target")
        ml.end_episode(eid, 0.8, steps=10)
        assert len(ml.episodes) == 1
        assert ml.episodes[0].improvement == pytest.approx(0.3)

    def test_recommend_strategy(self):
        ml = MetaLearner()
        # Train with aggressive strategy on php
        for _ in range(5):
            eid = ml.start_episode("aggressive", 0.1, 0.3, "php")
            ml.end_episode(eid, 0.8)
        # Train with stealth on php (worse)
        for _ in range(5):
            eid = ml.start_episode("stealth", 0.05, 0.3, "php")
            ml.end_episode(eid, 0.4)

        strategy, _ = ml.recommend_strategy("php")
        assert strategy == "aggressive"

    def test_recommend_learning_rate(self):
        ml = MetaLearner()
        for _ in range(5):
            eid = ml.start_episode("test", 0.2, 0.3)
            ml.end_episode(eid, 0.7)
        lr = ml.recommend_learning_rate()
        assert 0 < lr < 1


class TestSelfImprovementEngine:
    def test_full_pipeline(self):
        engine = SelfImprovementEngine()
        engine.record_scan_result(
            "agent_1", vulns_found=5, false_positives=1,
            requests=100, scan_time=30.0,
        )
        engine.performance.snapshot("agent_1")
        engine.assess_agent("agent_1", "sql_injection", 0.8)

        plan = engine.get_improvement_plan("agent_1")
        assert "training_focus" in plan
        assert "suggested_params" in plan

    def test_improvement_cycle(self):
        engine = SelfImprovementEngine()
        engine.record_scan_result("agent_1", vulns_found=3, requests=50)
        engine.performance.snapshot("agent_1")
        result = engine.run_improvement_cycle()
        assert result["cycle"] == 1


# ═══════════════════════════════════════════════════════════════════
# TRAINER TESTS
# ═══════════════════════════════════════════════════════════════════

from secprobe.agents.trainer import (
    AgentTrainer,
    BenchmarkSuite,
    CurriculumManager,
    Difficulty,
    GraduationSystem,
    SkillLevel,
)


class TestCurriculumManager:
    def test_default_curriculum(self):
        cm = CurriculumManager()
        assert len(cm.stages) >= 6

    def test_get_next_stage(self):
        cm = CurriculumManager()
        stage = cm.get_next_stage("agent_1")
        assert stage is not None
        assert stage.stage_id == 1  # Start from stage 1

    def test_progression(self):
        cm = CurriculumManager()
        # Pass stage 1
        cm.record_stage_result("agent_1", 1, 0.9)
        next_stage = cm.get_next_stage("agent_1")
        assert next_stage.stage_id == 2

    def test_get_agent_level(self):
        cm = CurriculumManager()
        cm.record_stage_result("agent_1", 1, 0.9)
        cm.record_stage_result("agent_1", 2, 0.8)
        level = cm.get_agent_level("agent_1")
        assert level in list(Difficulty)


class TestBenchmarkSuite:
    def test_default_benchmarks(self):
        bs = BenchmarkSuite()
        assert len(bs.benchmarks) >= 5

    def test_record_result(self):
        bs = BenchmarkSuite()
        result = bs.record_result(
            "sqli_standard", "agent_1",
            vulns_found=3, false_positives=0, time_taken=30,
        )
        assert result.score > 0
        assert result.f1_score > 0

    def test_leaderboard(self):
        bs = BenchmarkSuite()
        bs.record_result("sqli_standard", "agent_1", vulns_found=4)
        bs.record_result("sqli_standard", "agent_2", vulns_found=2)
        board = bs.get_leaderboard("sqli_standard")
        assert board[0][0] == "agent_1"


class TestGraduationSystem:
    def test_evaluate(self):
        gs = GraduationSystem()
        level = gs.evaluate("agent_1", 1, 0.3, 5)
        assert level == SkillLevel.NOVICE

    def test_promotion(self):
        gs = GraduationSystem()
        level = gs.evaluate("agent_1", 3, 0.7, 60)
        assert level == SkillLevel.JOURNEYMAN

    def test_grandmaster(self):
        gs = GraduationSystem()
        level = gs.evaluate("agent_1", 6, 0.96, 600)
        assert level == SkillLevel.GRANDMASTER


class TestAgentTrainer:
    def test_start_training(self):
        trainer = AgentTrainer()
        session = trainer.start_training("agent_1")
        assert session.stage is not None
        assert session.status == "active"

    def test_complete_training(self):
        trainer = AgentTrainer()
        session = trainer.start_training("agent_1")
        trainer.complete_training(session.session_id, 0.9, vulns_found=3)
        assert session.status == "completed"

    def test_benchmark(self):
        trainer = AgentTrainer()
        result = trainer.run_benchmark(
            "agent_1", "sqli_standard", vulns_found=4,
        )
        assert result.score > 0

    def test_graduation(self):
        trainer = AgentTrainer()
        # Complete stage 1
        trainer.curriculum.record_stage_result("agent_1", 1, 0.9)
        # Run benchmark
        trainer.run_benchmark("agent_1", "sqli_standard", vulns_found=2)
        level = trainer.check_graduation("agent_1", total_vulns=5)
        assert isinstance(level, SkillLevel)

    def test_training_report(self):
        trainer = AgentTrainer()
        session = trainer.start_training("agent_1")
        trainer.complete_training(session.session_id, 0.85)
        report = trainer.get_training_report("agent_1")
        assert report["agent_id"] == "agent_1"
        assert "curriculum_progress" in report
        assert "training_sessions" in report

    def test_full_training_pipeline(self):
        """End-to-end training pipeline test."""
        trainer = AgentTrainer()

        # Stage 1: Start training
        s1 = trainer.start_training("agent_1")
        assert s1.stage.stage_id == 1
        trainer.complete_training(s1.session_id, 0.9)

        # Stage 2: Should advance
        s2 = trainer.start_training("agent_1")
        assert s2.stage.stage_id == 2
        trainer.complete_training(s2.session_id, 0.85)

        # Run benchmarks
        trainer.run_benchmark("agent_1", "sqli_standard", 3)
        trainer.run_benchmark("agent_1", "xss_standard", 4)

        # Check graduation
        level = trainer.check_graduation("agent_1", total_vulns=25)
        assert level in list(SkillLevel)

        # Get report
        report = trainer.get_training_report("agent_1")
        assert report["curriculum_progress"]["stages_passed"] >= 2


# ═══════════════════════════════════════════════════════════════════
# INTEGRATION / IMPORTS TEST
# ═══════════════════════════════════════════════════════════════════

class TestImports:
    """Verify all new modules import cleanly from __init__."""

    def test_neural_memory_imports(self):
        from secprobe.agents import (
            NeuralMemory, EpisodicMemory, SemanticMemory,
            ProceduralMemory, WorkingMemory, FeatureExtractor,
        )

    def test_reinforcement_imports(self):
        from secprobe.agents import (
            RLSystem, QLearningEngine, MultiArmedBandit,
            PolicyGradient, ExperienceReplayBuffer, RewardShaper,
        )

    def test_evolution_imports(self):
        from secprobe.agents import (
            EvolutionEngine, PayloadGenome, MutationOperator,
            CrossoverOperator, FitnessFunction, PayloadSelector,
        )

    def test_profiler_imports(self):
        from secprobe.agents import (
            BehavioralProfiler, TimingProfiler, WAFBehaviorModel,
            ResponseFingerprinter,
        )

    def test_transfer_imports(self):
        from secprobe.agents import (
            KnowledgeTransferEngine, PayloadDatabase,
            SimilarityEngine, StrategyLibrary, TargetFingerprint,
        )

    def test_self_improve_imports(self):
        from secprobe.agents import (
            SelfImprovementEngine, PerformanceTracker,
            ABTestingFramework, HyperparameterTuner,
            SkillAssessor, MetaLearner,
        )

    def test_trainer_imports(self):
        from secprobe.agents import (
            AgentTrainer, CurriculumManager, BenchmarkSuite,
            GraduationSystem, Difficulty, SkillLevel,
        )
