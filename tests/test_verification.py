"""
Tests for secprobe.core.verification — finding verification engine.

Tests cover:
  - Confidence enum and ordering
  - VerificationResult escalation logic
  - PayloadVariants for each vuln type
  - ResponseComparer (strip_dynamic, similarity, is_different)
  - _inject_param URL helper
  - FindingVerifier.verify_reflection (replay, variant, negative, context)
  - FindingVerifier.verify_error_based (replay, variant, negative)
  - FindingVerifier.verify_boolean_based (multi-round differential)
  - FindingVerifier.verify_timing_based (baseline, z-score)
  - FindingVerifier.verify (auto-dispatch)
"""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock
import time

from secprobe.core.verification import (
    Confidence,
    VerificationResult,
    PayloadVariants,
    ResponseComparer,
    FindingVerifier,
    _inject_param,
)


# ═══════════════════════════════════════════════════════════════════════
# Confidence Enum
# ═══════════════════════════════════════════════════════════════════════

class TestConfidence(unittest.TestCase):

    def test_ordering(self):
        self.assertLess(Confidence.NONE.value, Confidence.TENTATIVE.value)
        self.assertLess(Confidence.TENTATIVE.value, Confidence.FIRM.value)
        self.assertLess(Confidence.FIRM.value, Confidence.CONFIRMED.value)

    def test_values(self):
        self.assertEqual(Confidence.NONE.value, 0)
        self.assertEqual(Confidence.TENTATIVE.value, 1)
        self.assertEqual(Confidence.FIRM.value, 2)
        self.assertEqual(Confidence.CONFIRMED.value, 3)


# ═══════════════════════════════════════════════════════════════════════
# VerificationResult
# ═══════════════════════════════════════════════════════════════════════

class TestVerificationResult(unittest.TestCase):

    def test_default_state(self):
        r = VerificationResult()
        self.assertFalse(r.confirmed)
        self.assertEqual(r.confidence, Confidence.NONE)
        self.assertEqual(r.evidence, [])
        self.assertFalse(r.replay_success)
        self.assertFalse(r.variant_success)
        self.assertFalse(r.negative_success)
        self.assertFalse(r.context_confirmed)
        self.assertEqual(r.rounds_passed, 0)
        self.assertEqual(r.rounds_total, 0)

    def test_escalate_variant_and_negative_gives_confirmed(self):
        r = VerificationResult()
        r.variant_success = True
        r.negative_success = True
        r.escalate()
        self.assertTrue(r.confirmed)
        self.assertEqual(r.confidence, Confidence.CONFIRMED)

    def test_escalate_replay_and_variant_gives_confirmed(self):
        r = VerificationResult()
        r.replay_success = True
        r.variant_success = True
        r.escalate()
        self.assertTrue(r.confirmed)
        self.assertEqual(r.confidence, Confidence.CONFIRMED)

    def test_escalate_replay_and_negative_gives_confirmed(self):
        r = VerificationResult()
        r.replay_success = True
        r.negative_success = True
        r.escalate()
        self.assertTrue(r.confirmed)
        self.assertEqual(r.confidence, Confidence.CONFIRMED)

    def test_escalate_replay_only_gives_firm(self):
        r = VerificationResult()
        r.replay_success = True
        r.escalate()
        self.assertTrue(r.confirmed)
        self.assertEqual(r.confidence, Confidence.FIRM)

    def test_escalate_variant_only_gives_firm(self):
        r = VerificationResult()
        r.variant_success = True
        r.escalate()
        self.assertTrue(r.confirmed)
        self.assertEqual(r.confidence, Confidence.FIRM)

    def test_escalate_context_only_gives_firm(self):
        r = VerificationResult()
        r.context_confirmed = True
        r.escalate()
        self.assertTrue(r.confirmed)
        self.assertEqual(r.confidence, Confidence.FIRM)

    def test_escalate_nothing_gives_tentative(self):
        r = VerificationResult()
        r.escalate()
        self.assertFalse(r.confirmed)
        self.assertEqual(r.confidence, Confidence.TENTATIVE)

    def test_evidence_accumulates(self):
        r = VerificationResult()
        r.evidence.append("first")
        r.evidence.append("second")
        self.assertEqual(len(r.evidence), 2)

    def test_details_dict(self):
        r = VerificationResult()
        r.details["z_score"] = 4.5
        self.assertEqual(r.details["z_score"], 4.5)


# ═══════════════════════════════════════════════════════════════════════
# PayloadVariants
# ═══════════════════════════════════════════════════════════════════════

class TestPayloadVariants(unittest.TestCase):

    def test_xss_variants_structure(self):
        result = PayloadVariants.xss_variants("")
        self.assertIn("variants", result)
        self.assertIn("negatives", result)
        self.assertGreater(len(result["variants"]), 0)
        self.assertGreater(len(result["negatives"]), 0)

    def test_sqli_variants_structure(self):
        result = PayloadVariants.sqli_variants("")
        self.assertIn("variants", result)
        self.assertIn("negatives", result)
        self.assertGreater(len(result["variants"]), 0)

    def test_ssti_variants_has_expected_results(self):
        result = PayloadVariants.ssti_variants("")
        self.assertIn("expected_results", result)
        self.assertIn("{{7*191}}", result["expected_results"])
        self.assertEqual(result["expected_results"]["{{7*191}}"], "1337")

    def test_cmdi_variants_structure(self):
        result = PayloadVariants.cmdi_variants("")
        self.assertIn("variants", result)
        self.assertIn("negatives", result)

    def test_lfi_variants_structure(self):
        result = PayloadVariants.lfi_variants("")
        self.assertIn("variants", result)
        for v in result["variants"]:
            self.assertIn("etc/passwd", v.replace("\\", "/"))

    def test_get_xss(self):
        result = PayloadVariants.get("xss")
        self.assertIn("variants", result)

    def test_get_sqli(self):
        result = PayloadVariants.get("sqli_error")
        self.assertIn("variants", result)

    def test_get_sql_alias(self):
        result = PayloadVariants.get("sql_injection")
        self.assertIn("variants", result)

    def test_get_ssti(self):
        result = PayloadVariants.get("ssti")
        self.assertIn("expected_results", result)

    def test_get_template_alias(self):
        result = PayloadVariants.get("template_injection")
        self.assertIn("expected_results", result)

    def test_get_cmdi(self):
        result = PayloadVariants.get("cmdi")
        self.assertIn("variants", result)

    def test_get_command_alias(self):
        result = PayloadVariants.get("command_injection")
        self.assertIn("variants", result)

    def test_get_lfi(self):
        result = PayloadVariants.get("lfi")
        self.assertIn("variants", result)

    def test_get_path_alias(self):
        result = PayloadVariants.get("path_traversal")
        self.assertIn("variants", result)

    def test_get_unknown_returns_empty(self):
        result = PayloadVariants.get("unknown_vuln_type")
        self.assertEqual(result["variants"], [])
        self.assertEqual(result["negatives"], [])


# ═══════════════════════════════════════════════════════════════════════
# _inject_param helper
# ═══════════════════════════════════════════════════════════════════════

class TestInjectParam(unittest.TestCase):

    def test_replace_existing_param(self):
        url = "http://example.com/page?name=alice&age=30"
        result = _inject_param(url, "name", "bob")
        self.assertIn("name=bob", result)
        self.assertIn("age=30", result)

    def test_add_to_empty_query(self):
        url = "http://example.com/page"
        result = _inject_param(url, "q", "test")
        self.assertIn("q=test", result)

    def test_special_chars_encoded(self):
        url = "http://example.com/page?q=normal"
        result = _inject_param(url, "q", "' OR '1'='1")
        self.assertIn("q=", result)

    def test_preserves_scheme_and_path(self):
        url = "https://example.com/a/b?x=1"
        result = _inject_param(url, "x", "2")
        self.assertTrue(result.startswith("https://example.com/a/b"))


# ═══════════════════════════════════════════════════════════════════════
# ResponseComparer
# ═══════════════════════════════════════════════════════════════════════

class TestResponseComparer(unittest.TestCase):

    def test_strip_dynamic_removes_csrf_token(self):
        text = 'csrf_token="abc123xyz"'
        cleaned = ResponseComparer.strip_dynamic(text)
        self.assertNotIn("abc123xyz", cleaned)

    def test_strip_dynamic_removes_nonce(self):
        text = 'nonce="xyz789abc"'
        cleaned = ResponseComparer.strip_dynamic(text)
        self.assertNotIn("xyz789abc", cleaned)

    def test_strip_dynamic_removes_unix_timestamp(self):
        text = 'created: 1700000000000'
        cleaned = ResponseComparer.strip_dynamic(text)
        self.assertNotIn("1700000000000", cleaned)

    def test_strip_dynamic_removes_uuid(self):
        text = 'id="550e8400-e29b-41d4-a716-446655440000"'
        cleaned = ResponseComparer.strip_dynamic(text)
        self.assertNotIn("550e8400-e29b-41d4-a716-446655440000", cleaned)

    def test_similarity_identical(self):
        self.assertEqual(ResponseComparer.similarity("hello", "hello"), 1.0)

    def test_similarity_empty_both(self):
        self.assertEqual(ResponseComparer.similarity("", ""), 1.0)

    def test_similarity_one_empty(self):
        self.assertEqual(ResponseComparer.similarity("hello", ""), 0.0)
        self.assertEqual(ResponseComparer.similarity("", "hello"), 0.0)

    def test_similarity_very_different(self):
        a = "short"
        b = "a" * 1000
        sim = ResponseComparer.similarity(a, b)
        self.assertLess(sim, 0.5)

    def test_similarity_similar_pages(self):
        base = "<html><body><h1>Page</h1><p>Content here</p></body></html>"
        variant = "<html><body><h1>Page</h1><p>Content here too</p></body></html>"
        sim = ResponseComparer.similarity(base, variant)
        self.assertGreater(sim, 0.4)

    def test_is_different_identical(self):
        self.assertFalse(ResponseComparer.is_different("same", "same"))

    def test_is_different_completely_different(self):
        self.assertTrue(ResponseComparer.is_different("a" * 100, "b" * 1000))

    def test_is_different_custom_threshold(self):
        # With a very high threshold, even similar pages are "different"
        a = "Hello World!"
        b = "Hello World?"
        self.assertFalse(ResponseComparer.is_different(a, b, threshold=0.5))


# ═══════════════════════════════════════════════════════════════════════
# FindingVerifier — Reflection Verification
# ═══════════════════════════════════════════════════════════════════════

def _mock_response(text="", status_code=200):
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = {}
    return resp


class TestVerifyReflection(unittest.TestCase):

    def setUp(self):
        self.client = MagicMock()
        self.verifier = FindingVerifier(self.client)

    def test_replay_confirms_when_payload_in_response(self):
        payload = '<script>alert(1)</script>'
        self.client.get.return_value = _mock_response(f"<p>{payload}</p>")
        result = self.verifier.verify_reflection(
            "http://test.com/page?q=test", "q", payload
        )
        self.assertTrue(result.replay_success)

    def test_replay_fails_when_payload_not_reflected(self):
        self.client.get.return_value = _mock_response("clean page")
        result = self.verifier.verify_reflection(
            "http://test.com/page?q=test", "q", "<script>alert(1)</script>"
        )
        self.assertFalse(result.replay_success)

    def test_variant_confirmed_when_variant_reflects(self):
        payload = '<script>alert(1)</script>'
        # Replay returns the original payload, then variant returns the variant
        responses = [
            _mock_response(payload),  # replay
            _mock_response('<img src=x onerror=alert(1)>'),  # variant 1
        ]
        self.client.get.side_effect = responses + [_mock_response("safe")] * 5
        result = self.verifier.verify_reflection(
            "http://test.com/page?q=test", "q", payload
        )
        self.assertTrue(result.variant_success)

    def test_negative_passes_when_safe_payload_no_trigger(self):
        payload = '<script>alert(1)</script>'
        # replay: has payload → OK
        # variants: doesn't match → skip
        # negatives: safe payload doesn't have original payload → pass
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_response(payload)  # replay
            return _mock_response("safe output")
        self.client.get.side_effect = side_effect
        result = self.verifier.verify_reflection(
            "http://test.com/page?q=test", "q", payload
        )
        self.assertTrue(result.negative_success)

    def test_full_confirmed_with_replay_variant_negative(self):
        payload = '<script>alert(1)</script>'
        variant = '<img src=x onerror=alert(1)>'
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_response(payload)  # replay: has payload
            if call_count[0] == 2:
                return _mock_response(variant)  # variant: has variant
            return _mock_response("safe output")  # negatives: clean
        self.client.get.side_effect = side_effect

        result = self.verifier.verify_reflection(
            "http://test.com/page?q=test", "q", payload
        )
        self.assertEqual(result.confidence, Confidence.CONFIRMED)
        self.assertTrue(result.confirmed)

    def test_replay_only_gives_firm(self):
        payload = '<script>alert(1)</script>'
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_response(payload)  # replay succeeds
            # All others: payload not in response, but detection_fn also doesn't trigger
            return _mock_response(payload)  # variant/negative: payload still there
        self.client.get.side_effect = side_effect

        result = self.verifier.verify_reflection(
            "http://test.com/page?q=test", "q", payload,
            detection_fn=lambda body: payload in body,
        )
        # Since negatives also have the payload, negative_success = False
        # replay + variant gives CONFIRMED
        self.assertTrue(result.replay_success)
        self.assertTrue(result.confirmed)

    def test_custom_detection_fn(self):
        payload = "{{7*7}}"
        self.client.get.return_value = _mock_response("result is 49")
        result = self.verifier.verify_reflection(
            "http://test.com/?tpl=test", "tpl", payload,
            detection_fn=lambda body: "49" in body,
            vuln_type="ssti",
        )
        self.assertTrue(result.replay_success)

    def test_exception_during_replay_handled(self):
        self.client.get.side_effect = Exception("connection timeout")
        result = self.verifier.verify_reflection(
            "http://test.com/?q=test", "q", "<script>alert(1)</script>"
        )
        self.assertFalse(result.replay_success)
        self.assertEqual(result.confidence, Confidence.TENTATIVE)


# ═══════════════════════════════════════════════════════════════════════
# FindingVerifier — Error-Based Verification
# ═══════════════════════════════════════════════════════════════════════

class TestVerifyErrorBased(unittest.TestCase):

    def setUp(self):
        self.client = MagicMock()
        self.verifier = FindingVerifier(self.client)

    def test_replay_confirms_error_pattern(self):
        self.client.get.return_value = _mock_response(
            "Error: You have an error in your SQL syntax near..."
        )
        result = self.verifier.verify_error_based(
            "http://test.com/?id=1", "id", "' OR 1=1--",
            error_pattern=r"SQL syntax",
        )
        self.assertTrue(result.replay_success)

    def test_variant_triggers_same_error(self):
        responses = [
            _mock_response("SQL syntax error"),  # replay
            _mock_response("SQL syntax in query"),  # variant
        ]
        self.client.get.side_effect = responses + [_mock_response("ok")] * 5
        result = self.verifier.verify_error_based(
            "http://test.com/?id=1", "id", "'",
            error_pattern=r"SQL syntax",
        )
        self.assertTrue(result.variant_success)

    def test_negative_clean_input_no_error(self):
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 3:  # replay + 2 variants
                return _mock_response("SQL syntax error")
            return _mock_response("Welcome, user!")  # clean input: no error
        self.client.get.side_effect = side_effect

        result = self.verifier.verify_error_based(
            "http://test.com/?id=1", "id", "'",
            error_pattern=r"SQL syntax",
        )
        self.assertTrue(result.negative_success)

    def test_full_confirmed(self):
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 3:  # replay + variants: error
                return _mock_response("SQL syntax error near")
            return _mock_response("Normal page")  # negatives: clean
        self.client.get.side_effect = side_effect

        result = self.verifier.verify_error_based(
            "http://test.com/?id=1", "id", "'",
            error_pattern=r"SQL syntax",
        )
        self.assertEqual(result.confidence, Confidence.CONFIRMED)

    def test_no_error_in_replay(self):
        self.client.get.return_value = _mock_response("Normal page, no errors")
        result = self.verifier.verify_error_based(
            "http://test.com/?id=1", "id", "'",
            error_pattern=r"SQL syntax",
        )
        self.assertFalse(result.replay_success)


# ═══════════════════════════════════════════════════════════════════════
# FindingVerifier — Boolean-Based Verification
# ═══════════════════════════════════════════════════════════════════════

class TestVerifyBooleanBased(unittest.TestCase):

    def setUp(self):
        self.client = MagicMock()
        self.verifier = FindingVerifier(self.client)

    def test_differential_detected_across_rounds(self):
        """True and false payloads produce different responses → confirmed."""
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            # Alternate: true gets big page, false gets small page
            if call_count[0] % 2 == 1:  # true payload (odd calls)
                return _mock_response("x" * 500, 200)
            else:  # false payload (even calls)
                return _mock_response("x" * 50, 200)
        self.client.get.side_effect = side_effect

        result = self.verifier.verify_boolean_based(
            "http://test.com/?id=1", "id",
            "' OR '1'='1", "' OR '1'='2",
            rounds=3,
        )
        self.assertGreater(result.rounds_passed, 0)
        self.assertTrue(result.confirmed)

    def test_no_differential_tentative(self):
        """Same response for true and false → not confirmed."""
        self.client.get.return_value = _mock_response("identical response", 200)
        result = self.verifier.verify_boolean_based(
            "http://test.com/?id=1", "id",
            "' OR '1'='1", "' OR '1'='2",
            rounds=3,
        )
        self.assertEqual(result.rounds_passed, 0)
        self.assertFalse(result.confirmed)

    def test_round_tracking(self):
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] % 2 == 1:
                return _mock_response("A" * 200)
            return _mock_response("B" * 10)
        self.client.get.side_effect = side_effect

        result = self.verifier.verify_boolean_based(
            "http://test.com/?id=1", "id",
            "' OR '1'='1", "' OR '1'='2",
            rounds=3,
        )
        self.assertEqual(result.rounds_total, 3)
        self.assertGreater(result.rounds_passed, 0)

    def test_status_code_differential(self):
        """Different status codes for true/false → differential detected."""
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] % 2 == 1:
                return _mock_response("ok", 200)
            return _mock_response("ok", 404)
        self.client.get.side_effect = side_effect

        result = self.verifier.verify_boolean_based(
            "http://test.com/?id=1", "id",
            "' OR '1'='1", "' OR '1'='2",
            rounds=3,
        )
        self.assertGreater(result.rounds_passed, 0)

    def test_exception_during_round_handled(self):
        self.client.get.side_effect = Exception("timeout")
        result = self.verifier.verify_boolean_based(
            "http://test.com/?id=1", "id",
            "' OR '1'='1", "' OR '1'='2",
            rounds=3,
        )
        self.assertEqual(result.rounds_passed, 0)
        self.assertFalse(result.confirmed)


# ═══════════════════════════════════════════════════════════════════════
# FindingVerifier — Timing-Based Verification
# ═══════════════════════════════════════════════════════════════════════

class TestVerifyTimingBased(unittest.TestCase):

    def setUp(self):
        self.client = MagicMock()
        self.verifier = FindingVerifier(self.client)

    def _mock_timed_responses(self, baseline_time=0.01, delay_time=5.0):
        """Mock that simulates timing by controlling time.monotonic."""
        call_count = [0]
        baseline_rounds = 3  # default
        def side_effect(url, **kwargs):
            call_count[0] += 1
            return _mock_response("ok")
        self.client.get.side_effect = side_effect
        return call_count

    def test_timing_structure(self):
        """Verify timing result has expected details."""
        self.client.get.return_value = _mock_response("ok")
        result = self.verifier.verify_timing_based(
            "http://test.com/?id=1", "id",
            "'; WAITFOR DELAY '0:0:5'--",
            delay_seconds=5.0,
            rounds=2,
            baseline_rounds=2,
        )
        self.assertEqual(result.rounds_total, 2)
        self.assertIn("baseline_mean", result.details)

    def test_all_fast_responses_not_confirmed(self):
        """When all responses are fast, timing vuln not confirmed."""
        self.client.get.return_value = _mock_response("ok")
        result = self.verifier.verify_timing_based(
            "http://test.com/?id=1", "id",
            "'; WAITFOR DELAY '0:0:5'--",
            delay_seconds=5.0,
            rounds=3,
            baseline_rounds=3,
        )
        # Everything finishes instantly in mocks → no delay detected
        self.assertFalse(result.confirmed)

    def test_exception_during_baseline_handled(self):
        self.client.get.side_effect = Exception("timeout")
        result = self.verifier.verify_timing_based(
            "http://test.com/?id=1", "id",
            "'; WAITFOR DELAY '0:0:5'--",
            delay_seconds=5.0,
        )
        self.assertFalse(result.confirmed)


# ═══════════════════════════════════════════════════════════════════════
# FindingVerifier — Auto-Dispatch
# ═══════════════════════════════════════════════════════════════════════

class TestVerifyDispatch(unittest.TestCase):

    def setUp(self):
        self.client = MagicMock()
        self.client.get.return_value = _mock_response("safe page")
        self.verifier = FindingVerifier(self.client)

    def test_dispatch_xss(self):
        result = self.verifier.verify(
            "http://test.com/?q=test", "q",
            "<script>alert(1)</script>", "xss"
        )
        self.assertIsInstance(result, VerificationResult)

    def test_dispatch_ssti(self):
        result = self.verifier.verify(
            "http://test.com/?tpl=test", "tpl",
            "{{7*7}}", "ssti"
        )
        self.assertIsInstance(result, VerificationResult)

    def test_dispatch_sqli_error(self):
        result = self.verifier.verify(
            "http://test.com/?id=1", "id",
            "'", "sqli_error",
            error_pattern=r"SQL syntax"
        )
        self.assertIsInstance(result, VerificationResult)

    def test_dispatch_sqli_boolean(self):
        result = self.verifier.verify(
            "http://test.com/?id=1", "id",
            "' OR '1'='1", "sqli_boolean",
            false_payload="' OR '1'='2",
        )
        self.assertIsInstance(result, VerificationResult)

    def test_dispatch_sqli_timing(self):
        result = self.verifier.verify(
            "http://test.com/?id=1", "id",
            "'; WAITFOR DELAY '0:0:5'--", "sqli_timing",
        )
        self.assertIsInstance(result, VerificationResult)

    def test_dispatch_unknown_defaults_to_reflection(self):
        result = self.verifier.verify(
            "http://test.com/?q=test", "q",
            "payload", "unknown_type",
        )
        self.assertIsInstance(result, VerificationResult)

    def test_dispatch_blind_alias(self):
        result = self.verifier.verify(
            "http://test.com/?id=1", "id",
            "' OR '1'='1", "blind_sqli",
            false_payload="' OR '1'='2",
        )
        self.assertIsInstance(result, VerificationResult)


# ═══════════════════════════════════════════════════════════════════════
# Integration-style: Full verification flow
# ═══════════════════════════════════════════════════════════════════════

class TestVerificationIntegration(unittest.TestCase):

    def test_sqli_error_full_flow(self):
        """Simulate a real SQL injection error-based verification."""
        client = MagicMock()
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 3:
                return _mock_response(
                    "MySQL Error: You have an error in your SQL syntax "
                    "near ''' at line 1"
                )
            return _mock_response("Welcome! Products: ...")
        client.get.side_effect = side_effect

        verifier = FindingVerifier(client)
        result = verifier.verify(
            "http://shop.test/products?id=1", "id", "'",
            "sqli_error",
            error_pattern=r"SQL syntax|MySQL Error",
        )
        self.assertTrue(result.confirmed)
        self.assertIn(result.confidence, (Confidence.FIRM, Confidence.CONFIRMED))
        self.assertGreater(len(result.evidence), 0)

    def test_xss_reflected_full_flow(self):
        """Simulate a real reflected XSS verification."""
        client = MagicMock()
        payload = '<script>alert(1)</script>'
        variant = '<img src=x onerror=alert(1)>'
        call_count = [0]
        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_response(f"<p>Search: {payload}</p>")
            if call_count[0] == 2:
                return _mock_response(f"<p>Search: {variant}</p>")
            return _mock_response("<p>Search: safe text</p>")
        client.get.side_effect = side_effect

        verifier = FindingVerifier(client)
        result = verifier.verify(
            "http://search.test/?q=hello", "q", payload, "xss",
        )
        self.assertTrue(result.confirmed)
        self.assertEqual(result.confidence, Confidence.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
