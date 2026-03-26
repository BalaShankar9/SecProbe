import pytest
import tempfile
from pathlib import Path
from secprobe.core.payload_manager import PayloadManager, COMMUNITY_SOURCES


class TestPayloadManager:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # Create a fake builtin payload
        payloads_dir = self.tmpdir / "payloads"
        payloads_dir.mkdir()
        (payloads_dir / "sqli.txt").write_text("' OR 1=1--\n\" OR 1=1--\n1' ORDER BY 1--\n")
        (payloads_dir / "xss.txt").write_text("<img src=x>\n<svg onload=alert(1)>\n")

        self.manager = PayloadManager(
            builtin_dir=payloads_dir,
            cache_dir=self.tmpdir / "cache",
            enable_community=False,  # Don't download in tests
        )

    def test_load_builtin(self):
        payloads = self.manager.get_payloads("sqli")
        assert len(payloads) == 3
        assert "' OR 1=1--" in payloads

    def test_load_xss(self):
        payloads = self.manager.get_payloads("xss")
        assert len(payloads) == 2

    def test_max_count(self):
        payloads = self.manager.get_payloads("sqli", max_count=2)
        assert len(payloads) == 2

    def test_nonexistent_type(self):
        payloads = self.manager.get_payloads("nonexistent")
        assert payloads == []

    def test_community_sources_defined(self):
        assert "sqli" in COMMUNITY_SOURCES
        assert "xss" in COMMUNITY_SOURCES
        assert len(COMMUNITY_SOURCES) >= 10

    def test_available_types(self):
        types = self.manager.get_available_types()
        assert "sqli" in types
        assert "xss" in types

    def test_deduplication(self):
        # Add duplicate to cache
        cache_dir = self.tmpdir / "cache"
        cache_dir.mkdir(exist_ok=True)
        (cache_dir / "test_sqli.txt").write_text("' OR 1=1--\nnew payload\n")

        manager = PayloadManager(
            builtin_dir=self.tmpdir / "payloads",
            cache_dir=cache_dir,
            enable_community=False,
        )
        payloads = manager.get_payloads("sqli")
        # Should not have duplicate "' OR 1=1--"
        assert payloads.count("' OR 1=1--") == 1


class TestSecretScanner:
    def setup_method(self):
        from secprobe.core.secret_scanner import SecretScanner
        self.scanner = SecretScanner()

    def test_detect_aws_key(self):
        text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        secrets = self.scanner.scan_text(text, "test.js")
        assert len(secrets) >= 1
        assert any(s.secret_type == "AWS Access Key ID" for s in secrets)

    def test_detect_github_token(self):
        text = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        secrets = self.scanner.scan_text(text, "config.js")
        assert len(secrets) >= 1
        assert any("GitHub" in s.secret_type for s in secrets)

    def test_detect_jwt(self):
        text = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        secrets = self.scanner.scan_text(text)
        assert len(secrets) >= 1

    def test_detect_private_key(self):
        text = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----'
        secrets = self.scanner.scan_text(text)
        assert any("Private Key" in s.secret_type for s in secrets)

    def test_detect_postgres_uri(self):
        text = 'DATABASE_URL=postgres://user:pass123@db.example.com/mydb'
        secrets = self.scanner.scan_text(text)
        assert any("PostgreSQL" in s.secret_type for s in secrets)

    def test_no_false_positives_on_normal_text(self):
        text = 'Hello world, this is a normal paragraph with no secrets.'
        secrets = self.scanner.scan_text(text)
        assert len(secrets) == 0

    def test_redacted_value(self):
        from secprobe.core.secret_scanner import DetectedSecret
        s = DetectedSecret(
            secret_type="Test",
            pattern_name="test",
            matched_value="sk_test_EXAMPLE_NOT_REAL_KEY_12345",
            location="test",
        )
        assert s.redacted_value.startswith("sk_t")
        assert s.redacted_value.endswith("2345")
        assert "..." in s.redacted_value

    def test_pattern_count(self):
        assert self.scanner.get_pattern_count() >= 25

    def test_scan_response(self):
        secrets = self.scanner.scan_response(
            "http://example.com/config",
            '{"api_key": "sk_test_EXAMPLE000NOT000REAL000KEY"}',
            {"X-Api-Key": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"},
        )
        assert len(secrets) >= 1
