import pytest
from secprobe.intelligence.federated_sync import FederatedSync


class TestFederatedSync:
    def test_disabled_by_default(self):
        sync = FederatedSync(enabled=False)
        assert sync.contribute_findings([], []) == 0
        assert sync.query_intel("sqli") == []
        assert sync.query_waf_intel("cloudflare") == []

    def test_contribute_returns_zero_when_disabled(self):
        sync = FederatedSync(enabled=False)

        class FakeFinding:
            category = "sqli"
            evidence = "Payload: ' OR 1=1--"

        count = sync.contribute_findings([FakeFinding()], ["wordpress"])
        assert count == 0

    def test_query_returns_empty_when_disabled(self):
        sync = FederatedSync(enabled=False)
        assert sync.get_trending() == []
