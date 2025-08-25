import pytest
from odin_hel.engine import PolicyEngine, InvalidPolicyContext


def test_invalid_context_type():
    eng = PolicyEngine()
    with pytest.raises(InvalidPolicyContext):
        eng.evaluate(None)
    with pytest.raises(InvalidPolicyContext):
        eng.evaluate(123)
    with pytest.raises(InvalidPolicyContext):
        eng.evaluate([])


def test_extract_host_invalid_url():
    eng = PolicyEngine()
    # Should not raise, just return None for bad URL
    d = eng.evaluate({"forward_url": ":not-a-url"})
    assert not d.allow and d.reason == "no_host"
