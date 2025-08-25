from odin_hel import PolicyEngine


def test_open_profile_allows_all():
    eng = PolicyEngine(profile="open")
    d = eng.evaluate({"forward_url": "https://example.com/path"})
    assert d.allow and d.engine == "allowlist" and d.reason == "profile_open"


def test_strict_profile_blocks_unknown():
    eng = PolicyEngine(profile="strict")
    d = eng.evaluate({"forward_url": "https://unknown.example/path"})
    assert not d.allow and d.reason == "host_denied"


def test_medium_profile_has_defaults():
    eng = PolicyEngine(profile="medium")
    d = eng.evaluate({"forward_url": "https://api.openai.com/v1/chat/completions"})
    assert d.allow


def test_tenant_allowlist_override():
    eng = PolicyEngine(profile="strict", allowlist=["internal.example.com"])
    d1 = eng.evaluate({"forward_url": "https://internal.example.com/foo"})
    d2 = eng.evaluate({"forward_url": "https://api.openai.com/foo"})
    assert d1.allow and not d2.allow
