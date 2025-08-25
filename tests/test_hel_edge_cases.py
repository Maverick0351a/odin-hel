from odin_hel import PolicyEngine


# Edge case: Empty context
def test_empty_context_blocks():
    eng = PolicyEngine(profile="strict")
    d = eng.evaluate({})
    assert not d.allow and d.reason == "no_host"

# Edge case: Host not in allowlist
def test_host_not_in_allowlist():
    eng = PolicyEngine(profile="strict", allowlist=["foo.com"])
    d = eng.evaluate({"host": "bar.com"})
    assert not d.allow and d.reason == "host_denied"

# Edge case: Wildcard allowlist
def test_wildcard_allows_any():
    eng = PolicyEngine(profile="strict", allowlist=["*"])
    d = eng.evaluate({"host": "anything.com"})
    assert d.allow and d.reason == "wildcard"

# Edge case: Suffix match
def test_suffix_match():
    eng = PolicyEngine(profile="strict", allowlist=["example.com"])
    d = eng.evaluate({"host": "api.example.com"})
    assert d.allow and d.reason == "host_allowed"

# Edge case: Exact match
def test_exact_match():
    eng = PolicyEngine(profile="strict", allowlist=["foo.com"])
    d = eng.evaluate({"host": "foo.com"})
    assert d.allow and d.reason == "host_allowed"

# Edge case: Forward URL with no host
def test_forward_url_no_host():
    eng = PolicyEngine(profile="strict")
    d = eng.evaluate({"forward_url": "not-a-url"})
    assert not d.allow and d.reason == "no_host"

# Edge case: Allowlist is empty
def test_empty_allowlist_blocks():
    eng = PolicyEngine(profile="strict", allowlist=[])
    d = eng.evaluate({"host": "foo.com"})
    assert not d.allow and d.reason == "host_denied"
