# ODIN HEL Policy Engine

Lightweight, embeddable **policy engine** for governing AI egress (URLs/hosts/methods) with:
- **Profiles**: `strict`, `medium`, `open`
- **Allowlist**: per-tenant overrides
- **Optional Rego (OPA)** evaluation when `rego_path` provided and the `opa` binary is available

Install:
```bash
pip install odin-hel
```

## Quick Start
```python
from odin_hel import PolicyEngine, Decision

# Create a PolicyEngine with the default 'medium' profile
engine = PolicyEngine(profile="medium")

# Prepare a context for evaluation (simulate an API call)
ctx = {
    "tenant_id": "acme",
    "forward_url": "https://api.openai.com/v1/chat/completions",
    "method": "POST",
    "headers": {"authorization": "Bearer ..."},
    "payload_cid": "sha256:...",
    "attrs": {"user": "alice"}
}

# Evaluate the context
decision = engine.evaluate(ctx)
print(decision)
assert decision.allow

# Use a strict profile (deny by default)
engine_strict = PolicyEngine(profile="strict")
decision_strict = engine_strict.evaluate(ctx)
print(decision_strict)

# Use a custom allowlist
engine_custom = PolicyEngine(profile="strict", allowlist=["api.openai.com"])
decision_custom = engine_custom.evaluate(ctx)
print(decision_custom)
```

---

## FAQ: Common Errors

**Q: I get `ModuleNotFoundError: No module named 'odin_hel'` when running tests.**
A: Ensure your `PYTHONPATH` includes the `src/` directory.

**Q: Why `reason='no_host'`?**
A: Provide either a `host` or valid `forward_url`.

**Q: Add a custom allowlist?**
A: `PolicyEngine(profile="strict", allowlist=["api.example.com"])`.

---

## Rego (OPA) optional
If you pass `rego_path="policies/egress.rego"` and an `opa` binary is on PATH, the engine evaluates `data.odin.allow`. Otherwise it falls back to profile/allowlist.

## Profiles
- **strict**: deny by default
- **medium**: curated defaults + allowlist
- **open**: allow all (dev/local)

## Contributing
See `CONTRIBUTING.md`.
