# ODIN HEL Policy Engine

<p align="center">
  <strong>Deterministic, lightweight egress policy engine for AI / LLM applications</strong><br/>
  Profiles + Allowlists + (optional) Rego (OPA) = quick, auditable decisions.
</p>

<p align="center">
  <a href="https://pypi.org/project/odin-hel/"><img src="https://img.shields.io/pypi/v/odin-hel.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/odin-hel/"><img src="https://img.shields.io/pypi/pyversions/odin-hel.svg" alt="Python Versions"></a>
  <a href="https://github.com/Maverick0351a/odin-hel/actions"><img src="https://github.com/Maverick0351a/odin-hel/workflows/Publish/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/style-ruff-000000.svg" alt="Ruff"></a>
</p>

---

## Why HEL?
Modern AI systems call out to many model + data APIs. You need fast, explainable allow/deny decisions (and maybe a path to more sophisticated policy later) without dragging in a heavy gateway. HEL gives you:

| Need | HEL Answer |
|------|------------|
| Quick start default safety | `profile="medium"` curated host allowlist |
| Lock everything then open surgically | `profile="strict"` + custom allowlist |
| No guardrails for local/dev | `profile="open"` |
| Deterministic allow/deny | Pure Python fallback path |
| Progressive hardening | Drop in a Rego file later (OPA) |
| Traceability | Structured `Decision` object (host, reason, pathway) |
| Low operational overhead | No daemon required; optional `opa` binary only when you want Rego |

---
## Install
```
pip install odin-hel
```

## Quick Start
```python
from odin_hel import PolicyEngine, Decision

engine = PolicyEngine(profile="medium")
ctx = {
    "tenant_id": "acme",
    "forward_url": "https://api.openai.com/v1/chat/completions",
    "method": "POST",
    "headers": {"authorization": "Bearer ..."},
    "payload_cid": "sha256:...",
    "attrs": {"user": "alice"},
}

decision = engine.evaluate(ctx)
print(decision)
assert decision.allow
```

### Switching Profiles / Allowlist Overrides
```python
# Strict (deny unless explicitly allowed)
strict_engine = PolicyEngine(profile="strict")
print(strict_engine.evaluate(ctx))  # likely deny

# Strict + custom allowlist host
strict_open_one = PolicyEngine(profile="strict", allowlist=["api.openai.com"])
print(strict_open_one.evaluate(ctx))  # allow

# Open (everything allowed) – use only in trusted local dev
open_engine = PolicyEngine(profile="open")
print(open_engine.evaluate(ctx))  # allow
```

---
## Architecture At A Glance

```mermaid
flowchart LR
    A[Context dict] --> B[Extract host]
    B --> C{Profile}
    C -->|open| D[Allow]
    C -->|medium| E[Check curated allowlist]
    C -->|strict| F[Check custom allowlist]
    E --> G{Allowed?}
    F --> G
    G -->|no| H[Deny Decision (reason)]
    G -->|yes| I[Allowed so far]
    I --> J{Rego enabled?}
    J -->|no| K[Final Allow]
    J -->|yes| L[OPA eval data.odin.allow]
    L -->|true| K
    L -->|false| H
```

---
## Security / Decision Model
1. Host Extraction: canonicalizes either `host` or derives from `forward_url`.
2. Profile Gate:
   - `open`: short‑circuit allow.
   - `medium`: allow if host ∈ curated list or user allowlist.
   - `strict`: allow only if host ∈ user allowlist.
3. Optional Rego Policy: if `rego_path` + `opa` binary present, evaluate `data.odin.allow`; missing/failed OPA falls back to previous decision (fail‑open only if prior allow was true).
4. Decision Object: always returned with `allow`, `host`, `reason`, and whether Rego path was taken.
5. Determinism: No network calls (except optional local OPA subprocess).

---
## Optional Rego (OPA) Layer
Add a Rego file later without changing call sites:
```python
e = PolicyEngine(profile="medium", rego_path="policies/egress.rego")
print(e.evaluate(ctx))
```
OPA is only invoked if the `opa` binary is available on `PATH`.

Expected rule inside the Rego file:
```rego
package odin
allow { true }  # replace with real logic
```

---
## Profiles Summary
| Profile | Behavior |
|---------|----------|
| strict  | Deny unless host in custom allowlist |
| medium  | Allow curated AI API hosts + custom allowlist |
| open    | Allow all (development only) |

---
## FAQ
**ModuleNotFoundError: 'odin_hel' when running tests?** Ensure `PYTHONPATH=src` (or install in editable mode).

**Why `reason='no_host'`?** Provide either a `host` key or a valid `forward_url` containing one.

**How to add a custom allowlist?** Pass `allowlist=["api.example.com"]` when constructing `PolicyEngine`.

**What if OPA isn't installed?** The engine silently skips Rego and returns profile/allowlist decision.

---
## Contributing
See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the unreleased notes in [`CHANGELOG.md`](CHANGELOG.md).

---
## License
Apache 2.0. See [`LICENSE`](LICENSE).
