from __future__ import annotations
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TypedDict
from urllib.parse import urlparse

from .profiles import DEFAULT_MEDIUM_ALLOWLIST


class InvalidPolicyContext(Exception):
    """Raised when the policy context is missing required fields or is not a dict."""
    pass


class PolicyContext(TypedDict, total=False):
    tenant_id: str
    forward_url: str
    host: str
    method: str
    headers: Dict[str, str]
    payload_cid: str
    attrs: Dict[str, Any]

@dataclass
class Decision:
    allow: bool
    engine: str  # "allowlist" or "rego"
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

def _extract_host(ctx: PolicyContext) -> Optional[str]:
    """Extract host from context (host field or hostname of forward_url)."""
    if not isinstance(ctx, dict):
        raise InvalidPolicyContext("Policy context must be a dict.")
    host = ctx.get("host")
    if host:
        return host
    fwd = ctx.get("forward_url")
    if fwd:
        try:
            return urlparse(fwd).hostname
        except Exception:
            return None
    return None

def _matches(host: str, allowed: str) -> bool:
    if host == allowed:
        return True
    if host.endswith("." + allowed):
        return True
    return False

class PolicyEngine:
    def __init__(self, profile: str = "medium", allowlist: Optional[List[str]] = None,
                 rego_path: Optional[str] = None, opa_bin: str = "opa"):
        self.profile = profile
        self.allowlist = allowlist or []
        self.rego_path = rego_path
        self.opa_bin = opa_bin

    def _profile_allowlist(self) -> List[str]:
        if self.profile == "open":
            return ["*"]
        if self.profile == "medium":
            return list(DEFAULT_MEDIUM_ALLOWLIST)
        if self.profile == "strict":
            return []
        return []

    def _allowlist_decision(self, host: Optional[str]) -> Decision:
        if self.profile == "open":
            return Decision(True, "allowlist", "profile_open", {"profile": "open"})
        if not host:
            return Decision(False, "allowlist", "no_host", {"profile": self.profile})

        effective = self._profile_allowlist() + self.allowlist
        for entry in effective:
            if entry == "*":
                return Decision(True, "allowlist", "wildcard", {"profile": self.profile})
            if _matches(host, entry):
                return Decision(
                    True,
                    "allowlist",
                    "host_allowed",
                    {"host": host, "match": entry, "profile": self.profile},
                )
        return Decision(
            False, "allowlist", "host_denied", {"host": host, "profile": self.profile}
        )

    def _rego_available(self) -> bool:
        return bool(shutil.which(self.opa_bin)) and (
            self.rego_path and os.path.exists(self.rego_path)
        )

    def _rego_decision(self, ctx: PolicyContext) -> Decision:
        try:
            proc = subprocess.run(
                [
                    self.opa_bin,
                    "eval",
                    "-f",
                    "json",
                    "-d",
                    self.rego_path,
                    "data.odin.allow",
                    "--input",
                    "-",
                ],
                input=json.dumps(ctx).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if proc.returncode != 0:
                return Decision(
                    False,
                    "rego",
                    "rego_error",
                    {"stderr": proc.stderr.decode("utf-8", "ignore")},
                )
            out = json.loads(proc.stdout.decode("utf-8"))
            value = None
            try:
                value = out["result"][0]["expressions"][0]["value"]
            except Exception:
                pass
            if value is True:
                return Decision(True, "rego", "rego_allow", {})
            return Decision(False, "rego", "rego_deny", {"value": value})
        except Exception as e:
            return Decision(False, "rego", "rego_exception", {"error": str(e)})

    def evaluate(self, ctx: PolicyContext) -> Decision:
        if not isinstance(ctx, dict):
            raise InvalidPolicyContext("Policy context must be a dict.")
        host = _extract_host(ctx)
        base = self._allowlist_decision(host)
        if self._rego_available():
            return self._rego_decision(ctx)
        return base
