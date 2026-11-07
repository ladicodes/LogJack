"""Simulated canary tripwire (combined defense only).

Signals:
* canary_leak            - the secret canary from the system prompt appears in the response.
* forbidden_tool_request - the model requested a tool the application denies for this role.

When fired, the model output is quarantined: the verdict is replaced by "suspicious"
with mandatory human review, free-text fields are withheld, and no tool requests pass.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any

from app.soc.tools import ToolDecision

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def make_canary(salt: str, key: str) -> str:
    digest = hmac.new(salt.encode(), key.encode(), hashlib.sha256).hexdigest()[:16].upper()
    return f"LJC-{digest}"


@dataclass
class TripwireResult:
    fired: bool = False
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def check(response_text: str, decisions: list[ToolDecision], canary: str | None) -> TripwireResult:
    res = TripwireResult()
    if canary and canary.lower() in (response_text or "").lower():
        res.reasons.append("canary_leak")
        res.details["canary_leak"] = "Secret canary token appeared in model output."
    denied = [d.tool for d in decisions if d.decision == "denied"]
    if denied:
        res.reasons.append("forbidden_tool_request")
        res.details["forbidden_tools"] = denied
    res.fired = bool(res.reasons)
    return res


def quarantine(output: dict[str, Any], tw: TripwireResult) -> dict[str, Any]:
    q = copy.deepcopy(output)
    q["verdict"] = "suspicious"
    sev = output.get("severity") or "medium"
    q["severity"] = sev if SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index("medium") else "medium"
    q["summary"] = f"[withheld: integrity tripwire fired ({', '.join(tw.reasons)})] Output quarantined for human review."
    q["recommended_actions"] = ["Escalate to a human analyst: model output failed integrity checks."]
    q["tool_requests"] = []
    q["requires_human_review"] = True
    return q
