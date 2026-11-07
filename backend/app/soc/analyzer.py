"""End-to-end analysis pipeline for one log event under one model + defense."""
from __future__ import annotations

import copy
import hashlib
import json
import secrets
from typing import Any

from app.config import Settings
from app.llm.base import ProviderError
from app.llm.registry import ProviderRegistry
from app.soc.parsers import detect_log_type, parse_fields
from app.soc.parsing import parse_analysis
from app.soc.prompts import DEFENSES, PROMPT_FINGERPRINT, build_system_prompt, build_user_prompt
from app.soc.tools import enforce_tool_requests
from app.soc import tripwire as tw


def _nonce(seed_key: str | None) -> str:
    if seed_key:
        return hashlib.sha256(f"nonce|{seed_key}".encode()).hexdigest()[:12]
    return secrets.token_hex(6)


def disclosure_detected(text: str, canary: str | None) -> bool:
    low = (text or "").lower()
    return PROMPT_FINGERPRINT.lower() in low or bool(canary and canary.lower() in low)


async def analyze(registry: ProviderRegistry, settings: Settings, *, model_id: str, defense_id: str,
                  raw: str, log_type: str | None = None, fields: dict[str, Any] | None = None,
                  seed_key: str | None = None) -> dict[str, Any]:
    if defense_id not in DEFENSES:
        raise ValueError(f"unknown defense {defense_id!r}")
    defense = DEFENSES[defense_id]
    log_type = log_type if log_type and log_type != "auto" else detect_log_type(raw)
    fields = fields if fields else parse_fields(log_type, raw)
    provider, model = registry.get(model_id)

    canary = tw.make_canary(settings.canary_salt, seed_key or secrets.token_hex(8)) if defense.canary_tripwire else None
    system = build_system_prompt(defense, canary)
    user = build_user_prompt(defense, log_type, raw, fields, _nonce(seed_key))

    result: dict[str, Any] = {
        "model": model_id, "provider": provider.name, "is_mock": provider.is_mock, "defense": defense_id,
        "log_type": log_type, "prompt": {"system": system, "user": user}, "canary": canary,
        "response_text": "", "latency_ms": None, "error": None, "parse_ok": False, "parse_error": None,
        "raw_output": None, "final_output": None, "tool_decisions": [],
        "tripwire": {"enabled": defense.canary_tripwire, "fired": False, "reasons": [], "details": {}},
        "disclosure_raw": False, "disclosure_final": False,
    }
    try:
        resp = await provider.complete(model, system, user)
    except ProviderError as exc:
        result["error"] = str(exc)
        return result

    result["response_text"] = resp.text
    result["latency_ms"] = round(resp.latency_ms, 2)
    output, ok, perr = parse_analysis(resp.text)
    result["parse_ok"], result["parse_error"] = ok, perr
    result["raw_output"] = output

    decisions = enforce_tool_requests(output.get("tool_requests"))
    result["tool_decisions"] = [d.to_dict() for d in decisions]

    final = copy.deepcopy(output)
    # Application-side enforcement: only permitted (simulated) tool requests survive.
    final["tool_requests"] = [{"tool": d.tool, "arguments": d.arguments} for d in decisions
                              if d.decision == "allowed_simulated"]
    if defense.canary_tripwire:
        trip = tw.check(resp.text, decisions, canary)
        result["tripwire"].update(fired=trip.fired, reasons=trip.reasons, details=trip.details)
        if trip.fired:
            final = tw.quarantine(final, trip)
            final["indicators"] = [i for i in final["indicators"] if canary and canary.lower() not in i.lower()]
    result["final_output"] = final
    result["disclosure_raw"] = disclosure_detected(resp.text, canary)
    result["disclosure_final"] = disclosure_detected(json.dumps(final), canary)
    return result
