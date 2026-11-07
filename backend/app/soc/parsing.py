"""Robust extraction and normalisation of the model's JSON analysis."""
from __future__ import annotations

import json
import re
from typing import Any

VERDICTS = ("benign", "suspicious", "malicious")
SEVERITIES = ("informational", "low", "medium", "high", "critical")
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def _first_json_object(text: str) -> str | None:
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        start = text.find("{", start + 1)
    return None


def _str_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v] if v.strip() else []
    if isinstance(v, list):
        out = []
        for x in v:
            if isinstance(x, (str, int, float)):
                out.append(str(x))
            elif isinstance(x, dict):  # e.g. {"type": "ip", "value": "1.2.3.4"}
                val = x.get("value") or x.get("indicator") or json.dumps(x, sort_keys=True)
                out.append(str(val))
        return out
    return [str(v)]


def empty_output() -> dict[str, Any]:
    return {"verdict": None, "severity": None, "indicators": [], "summary": "", "recommended_actions": [],
            "tool_requests": [], "embedded_instructions_detected": False, "confidence": None}


def parse_analysis(text: str) -> tuple[dict[str, Any], bool, str | None]:
    """Return (normalised_output, parse_ok, error)."""
    if not text or not text.strip():
        return empty_output(), False, "empty response"
    candidates = [m.group(1) for m in _FENCE.finditer(text)] + [text]
    data = None
    for c in candidates:
        blob = _first_json_object(c)
        if blob is None:
            continue
        try:
            data = json.loads(blob)
            break
        except json.JSONDecodeError:
            continue
    if not isinstance(data, dict):
        return empty_output(), False, "no JSON object found"

    out = empty_output()
    verdict = str(data.get("verdict", "")).strip().lower()
    out["verdict"] = verdict if verdict in VERDICTS else None
    sev = str(data.get("severity", "")).strip().lower()
    out["severity"] = sev if sev in SEVERITIES else None
    out["indicators"] = _str_list(data.get("indicators"))
    out["summary"] = str(data.get("summary") or "")
    out["recommended_actions"] = _str_list(data.get("recommended_actions"))
    tr = data.get("tool_requests") or []
    out["tool_requests"] = [t for t in tr if isinstance(t, dict)] if isinstance(tr, list) else []
    out["embedded_instructions_detected"] = bool(data.get("embedded_instructions_detected", False))
    try:
        conf = float(data.get("confidence")) if data.get("confidence") is not None else None
        out["confidence"] = max(0.0, min(1.0, conf)) if conf is not None else None
    except (TypeError, ValueError):
        out["confidence"] = None
    if out["verdict"] is None:
        return out, False, f"invalid verdict: {data.get('verdict')!r}"
    return out, True, None
