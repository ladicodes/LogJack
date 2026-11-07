"""Findings are generated *only* from stored results. If there is no data, we say so."""
from __future__ import annotations

from typing import Any


def _fmt(r: dict[str, Any] | None) -> str:
    if not r or r.get("value") is None:
        return "n/a"
    ci = r.get("ci95")
    ci_s = f", 95% CI {ci[0]:.0%}-{ci[1]:.0%}" if ci else ""
    return f"{r['value']:.1%} ({r['k']}/{r['n']}{ci_s})"


def build_findings(experiment: dict[str, Any] | None, metrics: list[dict[str, Any]], scope: str) -> dict[str, Any]:
    label = "simulated (mock provider)" if scope == "mock" else "real LLM"
    if not experiment or not metrics:
        return {
            "scope": scope, "experiment": None, "statements": [],
            "notice": (f"No completed {label} experiments yet, so there are no findings to report. "
                       "Run an experiment from the Experiments page."),
        }
    caveat = ("These numbers come from the deterministic mock provider. They reflect the simulator's scripted "
              "susceptibility constants, not the behaviour of any real model, and must not be reported as research "
              "findings." if scope == "mock" else
              "Measured on synthetic logs with a fixed benchmark of simple, transparent injection strings at the stated "
              "temperature. Results may not generalise to other models, prompts, log sources or adaptive attackers.")
    statements: list[dict[str, Any]] = []
    by_model: dict[str, list[dict[str, Any]]] = {}
    for m in metrics:
        by_model.setdefault(m["model"], []).append(m)
    for model, rows in by_model.items():
        for r in rows:
            statements.append({
                "model": model, "defense": r["defense"], "kind": "summary",
                "text": (f"{model} / {r['defense']}: model-level attack success {_fmt(r['attack']['asr_model'])}; "
                         f"system-level (after app enforcement/tripwire) {_fmt(r['attack']['asr_system'])}; "
                         f"clean accuracy {_fmt(r['clean']['accuracy'])}, modified accuracy {_fmt(r['modified']['accuracy'])}."),
            })
        base = next((r for r in rows if r["defense"] == "baseline"), None)
        for r in rows:
            if base is None or r is base:
                continue
            b, x = base["attack"]["asr_model"], r["attack"]["asr_model"]
            if b.get("value") is None or x.get("value") is None:
                continue
            overlap = bool(b["ci95"] and x["ci95"] and not (x["ci95"][1] < b["ci95"][0] or x["ci95"][0] > b["ci95"][1]))
            direction = "lower" if x["value"] < b["value"] else ("higher" if x["value"] > b["value"] else "equal")
            statements.append({
                "model": model, "defense": r["defense"], "kind": "comparison",
                "text": (f"{model}: {r['defense']} model-level ASR was {direction} than baseline "
                         f"({x['value']:.1%} vs {b['value']:.1%}); the 95% intervals "
                         f"{'overlap, so the difference is not clearly distinguishable at this sample size' if overlap else 'do not overlap'}."),
            })
    return {"scope": scope, "experiment": {"id": experiment["id"], "name": experiment["name"],
                                           "status": experiment["status"], "total_runs": experiment["total_runs"]},
            "statements": statements, "notice": caveat}
