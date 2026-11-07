from __future__ import annotations

import csv
import io
import json
from typing import Any, Literal

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field, ValidationError

from app.dataset import store
from app.dataset.benchmark import parse_benchmark
from app.eval.findings import build_findings
from app.eval.metrics import compute_metrics
from app.eval.scoring import score
from app.experiments.runner import ExperimentError, persist_result
from app.llm.base import ProviderError
from app.soc.analyzer import analyze
from app.soc.prompts import DEFENSES
from app.soc.tools import ALLOWED_TOOLS, PRIVILEGED_TOOLS

router = APIRouter(prefix="/api")

RESULT_COLUMNS = ["id", "experiment_id", "dataset_id", "case_id", "variant", "model", "provider", "defense", "is_mock",
                  "log_type", "label", "attack_type", "verdict_raw", "verdict_final", "severity_final", "correct",
                  "attack_success_raw", "attack_success_final", "indicator_recall", "tripwire_fired",
                  "tool_violation_attempted", "injection_flagged", "parse_ok", "latency_ms", "error", "created_at"]


def _db(req: Request):
    return req.app.state.db


def _runner(req: Request):
    return req.app.state.runner


# ------------------------------------------------------------------ meta

@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/models")
async def models(req: Request) -> list[dict[str, Any]]:
    return await req.app.state.registry.catalog()


@router.get("/defenses")
def defenses() -> list[dict[str, Any]]:
    return [d.__dict__ for d in DEFENSES.values()]


@router.get("/tools")
def tools() -> dict[str, Any]:
    return {"allowed": ALLOWED_TOOLS, "privileged_denied": PRIVILEGED_TOOLS,
            "note": "All tools are simulated. Nothing is ever executed against real systems."}


@router.get("/config")
def config(req: Request) -> dict[str, Any]:
    s = req.app.state.settings
    return {"temperature": s.temperature, "max_tokens": s.max_tokens, "openai_base_url": s.openai_base_url,
            "ollama_base_url": s.ollama_base_url, "openai_configured": bool(s.openai_api_key),
            "anthropic_configured": bool(s.anthropic_api_key), "mock_latency_ms": s.mock_latency_ms}


# ------------------------------------------------------------------ datasets

@router.get("/datasets")
def datasets(req: Request) -> list[dict[str, Any]]:
    return store.list_datasets(_db(req))


@router.get("/datasets/{dataset_id}/stats")
def dataset_stats(dataset_id: str, req: Request) -> dict[str, Any]:
    if not store.get_dataset(_db(req), dataset_id):
        raise HTTPException(404, "dataset not found")
    return store.dataset_stats(_db(req), dataset_id)


@router.get("/datasets/{dataset_id}/cases")
def dataset_cases(dataset_id: str, req: Request, log_type: str | None = None, label: str | None = None,
                  attack_type: str | None = None, q: str | None = None, offset: int = Query(0, ge=0),
                  limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    if not store.get_dataset(_db(req), dataset_id):
        raise HTTPException(404, "dataset not found")
    items, total = store.query_cases(_db(req), dataset_id, log_type=log_type, label=label, attack_type=attack_type,
                                     q=q, offset=offset, limit=limit)
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/datasets/{dataset_id}/cases/{case_id}")
def dataset_case(dataset_id: str, case_id: str, req: Request) -> dict[str, Any]:
    case = store.get_case(_db(req), dataset_id, case_id)
    if not case:
        raise HTTPException(404, "case not found")
    results = _db(req).query(
        "SELECT id, experiment_id, variant, model, defense, is_mock, verdict_final, correct,"
        " attack_success_raw, attack_success_final, tripwire_fired, latency_ms, error"
        " FROM results WHERE dataset_id = ? AND case_id = ? ORDER BY id DESC LIMIT 100",
        (dataset_id, case_id))
    return {"case": case, "results": results}


@router.get("/datasets/{dataset_id}/download")
def dataset_download(dataset_id: str, req: Request) -> Response:
    ds = store.get_dataset(_db(req), dataset_id)
    if not ds:
        raise HTTPException(404, "dataset not found")
    with open(ds["file_path"], "r", encoding="utf-8") as fh:
        body = fh.read()
    return Response(body, media_type="application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="{dataset_id}.jsonl"'})


@router.post("/datasets/import")
async def dataset_import(req: Request, file: UploadFile = File(...), name: str = Form("Imported dataset")) -> dict[str, Any]:
    raw = await file.read()
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(413, "file too large (20 MB max)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "file must be UTF-8 JSONL")
    try:
        return store.import_dataset(_db(req), req.app.state.settings.data_dir, name, text)
    except store.DatasetValidationError as exc:
        raise HTTPException(422, {"message": "dataset validation failed", "errors": exc.errors[:50]})


# ------------------------------------------------------------------ benchmarks

@router.get("/benchmarks")
def benchmarks(req: Request) -> list[dict[str, Any]]:
    return store.list_benchmarks(_db(req))


@router.post("/benchmarks/import")
async def benchmark_import(req: Request, file: UploadFile = File(...)) -> dict[str, Any]:
    raw = await file.read()
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(413, "file too large (2 MB max)")
    try:
        bench = parse_benchmark(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, f"invalid JSON: {exc}")
    except ValidationError as exc:
        raise HTTPException(422, {"message": "benchmark validation failed",
                                  "errors": [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:50]]})
    ds = store.import_benchmark(_db(req), req.app.state.settings.data_dir, bench)
    return {"benchmark_id": bench.benchmark_id, "templates": len(bench.templates), "dataset": ds}


# ------------------------------------------------------------------ playground

class AnalyzeRequest(BaseModel):
    log: str = Field(min_length=1, max_length=20000)
    log_type: Literal["auto", "nginx", "ssh", "dns", "ids"] = "auto"
    model: str = "mock:naive"
    defense: str = "baseline"
    dataset_id: str | None = None
    case_id: str | None = None
    variant: Literal["clean", "modified", "adhoc"] = "adhoc"


@router.post("/analyze")
async def analyze_log(body: AnalyzeRequest, req: Request) -> dict[str, Any]:
    if body.defense not in DEFENSES:
        raise HTTPException(422, f"unknown defense {body.defense}")
    case = store.get_case(_db(req), body.dataset_id, body.case_id) if body.dataset_id and body.case_id else None
    # Only reuse a case's structured fields when the submitted log is unchanged.
    use_case = bool(case and body.variant in ("clean", "modified") and case[body.variant]["raw"] == body.log)
    fields = case[body.variant]["fields"] if use_case else None
    try:
        result = await analyze(req.app.state.registry, req.app.state.settings, model_id=body.model,
                               defense_id=body.defense, raw=body.log,
                               log_type=None if body.log_type == "auto" else body.log_type, fields=fields)
    except ProviderError as exc:
        raise HTTPException(422, str(exc))
    variant = body.variant if use_case else "adhoc"
    scored = score(case, variant, result) if use_case and not result.get("error") else None
    result["score"] = scored
    result["result_id"] = persist_result(_db(req), result, experiment_id=None,
                                         dataset_id=body.dataset_id if use_case else None,
                                         case_id=body.case_id if use_case else None, variant=variant, scored=scored)
    return result


# ------------------------------------------------------------------ experiments

class ExperimentRequest(BaseModel):
    name: str = ""
    dataset_id: str = "logjack-v1"
    models: list[str]
    defenses: list[str]
    variants: list[str] = ["clean", "modified"]
    case_ids: list[str] | None = None
    log_types: list[str] | None = None
    attack_types: list[str] | None = None
    labels: list[str] | None = None
    limit: int | None = Field(None, ge=1)
    sample_seed: int = 42
    concurrency: int = Field(4, ge=1, le=16)
    start: bool = True


def _public(exp: dict[str, Any]) -> dict[str, Any]:
    exp = dict(exp)
    cfg = dict(exp["config"])
    cfg["case_count"] = len(cfg.pop("case_ids", []) or [])
    exp["config"] = cfg
    return exp


@router.get("/experiments")
def experiments(req: Request) -> list[dict[str, Any]]:
    return [_public(e) for e in _runner(req).list()]


@router.post("/experiments")
async def create_experiment(body: ExperimentRequest, req: Request) -> dict[str, Any]:
    try:
        exp = _runner(req).create(body.model_dump())
        if body.start:
            exp = _runner(req).start(exp["id"])
        return _public(exp)
    except ExperimentError as exc:
        raise HTTPException(422, str(exc))


def _exp_or_404(req: Request, exp_id: str) -> dict[str, Any]:
    exp = _runner(req).get(exp_id)
    if not exp:
        raise HTTPException(404, "experiment not found")
    return exp


@router.get("/experiments/{exp_id}")
def get_experiment(exp_id: str, req: Request) -> dict[str, Any]:
    return _public(_exp_or_404(req, exp_id))


@router.post("/experiments/{exp_id}/start")
@router.post("/experiments/{exp_id}/resume")
async def start_experiment(exp_id: str, req: Request) -> dict[str, Any]:
    _exp_or_404(req, exp_id)
    try:
        return _public(_runner(req).start(exp_id))
    except ExperimentError as exc:
        raise HTTPException(409, str(exc))


@router.post("/experiments/{exp_id}/pause")
async def pause_experiment(exp_id: str, req: Request) -> dict[str, Any]:
    _exp_or_404(req, exp_id)
    return _public(_runner(req).pause(exp_id))


@router.delete("/experiments/{exp_id}")
async def delete_experiment(exp_id: str, req: Request) -> dict[str, str]:
    _exp_or_404(req, exp_id)
    _runner(req).delete(exp_id)
    return {"status": "deleted"}


def _result_rows(req: Request, exp_id: str) -> list[dict[str, Any]]:
    return _db(req).query(f"SELECT {', '.join(RESULT_COLUMNS)} FROM results WHERE experiment_id = ? ORDER BY id", (exp_id,))


@router.get("/experiments/{exp_id}/metrics")
def experiment_metrics(exp_id: str, req: Request) -> dict[str, Any]:
    exp = _exp_or_404(req, exp_id)
    return {"experiment_id": exp_id, "is_mock": exp["is_mock"], "status": exp["status"],
            "metrics": compute_metrics(_result_rows(req, exp_id))}


@router.get("/experiments/{exp_id}/results")
def experiment_results(exp_id: str, req: Request, variant: str | None = None, model: str | None = None,
                       defense: str | None = None, attack_type: str | None = None,
                       outcome: Literal["attack_success", "attack_blocked", "incorrect", "tripwire", "error"] | None = None,
                       offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    _exp_or_404(req, exp_id)
    where, params = ["experiment_id = ?"], [exp_id]
    for col, val in (("variant", variant), ("model", model), ("defense", defense), ("attack_type", attack_type)):
        if val:
            where.append(f"{col} = ?")
            params.append(val)
    cond = {"attack_success": "attack_success_final = 1", "attack_blocked": "attack_success_final = 0",
            "incorrect": "correct = 0", "tripwire": "tripwire_fired = 1", "error": "error IS NOT NULL"}
    if outcome:
        where.append(cond[outcome])
    w = " AND ".join(where)
    total = _db(req).one(f"SELECT COUNT(*) AS n FROM results WHERE {w}", params)["n"]
    rows = _db(req).query(f"SELECT {', '.join(RESULT_COLUMNS)} FROM results WHERE {w} ORDER BY id LIMIT ? OFFSET ?",
                          params + [limit, offset])
    return {"items": rows, "total": total}


@router.get("/results/{result_id}")
def get_result(result_id: int, req: Request) -> dict[str, Any]:
    row = _db(req).one("SELECT * FROM results WHERE id = ?", (result_id,))
    if not row:
        raise HTTPException(404, "result not found")
    row["detail"] = json.loads(row["detail"]) if row.get("detail") else None
    return row


def _csv(rows: list[dict[str, Any]], columns: list[str]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        elif isinstance(v, (list, tuple)):
            out[key] = json.dumps(v)
        else:
            out[key] = v
    return out


@router.get("/experiments/{exp_id}/export")
def export_experiment(exp_id: str, req: Request, kind: Literal["results", "metrics"] = "results",
                      format: Literal["csv", "json"] = "csv") -> Response:
    exp = _exp_or_404(req, exp_id)
    tag = "MOCK" if exp["is_mock"] else "REAL"
    fname = f"logjack-{exp_id}-{tag}-{kind}.{format}"
    rows = _result_rows(req, exp_id)
    if kind == "results":
        if format == "json":
            body = json.dumps({"experiment": exp, "is_mock": exp["is_mock"], "results": rows}, indent=2)
        else:
            body = _csv(rows, RESULT_COLUMNS)
    else:
        metrics = compute_metrics(rows)
        if format == "json":
            body = json.dumps({"experiment": exp, "is_mock": exp["is_mock"], "metrics": metrics}, indent=2)
        else:
            flat = [_flatten(m) for m in metrics]
            cols = sorted({k for f in flat for k in f}, key=lambda c: (c not in ("model", "defense", "is_mock"), c))
            body = _csv(flat, cols)
    media = "application/json" if format == "json" else "text/csv"
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# ------------------------------------------------------------------ events, overview, findings

@router.get("/tripwires")
def tripwires(req: Request, experiment_id: str | None = None, is_mock: bool | None = None,
              limit: int = Query(200, ge=1, le=2000)) -> list[dict[str, Any]]:
    where, params = ["1=1"], []
    if experiment_id:
        where.append("experiment_id = ?")
        params.append(experiment_id)
    if is_mock is not None:
        where.append("is_mock = ?")
        params.append(int(is_mock))
    rows = _db(req).query(f"SELECT * FROM tripwire_events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                          params + [limit])
    for r in rows:
        r["reasons"] = json.loads(r["reasons"])
        r["details"] = json.loads(r["details"]) if r["details"] else {}
    return rows


@router.get("/tool-events")
def tool_events(req: Request, decision: str | None = None, experiment_id: str | None = None,
                limit: int = Query(200, ge=1, le=2000)) -> list[dict[str, Any]]:
    where, params = ["1=1"], []
    if decision:
        where.append("decision = ?")
        params.append(decision)
    if experiment_id:
        where.append("experiment_id = ?")
        params.append(experiment_id)
    rows = _db(req).query(f"SELECT * FROM tool_events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                          params + [limit])
    for r in rows:
        r["arguments"] = json.loads(r["arguments"]) if r["arguments"] else {}
    return rows


def _latest_completed(req: Request, is_mock: bool) -> dict[str, Any] | None:
    row = _db(req).one("SELECT id FROM experiments WHERE is_mock = ? AND status LIKE 'completed%'"
                       " ORDER BY COALESCE(finished_at, created_at) DESC LIMIT 1", (int(is_mock),))
    return _runner(req).get(row["id"]) if row else None


@router.get("/overview")
def overview(req: Request) -> dict[str, Any]:
    db = _db(req)

    def n(sql: str) -> int:
        return db.one(sql)["n"]

    counts = {
        "datasets": n("SELECT COUNT(*) AS n FROM datasets"),
        "cases": n("SELECT COUNT(*) AS n FROM cases WHERE dataset_id = 'logjack-v1'"),
        "experiments": n("SELECT COUNT(*) AS n FROM experiments"),
        "runs_real": n("SELECT COUNT(*) AS n FROM results WHERE is_mock = 0"),
        "runs_mock": n("SELECT COUNT(*) AS n FROM results WHERE is_mock = 1"),
        "tripwire_events": n("SELECT COUNT(*) AS n FROM tripwire_events"),
        "denied_tool_requests": n("SELECT COUNT(*) AS n FROM tool_events WHERE decision = 'denied'"),
        "executed_external_actions": n("SELECT COUNT(*) AS n FROM tool_events WHERE executed_externally = 1"),
    }
    latest = {}
    for scope, flag in (("real", False), ("mock", True)):
        exp = _latest_completed(req, flag)
        latest[scope] = {"experiment": _public(exp) if exp else None,
                         "metrics": compute_metrics(_result_rows(req, exp["id"])) if exp else []}
    recent = [_public(e) for e in _runner(req).list()[:6]]
    return {"counts": counts, "latest": latest, "recent_experiments": recent}


@router.get("/findings")
def findings(req: Request, scope: Literal["real", "mock"] = "real", experiment_id: str | None = None) -> dict[str, Any]:
    if experiment_id:
        exp = _exp_or_404(req, experiment_id)
        scope = "mock" if exp["is_mock"] else "real"
    else:
        exp = _latest_completed(req, scope == "mock")
    metrics = compute_metrics(_result_rows(req, exp["id"])) if exp else []
    return build_findings(exp, metrics, scope)
