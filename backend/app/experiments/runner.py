"""Experiment engine: plans (case x variant x model x defense) runs, executes them with a
small async worker pool, persists every result immediately, and can resume after pause,
crash or restart by skipping runs that already have a successful result."""
from __future__ import annotations

import asyncio
import json
import random
import uuid
from typing import Any

from app.config import Settings
from app.db import Database, dumps, now_iso
from app.dataset import store
from app.eval.scoring import score
from app.llm.base import ProviderError
from app.llm.registry import ProviderRegistry, split_model_id
from app.soc.analyzer import analyze
from app.soc.prompts import DEFENSES

VARIANTS = ("clean", "modified")


class ExperimentError(ValueError):
    pass


def persist_result(db: Database, analysis: dict[str, Any], *, experiment_id: str | None, dataset_id: str | None,
                   case_id: str | None, variant: str, scored: dict[str, Any] | None) -> int:
    s = scored or {}
    detail = {k: analysis.get(k) for k in ("prompt", "response_text", "raw_output", "final_output", "tool_decisions",
                                           "tripwire", "parse_error", "canary", "disclosure_raw", "disclosure_final")}

    def b(v: Any) -> int | None:
        return None if v is None else int(bool(v))

    cur = db.execute(
        """INSERT OR REPLACE INTO results (experiment_id, dataset_id, case_id, variant, model, provider, defense, is_mock,
           label, attack_type, log_type, verdict_raw, verdict_final, severity_final, correct, attack_success_raw,
           attack_success_final, indicator_recall, tripwire_fired, tool_violation_attempted, injection_flagged,
           parse_ok, latency_ms, error, detail, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (experiment_id, dataset_id, case_id, variant, analysis["model"], analysis["provider"], analysis["defense"],
         int(analysis["is_mock"]), s.get("label"), s.get("attack_type"), analysis.get("log_type"),
         s.get("verdict_raw"), s.get("verdict_final"), s.get("severity_final"), b(s.get("correct")),
         b(s.get("attack_success_raw")), b(s.get("attack_success_final")), s.get("indicator_recall"),
         int(bool(analysis.get("tripwire", {}).get("fired"))),
         int(any(d.get("violation") for d in analysis.get("tool_decisions", []))),
         int(bool((analysis.get("raw_output") or {}).get("embedded_instructions_detected"))),
         int(bool(analysis.get("parse_ok"))), analysis.get("latency_ms"), analysis.get("error"),
         dumps(detail), now_iso()),
    )
    result_id = cur.lastrowid
    base = (result_id, experiment_id, case_id, variant, analysis["model"], analysis["defense"], int(analysis["is_mock"]))
    for d in analysis.get("tool_decisions", []):
        db.execute(
            "INSERT INTO tool_events (result_id, experiment_id, case_id, variant, model, defense, is_mock, tool, arguments,"
            " decision, reason, executed_externally, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?)",
            base + (d["tool"], dumps(d.get("arguments")), d["decision"], d.get("reason"), now_iso()))
    trip = analysis.get("tripwire") or {}
    if trip.get("fired"):
        db.execute(
            "INSERT INTO tripwire_events (result_id, experiment_id, case_id, variant, model, defense, is_mock, reasons,"
            " details, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            base + (dumps(trip.get("reasons", [])), dumps(trip.get("details", {})), now_iso()))
    return result_id


class ExperimentRunner:
    def __init__(self, db: Database, registry: ProviderRegistry, settings: Settings):
        self.db = db
        self.registry = registry
        self.settings = settings
        self.tasks: dict[str, asyncio.Task] = {}
        self.stop_flags: dict[str, asyncio.Event] = {}

    # ------------------------------------------------------------ lifecycle
    def recover_interrupted(self) -> int:
        cur = self.db.execute("UPDATE experiments SET status = 'interrupted' WHERE status = 'running'")
        return cur.rowcount

    def create(self, cfg: dict[str, Any]) -> dict[str, Any]:
        models = list(dict.fromkeys(cfg.get("models") or []))
        defenses = list(dict.fromkeys(cfg.get("defenses") or []))
        variants = list(dict.fromkeys(cfg.get("variants") or list(VARIANTS)))
        dataset_id = cfg.get("dataset_id") or "logjack-v1"
        if not models:
            raise ExperimentError("select at least one model")
        if not defenses:
            raise ExperimentError("select at least one defense")
        for m in models:
            try:
                provider, _ = split_model_id(m)
                self.registry.get(m)
            except ProviderError as exc:
                raise ExperimentError(str(exc)) from exc
        mock_flags = {self.registry.is_mock(m) for m in models}
        if len(mock_flags) > 1:
            raise ExperimentError("mock and real models cannot be mixed in one experiment; "
                                  "run them as separate experiments so simulated results stay separate")
        bad = [d for d in defenses if d not in DEFENSES]
        if bad:
            raise ExperimentError(f"unknown defenses: {bad}")
        if any(v not in VARIANTS for v in variants) or not variants:
            raise ExperimentError(f"variants must be a non-empty subset of {VARIANTS}")
        if not store.get_dataset(self.db, dataset_id):
            raise ExperimentError(f"unknown dataset {dataset_id!r}")

        case_ids = cfg.get("case_ids") or store.all_case_ids(
            self.db, dataset_id, log_types=cfg.get("log_types"), attack_types=cfg.get("attack_types"),
            labels=cfg.get("labels"))
        missing = [c for c in case_ids if not store.get_case(self.db, dataset_id, c)]
        if missing:
            raise ExperimentError(f"unknown case ids: {missing[:5]}")
        limit = cfg.get("limit")
        if limit and int(limit) < len(case_ids):
            seed = int(cfg.get("sample_seed", 42))
            case_ids = sorted(random.Random(seed).sample(case_ids, int(limit)))
        if not case_ids:
            raise ExperimentError("no cases match the selection")
        concurrency = max(1, min(int(cfg.get("concurrency", 4)), 16))

        exp_id = uuid.uuid4().hex[:12]
        config = {"dataset_id": dataset_id, "models": models, "defenses": defenses, "variants": variants,
                  "case_ids": case_ids, "concurrency": concurrency, "limit": limit,
                  "sample_seed": cfg.get("sample_seed", 42), "log_types": cfg.get("log_types"),
                  "attack_types": cfg.get("attack_types"), "labels": cfg.get("labels"),
                  "temperature": self.settings.temperature, "max_tokens": self.settings.max_tokens}
        total = len(case_ids) * len(variants) * len(models) * len(defenses)
        name = (cfg.get("name") or "").strip() or f"Experiment {exp_id[:6]}"
        self.db.execute(
            "INSERT INTO experiments (id, name, status, is_mock, config, total_runs, created_at) VALUES (?,?,?,?,?,?,?)",
            (exp_id, name, "pending", int(mock_flags.pop()), dumps(config), total, now_iso()))
        return self.get(exp_id)

    def get(self, exp_id: str) -> dict[str, Any] | None:
        row = self.db.one("SELECT * FROM experiments WHERE id = ?", (exp_id,))
        if row:
            row["config"] = json.loads(row["config"])
            row["is_mock"] = bool(row["is_mock"])
            row["progress"] = round(row["completed_runs"] / row["total_runs"], 4) if row["total_runs"] else 0
        return row

    def list(self) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT id FROM experiments ORDER BY created_at DESC")
        return [self.get(r["id"]) for r in rows]

    def start(self, exp_id: str) -> dict[str, Any]:
        exp = self.get(exp_id)
        if not exp:
            raise ExperimentError("experiment not found")
        if exp_id in self.tasks and not self.tasks[exp_id].done():
            return exp
        if exp["status"] == "completed":
            raise ExperimentError("experiment already completed")
        self.db.execute("UPDATE experiments SET status = 'running', error = NULL, started_at = COALESCE(started_at, ?),"
                        " finished_at = NULL WHERE id = ?", (now_iso(), exp_id))
        self.stop_flags[exp_id] = asyncio.Event()
        self.tasks[exp_id] = asyncio.create_task(self._run(exp_id))
        return self.get(exp_id)

    def pause(self, exp_id: str) -> dict[str, Any]:
        exp = self.get(exp_id)
        if not exp:
            raise ExperimentError("experiment not found")
        flag = self.stop_flags.get(exp_id)
        if flag and exp_id in self.tasks and not self.tasks[exp_id].done():
            flag.set()
            self.db.execute("UPDATE experiments SET status = 'pausing' WHERE id = ?", (exp_id,))
        elif exp["status"] in ("pending", "interrupted"):
            self.db.execute("UPDATE experiments SET status = 'paused' WHERE id = ?", (exp_id,))
        return self.get(exp_id)

    async def wait(self, exp_id: str) -> None:
        task = self.tasks.get(exp_id)
        if task:
            await task

    def delete(self, exp_id: str) -> None:
        flag = self.stop_flags.get(exp_id)
        if flag:
            flag.set()
        for table in ("tool_events", "tripwire_events", "results"):
            self.db.execute(f"DELETE FROM {table} WHERE experiment_id = ?", (exp_id,))
        self.db.execute("DELETE FROM experiments WHERE id = ?", (exp_id,))

    async def shutdown(self) -> None:
        for exp_id, flag in self.stop_flags.items():
            flag.set()
        for task in list(self.tasks.values()):
            if not task.done():
                try:
                    await asyncio.wait_for(task, timeout=5)
                except (asyncio.TimeoutError, Exception):
                    task.cancel()

    # ------------------------------------------------------------ execution
    def _refresh_counts(self, exp_id: str) -> None:
        self.db.execute(
            "UPDATE experiments SET completed_runs = (SELECT COUNT(*) FROM results WHERE experiment_id = ? AND error IS NULL),"
            " failed_runs = (SELECT COUNT(*) FROM results WHERE experiment_id = ? AND error IS NOT NULL) WHERE id = ?",
            (exp_id, exp_id, exp_id))

    async def _run(self, exp_id: str) -> None:
        exp = self.get(exp_id)
        cfg = exp["config"]
        flag = self.stop_flags[exp_id]
        try:
            # Failed runs are retried on resume.
            self.db.execute("DELETE FROM tool_events WHERE result_id IN (SELECT id FROM results WHERE experiment_id = ?"
                            " AND error IS NOT NULL)", (exp_id,))
            self.db.execute("DELETE FROM results WHERE experiment_id = ? AND error IS NOT NULL", (exp_id,))
            done = {(r["case_id"], r["variant"], r["model"], r["defense"]) for r in self.db.query(
                "SELECT case_id, variant, model, defense FROM results WHERE experiment_id = ?", (exp_id,))}
            plan = [(c, v, m, d) for c in cfg["case_ids"] for v in cfg["variants"] for m in cfg["models"]
                    for d in cfg["defenses"] if (c, v, m, d) not in done]
            self._refresh_counts(exp_id)
            queue: asyncio.Queue = asyncio.Queue()
            for item in plan:
                queue.put_nowait(item)
            cases: dict[str, dict[str, Any]] = {}

            async def worker() -> None:
                while not flag.is_set():
                    try:
                        case_id, variant, model, defense = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        return
                    case = cases.get(case_id) or store.get_case(self.db, cfg["dataset_id"], case_id)
                    cases[case_id] = case
                    v = case[variant]
                    analysis = await analyze(self.registry, self.settings, model_id=model, defense_id=defense,
                                             raw=v["raw"], log_type=case["log_type"], fields=v.get("fields"),
                                             seed_key=f"{case_id}|{variant}")
                    scored = None if analysis.get("error") else score(case, variant, analysis)
                    if scored is None:
                        scored = {"label": case["label"],
                                  "attack_type": case["modified"]["injection"]["attack_type"] if variant == "modified" else None}
                    persist_result(self.db, analysis, experiment_id=exp_id, dataset_id=cfg["dataset_id"],
                                   case_id=case_id, variant=variant, scored=scored)
                    self._refresh_counts(exp_id)

            await asyncio.gather(*(worker() for _ in range(cfg.get("concurrency", 4))))
            self._refresh_counts(exp_id)
            if flag.is_set() and not queue.empty():
                status = "paused"
            else:
                exp = self.get(exp_id)
                status = "completed" if exp and exp["failed_runs"] == 0 else "completed_with_errors"
            if self.get(exp_id):  # may have been deleted meanwhile
                self.db.execute("UPDATE experiments SET status = ?, finished_at = ? WHERE id = ?",
                                (status, now_iso() if status.startswith("completed") else None, exp_id))
        except Exception as exc:  # pragma: no cover - defensive
            self.db.execute("UPDATE experiments SET status = 'failed', error = ? WHERE id = ?", (repr(exc), exp_id))
