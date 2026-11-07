"""Dataset and benchmark persistence: JSONL files on disk mirrored into SQLite."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator

from app.db import Database, dumps, now_iso
from app.dataset.benchmark import ATTACK_TYPES, LABELS, DEFAULT_BENCHMARK_PATH, Benchmark, load_benchmark
from app.dataset import generator
from app.soc.parsers import LOG_TYPES

SEVERITIES = ("informational", "low", "medium", "high", "critical")
INJECTION_FIELDS = ("user_agent", "path", "referrer", "username", "query")


class _Variant(BaseModel):
    raw: str = Field(min_length=1, max_length=20000)
    fields: dict[str, Any] = {}


class _Injection(BaseModel):
    benchmark_id: str
    template_id: str
    attack_type: str
    field: str
    objective: dict[str, str]
    injected_text: str = Field(max_length=1000)
    field_display: str | None = None

    @field_validator("attack_type")
    @classmethod
    def _at(cls, v: str) -> str:
        if v not in ATTACK_TYPES:
            raise ValueError(f"attack_type must be one of {ATTACK_TYPES}")
        return v

    @field_validator("field")
    @classmethod
    def _f(cls, v: str) -> str:
        if v not in INJECTION_FIELDS:
            raise ValueError(f"field must be one of {INJECTION_FIELDS}")
        return v


class _Modified(_Variant):
    injection: _Injection


class CaseModel(BaseModel):
    case_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    log_type: str
    scenario: str = "imported"
    category: str = "imported"
    label: str
    severity: str
    description: str = ""
    expected_indicators: list[str] = []
    primary_indicator: str = ""
    clean: _Variant
    modified: _Modified

    @field_validator("log_type")
    @classmethod
    def _lt(cls, v: str) -> str:
        if v not in LOG_TYPES:
            raise ValueError(f"log_type must be one of {LOG_TYPES}")
        return v

    @field_validator("label")
    @classmethod
    def _lb(cls, v: str) -> str:
        if v not in LABELS:
            raise ValueError(f"label must be one of {LABELS}")
        return v

    @field_validator("severity")
    @classmethod
    def _sv(cls, v: str) -> str:
        if v not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        return v


class DatasetValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors[:5]))
        self.errors = errors


def parse_jsonl(text: str, dataset_id: str) -> list[dict[str, Any]]:
    cases, errors, seen = [], [], set()
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            model = CaseModel.model_validate(obj)
        except json.JSONDecodeError as exc:
            errors.append(f"line {n}: invalid JSON ({exc.msg})")
            continue
        except ValidationError as exc:
            errors.append(f"line {n}: " + "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:3]))
            continue
        if model.case_id in seen:
            errors.append(f"line {n}: duplicate case_id {model.case_id}")
            continue
        seen.add(model.case_id)
        rec = model.model_dump()
        rec["dataset_id"] = dataset_id
        cases.append(rec)
    if errors:
        raise DatasetValidationError(errors)
    if not cases:
        raise DatasetValidationError(["no cases found"])
    if len(cases) > 5000:
        raise DatasetValidationError(["at most 5000 cases per dataset"])
    return cases


def _insert_cases(db: Database, dataset_id: str, cases: list[dict[str, Any]]) -> None:
    db.execute("DELETE FROM cases WHERE dataset_id = ?", (dataset_id,))
    db.executemany(
        "INSERT INTO cases (dataset_id, case_id, log_type, label, severity, scenario, attack_type, injection_field, data)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        [(dataset_id, c["case_id"], c["log_type"], c["label"], c["severity"], c.get("scenario", ""),
          c["modified"]["injection"]["attack_type"], c["modified"]["injection"]["field"], dumps(c)) for c in cases],
    )


def _register(db: Database, dataset_id: str, name: str, description: str, source: str, path: Path,
              sha: str, cases: list[dict[str, Any]]) -> None:
    db.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))
    db.execute(
        "INSERT INTO datasets (id, name, description, source, file_path, sha256, case_count, created_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (dataset_id, name, description, source, str(path), sha, len(cases), now_iso()),
    )
    _insert_cases(db, dataset_id, cases)


def sync_builtin(db: Database, data_dir: str) -> None:
    """Load the built-in dataset (generating it if missing) and the built-in benchmark."""
    path = Path(data_dir) / "datasets" / f"{generator.DATASET_ID}.jsonl"
    if not path.exists():
        generator.write_dataset(path=path, manifest_path=path.parent / f"{generator.DATASET_ID}.manifest.json")
    text = path.read_text(encoding="utf-8")
    sha = hashlib.sha256(text.encode()).hexdigest()
    row = db.one("SELECT sha256 FROM datasets WHERE id = ?", (generator.DATASET_ID,))
    if not row or row["sha256"] != sha:
        cases = parse_jsonl(text, generator.DATASET_ID)
        _register(db, generator.DATASET_ID, "LogJack synthetic v1",
                  "200 synthetic labelled nginx/ssh/dns/ids cases with clean and benchmark-modified variants.",
                  "builtin", path, sha, cases)
    bench_path = Path(data_dir) / "benchmarks" / DEFAULT_BENCHMARK_PATH.name
    if bench_path.exists():
        register_benchmark(db, load_benchmark(bench_path))


def import_dataset(db: Database, data_dir: str, name: str, text: str) -> dict[str, Any]:
    sha = hashlib.sha256(text.encode()).hexdigest()
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "dataset"
    dataset_id = f"imp-{slug}-{sha[:8]}"
    cases = parse_jsonl(text, dataset_id)
    path = Path(data_dir) / "datasets" / "imported" / f"{dataset_id}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _register(db, dataset_id, name, f"Imported dataset ({len(cases)} cases).", "imported", path, sha, cases)
    return get_dataset(db, dataset_id)


def register_benchmark(db: Database, bench: Benchmark) -> None:
    db.execute("DELETE FROM benchmarks WHERE id = ?", (bench.benchmark_id,))
    db.execute("INSERT INTO benchmarks (id, version, description, template_count, data, imported_at) VALUES (?,?,?,?,?,?)",
               (bench.benchmark_id, bench.version, bench.description, len(bench.templates),
                bench.model_dump_json(), now_iso()))


def import_benchmark(db: Database, data_dir: str, bench: Benchmark, seed: int = generator.DEFAULT_SEED) -> dict[str, Any]:
    """Register a reviewed benchmark and build a dataset applying it to the built-in clean cases."""
    register_benchmark(db, bench)
    dataset_id = f"{generator.DATASET_ID}+{bench.benchmark_id}"
    cases = generator.generate(seed=seed, benchmark=bench, dataset_id=dataset_id)
    text = generator.to_jsonl(cases)
    path = Path(data_dir) / "datasets" / "imported" / f"{dataset_id}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _register(db, dataset_id, f"LogJack v1 x {bench.benchmark_id}",
              f"Built-in clean cases with templates from benchmark {bench.benchmark_id} v{bench.version}.",
              "imported", path, generator.sha256_text(text), cases)
    return get_dataset(db, dataset_id)


def list_benchmarks(db: Database) -> list[dict[str, Any]]:
    rows = db.query("SELECT * FROM benchmarks ORDER BY imported_at")
    for r in rows:
        r["data"] = json.loads(r["data"])
    return rows


def get_dataset(db: Database, dataset_id: str) -> dict[str, Any] | None:
    return db.one("SELECT * FROM datasets WHERE id = ?", (dataset_id,))


def list_datasets(db: Database) -> list[dict[str, Any]]:
    return db.query("SELECT * FROM datasets ORDER BY source, created_at")


def dataset_stats(db: Database, dataset_id: str) -> dict[str, Any]:
    def grp(col: str) -> dict[str, int]:
        return {r["k"]: r["n"] for r in db.query(
            f"SELECT {col} AS k, COUNT(*) AS n FROM cases WHERE dataset_id = ? GROUP BY {col} ORDER BY {col}", (dataset_id,))}
    return {"by_log_type": grp("log_type"), "by_label": grp("label"), "by_attack_type": grp("attack_type"),
            "by_injection_field": grp("injection_field"), "by_severity": grp("severity")}


def query_cases(db: Database, dataset_id: str, *, log_type: str | None = None, label: str | None = None,
                attack_type: str | None = None, q: str | None = None, offset: int = 0,
                limit: int = 50) -> tuple[list[dict[str, Any]], int]:
    where, params = ["dataset_id = ?"], [dataset_id]
    for col, val in (("log_type", log_type), ("label", label), ("attack_type", attack_type)):
        if val:
            where.append(f"{col} = ?")
            params.append(val)
    if q:
        where.append("(case_id LIKE ? OR data LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    w = " AND ".join(where)
    total = db.one(f"SELECT COUNT(*) AS n FROM cases WHERE {w}", params)["n"]
    rows = db.query(f"SELECT data FROM cases WHERE {w} ORDER BY case_id LIMIT ? OFFSET ?", params + [limit, offset])
    return [json.loads(r["data"]) for r in rows], total


def get_case(db: Database, dataset_id: str, case_id: str) -> dict[str, Any] | None:
    row = db.one("SELECT data FROM cases WHERE dataset_id = ? AND case_id = ?", (dataset_id, case_id))
    return json.loads(row["data"]) if row else None


def all_case_ids(db: Database, dataset_id: str, *, log_types: list[str] | None = None,
                 attack_types: list[str] | None = None, labels: list[str] | None = None) -> list[str]:
    where, params = ["dataset_id = ?"], [dataset_id]
    for col, vals in (("log_type", log_types), ("attack_type", attack_types), ("label", labels)):
        if vals:
            where.append(f"{col} IN ({','.join('?' * len(vals))})")
            params += list(vals)
    return [r["case_id"] for r in db.query(f"SELECT case_id FROM cases WHERE {' AND '.join(where)} ORDER BY case_id", params)]
