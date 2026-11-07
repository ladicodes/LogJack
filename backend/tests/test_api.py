"""API integration tests through FastAPI's TestClient (lifespan included)."""
import asyncio
import csv
import io
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.db import Database
from app.main import create_app


@pytest.fixture()
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c


def wait_for(client, exp_id, statuses=("completed", "completed_with_errors"), timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        e = client.get(f"/api/experiments/{exp_id}").json()
        if e["status"] in statuses:
            return e
        time.sleep(0.05)
    raise AssertionError(f"timeout; last status {e['status']}")


def test_health_and_meta(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    defenses = client.get("/api/defenses").json()
    assert [d["id"] for d in defenses] == ["baseline", "guardrails", "isolation", "combined"]
    catalog = client.get("/api/models").json()
    mock = next(p for p in catalog if p["provider"] == "mock")
    assert mock["is_mock"] and "mock:naive" in mock["models"]
    assert next(p for p in catalog if p["provider"] == "openai")["configured"] is False
    tools = client.get("/api/tools").json()
    assert "whitelist_ip" in tools["privileged_denied"]


def _preflight(client, origin):
    return client.options("/api/overview", headers={"Origin": origin, "Access-Control-Request-Method": "GET"})


@pytest.mark.parametrize("origin", [
    "https://log-jack.vercel.app",                                   # production
    "https://log-jack-git-main-ladicodes-projects.vercel.app",       # branch deployment
    "https://log-jack-a1b2c3d4e-ladicodes-projects.vercel.app",      # per-deploy preview
    "http://localhost:5173",                                         # local dev
])
def test_cors_allows_frontend_origins(client, origin):
    r = _preflight(client, origin)
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == origin
    simple = client.get("/api/health", headers={"Origin": origin})
    assert simple.headers["access-control-allow-origin"] == origin


@pytest.mark.parametrize("origin", [
    "https://evil.example.com",
    "https://log-jack.vercel.app.evil.com",   # suffix trick must not match
    "https://notlog-jack.vercel.app",
    "http://log-jack.vercel.app",             # plain http is not allowed
])
def test_cors_rejects_other_origins(client, origin):
    r = _preflight(client, origin)
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers
    assert "access-control-allow-origin" not in client.get("/api/health", headers={"Origin": origin}).headers


def test_cors_origins_configurable(settings):
    settings.cors_origins = "https://soc.example.org"
    settings.cors_origin_regex = ""
    with TestClient(create_app(settings)) as c:
        assert _preflight(c, "https://soc.example.org").status_code == 200
        assert _preflight(c, "https://log-jack.vercel.app").status_code == 400


def test_dataset_endpoints(client):
    ds = client.get("/api/datasets").json()
    assert ds[0]["id"] == "logjack-v1" and ds[0]["case_count"] == 200
    stats = client.get("/api/datasets/logjack-v1/stats").json()
    assert sum(stats["by_label"].values()) == 200
    page = client.get("/api/datasets/logjack-v1/cases", params={"log_type": "ssh", "limit": 10}).json()
    assert page["total"] == 50 and len(page["items"]) == 10
    assert all(c["log_type"] == "ssh" for c in page["items"])
    one = client.get("/api/datasets/logjack-v1/cases/LJ-DNS-001").json()
    assert one["case"]["case_id"] == "LJ-DNS-001" and "injection" in one["case"]["modified"]
    assert client.get("/api/datasets/logjack-v1/cases/NOPE").status_code == 404
    dl = client.get("/api/datasets/logjack-v1/download")
    assert dl.status_code == 200 and len(dl.text.splitlines()) == 200


def test_dataset_import_roundtrip_and_validation(client):
    dl = client.get("/api/datasets/logjack-v1/download").text
    subset = "\n".join(dl.splitlines()[:5]) + "\n"
    r = client.post("/api/datasets/import", files={"file": ("x.jsonl", subset)}, data={"name": "Five cases"})
    assert r.status_code == 200, r.text
    assert r.json()["case_count"] == 5 and r.json()["source"] == "imported"
    bad = client.post("/api/datasets/import", files={"file": ("x.jsonl", '{"case_id": "a"}\n')})
    assert bad.status_code == 422 and bad.json()["detail"]["errors"]


def test_benchmark_import_builds_dataset(client, data_dir):
    bench = json.loads((data_dir / "benchmarks" / "logjack-pi-bench-v1.json").read_text())
    bench["benchmark_id"] = "reviewed-subset"
    bench["templates"] = [t for t in bench["templates"] if t["id"] in ("VM-01", "FP-01")]
    r = client.post("/api/benchmarks/import", files={"file": ("b.json", json.dumps(bench))})
    assert r.status_code == 200, r.text
    ds_id = r.json()["dataset"]["id"]
    assert r.json()["dataset"]["case_count"] == 200
    page = client.get(f"/api/datasets/{ds_id}/cases", params={"limit": 500}).json()
    assert {c["modified"]["injection"]["template_id"] for c in page["items"]} <= {"VM-01", "FP-01"}
    assert any(b["id"] == "reviewed-subset" for b in client.get("/api/benchmarks").json())
    bench["templates"][0]["attack_type"] = "nope"
    assert client.post("/api/benchmarks/import", files={"file": ("b.json", json.dumps(bench))}).status_code == 422


def test_analyze_playground(client):
    case = client.get("/api/datasets/logjack-v1/cases/LJ-NGX-002").json()["case"]
    r = client.post("/api/analyze", json={"log": case["modified"]["raw"], "model": "mock:naive", "defense": "combined",
                                         "dataset_id": "logjack-v1", "case_id": "LJ-NGX-002", "variant": "modified"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_mock"] and body["parse_ok"] and body["score"] is not None
    assert body["prompt"]["system"].startswith("LogJack SOC Analyst Profile v1")
    detail = client.get(f"/api/results/{body['result_id']}").json()
    assert detail["experiment_id"] is None and detail["detail"]["response_text"]
    adhoc = client.post("/api/analyze", json={"log": "Mar 01 00:00:00 h sshd[1]: Invalid user test from 203.0.113.8 port 1"})
    assert adhoc.status_code == 200 and adhoc.json()["log_type"] == "ssh" and adhoc.json()["score"] is None
    assert client.post("/api/analyze", json={"log": "x", "defense": "nope"}).status_code == 422
    assert client.post("/api/analyze", json={"log": "x", "model": "bogus:m"}).status_code == 422


def test_experiment_lifecycle_metrics_and_exports(client):
    r = client.post("/api/experiments", json={"name": "mock smoke", "models": ["mock:naive", "mock:cautious"],
                                              "defenses": ["baseline", "combined"], "limit": 12, "sample_seed": 7})
    assert r.status_code == 200, r.text
    exp = r.json()
    assert exp["is_mock"] and exp["total_runs"] == 12 * 2 * 2 * 2 and exp["config"]["case_count"] == 12
    done = wait_for(client, exp["id"])
    assert done["status"] == "completed" and done["completed_runs"] == 96

    m = client.get(f"/api/experiments/{exp['id']}/metrics").json()
    assert m["is_mock"] and len(m["metrics"]) == 4
    for row in m["metrics"]:
        assert row["clean"]["runs"] == 12 and row["modified"]["runs"] == 12
        assert row["attack"]["asr_model"]["n"] > 0

    res = client.get(f"/api/experiments/{exp['id']}/results", params={"variant": "modified", "limit": 5}).json()
    assert res["total"] == 48 and len(res["items"]) == 5

    csv_text = client.get(f"/api/experiments/{exp['id']}/export", params={"kind": "results", "format": "csv"}).text
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == 96 and all(r["is_mock"] == "1" for r in rows)
    mj = client.get(f"/api/experiments/{exp['id']}/export", params={"kind": "metrics", "format": "json"})
    assert "MOCK" in mj.headers["content-disposition"] and mj.json()["is_mock"] is True
    mc = client.get(f"/api/experiments/{exp['id']}/export", params={"kind": "metrics", "format": "csv"}).text
    assert "attack.asr_model.value" in mc.splitlines()[0]

    trips = client.get("/api/tripwires", params={"experiment_id": exp["id"]}).json()
    assert all(t["defense"] == "combined" for t in trips)
    events = client.get("/api/tool-events", params={"experiment_id": exp["id"]}).json()
    assert all(e["executed_externally"] == 0 for e in events)

    ov = client.get("/api/overview").json()
    assert ov["counts"]["runs_mock"] >= 96 and ov["counts"]["executed_external_actions"] == 0
    assert ov["latest"]["mock"]["experiment"]["id"] == exp["id"] and ov["latest"]["real"]["experiment"] is None

    f_mock = client.get("/api/findings", params={"scope": "mock"}).json()
    assert f_mock["statements"] and "mock provider" in f_mock["notice"]
    f_real = client.get("/api/findings", params={"scope": "real"}).json()
    assert f_real["statements"] == [] and "No completed real LLM experiments" in f_real["notice"]

    assert client.post(f"/api/experiments/{exp['id']}/resume").status_code == 409  # already completed
    assert client.delete(f"/api/experiments/{exp['id']}").json() == {"status": "deleted"}
    assert client.get(f"/api/experiments/{exp['id']}").status_code == 404


def test_experiment_validation(client):
    bad = [
        {"models": [], "defenses": ["baseline"]},
        {"models": ["mock:naive"], "defenses": []},
        {"models": ["mock:naive", "openai:gpt-4o-mini"], "defenses": ["baseline"]},
        {"models": ["mock:naive"], "defenses": ["nope"]},
        {"models": ["mock:naive"], "defenses": ["baseline"], "variants": ["weird"]},
        {"models": ["mock:naive"], "defenses": ["baseline"], "dataset_id": "missing"},
        {"models": ["mock:naive"], "defenses": ["baseline"], "case_ids": ["NOPE"]},
    ]
    for body in bad:
        r = client.post("/api/experiments", json=body)
        assert r.status_code == 422, body
    mixed = client.post("/api/experiments", json={"models": ["mock:naive", "openai:x"], "defenses": ["baseline"]})
    assert "cannot be mixed" in mixed.json()["detail"]


def test_filters_select_cases(client):
    r = client.post("/api/experiments", json={"models": ["mock:naive"], "defenses": ["baseline"], "variants": ["modified"],
                                              "attack_types": ["unauthorized_action"], "log_types": ["nginx"], "start": False})
    exp = r.json()
    assert exp["status"] == "pending" and exp["config"]["case_count"] > 0
    assert exp["total_runs"] == exp["config"]["case_count"]


def test_pause_and_resume_skip_completed_runs(settings):
    settings.mock_latency_ms = 15
    with TestClient(create_app(settings)) as client:
        exp = client.post("/api/experiments", json={"models": ["mock:naive"], "defenses": ["baseline", "isolation"],
                                                    "limit": 20, "concurrency": 1}).json()
        time.sleep(0.25)
        paused = client.post(f"/api/experiments/{exp['id']}/pause").json()
        assert paused["status"] in ("pausing", "paused", "completed")
        e = wait_for(client, exp["id"], statuses=("paused", "completed"))
        if e["status"] == "completed":
            pytest.skip("experiment finished before pause took effect")
        done_before = e["completed_runs"]
        assert 0 < done_before < e["total_runs"]
        client.post(f"/api/experiments/{exp['id']}/resume")
        final = wait_for(client, exp["id"])
        assert final["completed_runs"] == final["total_runs"] == 80
        n = client.get(f"/api/experiments/{exp['id']}/results", params={"limit": 1}).json()["total"]
        assert n == 80  # no duplicate runs after resume


def test_interrupted_experiment_recovers_after_restart(settings):
    settings.mock_latency_ms = 0
    with TestClient(create_app(settings)) as client:
        exp = client.post("/api/experiments", json={"models": ["mock:naive"], "defenses": ["baseline"],
                                                    "limit": 10, "start": False}).json()
    # Simulate a crash mid-run: mark running and keep 3 results only.
    db = Database(settings.db_path)
    db.execute("UPDATE experiments SET status = 'running' WHERE id = ?", (exp["id"],))
    db.close()
    with TestClient(create_app(settings)) as client:
        e = client.get(f"/api/experiments/{exp['id']}").json()
        assert e["status"] == "interrupted"
        client.post(f"/api/experiments/{exp['id']}/resume")
        final = wait_for(client, exp["id"])
        assert final["completed_runs"] == 20


def test_failed_runs_recorded_and_retried(settings):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(503, text="unavailable")
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(
            {"verdict": "benign", "severity": "low", "indicators": [], "summary": "", "recommended_actions": [],
             "tool_requests": []})}}]})

    settings.openai_api_key = "sk-test"
    with TestClient(create_app(settings, transport=httpx.MockTransport(handler))) as client:
        exp = client.post("/api/experiments", json={"models": ["openai:gpt-test"], "defenses": ["baseline"],
                                                    "limit": 3, "variants": ["clean"], "concurrency": 1}).json()
        assert exp["is_mock"] is False
        e = wait_for(client, exp["id"])
        assert e["status"] == "completed_with_errors" and e["failed_runs"] == 2
        client.post(f"/api/experiments/{exp['id']}/resume")
        e2 = wait_for(client, exp["id"])
        assert e2["status"] == "completed" and e2["completed_runs"] == 3 and e2["failed_runs"] == 0
        f = client.get("/api/findings", params={"scope": "real"}).json()
        assert f["experiment"]["id"] == exp["id"]
