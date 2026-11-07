import json
import shutil
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.config import DATA_DIR, Settings  # noqa: E402


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    (d / "datasets" / "imported").mkdir(parents=True)
    (d / "benchmarks").mkdir(parents=True)
    shutil.copy(DATA_DIR / "datasets" / "logjack-v1.jsonl", d / "datasets" / "logjack-v1.jsonl")
    shutil.copy(DATA_DIR / "benchmarks" / "logjack-pi-bench-v1.json", d / "benchmarks" / "logjack-pi-bench-v1.json")
    return d


@pytest.fixture()
def settings(tmp_path: Path, data_dir: Path) -> Settings:
    return Settings(db_path=str(tmp_path / "test.db"), data_dir=str(data_dir), mock_latency_ms=0,
                    serve_frontend=False, openai_api_key="", anthropic_api_key="", ollama_models="",
                    ollama_base_url="http://127.0.0.1:9")


@pytest.fixture(scope="session")
def cases() -> list[dict]:
    with open(DATA_DIR / "datasets" / "logjack-v1.jsonl", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]
