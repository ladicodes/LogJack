"""Loading and validation of fixed, reviewable prompt-injection benchmark files.

LogJack deliberately has no payload generation, mutation, or optimisation code. A
benchmark is a static JSON document reviewed by a human; this module only validates its
structure and renders the two documented placeholders ({src_ip}, {target_indicator}).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.config import DATA_DIR
from app.soc.tools import KNOWN_TOOLS, ALLOWED_TOOLS

ATTACK_TYPES = (
    "verdict_manipulation",
    "indicator_omission",
    "false_positive",
    "unauthorized_action",
    "prompt_disclosure",
)
LABELS = ("benign", "suspicious", "malicious")
ALLOWED_PLACEHOLDERS = {"{src_ip}", "{target_indicator}"}
MAX_TEMPLATE_CHARS = 300

DEFAULT_BENCHMARK_PATH = DATA_DIR / "benchmarks" / "logjack-pi-bench-v1.json"


class BenchmarkTemplate(BaseModel):
    id: str = Field(pattern=r"^[A-Z]{2}-\d{2}$")
    attack_type: str
    applies_to_labels: list[str]
    objective: dict[str, str]
    text: str = Field(min_length=10, max_length=MAX_TEMPLATE_CHARS)

    @field_validator("attack_type")
    @classmethod
    def _attack_type(cls, v: str) -> str:
        if v not in ATTACK_TYPES:
            raise ValueError(f"attack_type must be one of {ATTACK_TYPES}")
        return v

    @field_validator("applies_to_labels")
    @classmethod
    def _labels(cls, v: list[str]) -> list[str]:
        if not v or any(label not in LABELS for label in v):
            raise ValueError(f"applies_to_labels must be a non-empty subset of {LABELS}")
        return v

    @field_validator("text")
    @classmethod
    def _placeholders(cls, v: str) -> str:
        found = set(re.findall(r"\{[a-z_]+\}", v))
        unknown = found - ALLOWED_PLACEHOLDERS
        if unknown:
            raise ValueError(f"unknown placeholders {sorted(unknown)}")
        return v

    @model_validator(mode="after")
    def _objective(self) -> "BenchmarkTemplate":
        o = self.objective
        if self.attack_type in ("verdict_manipulation", "false_positive"):
            if o.get("target_verdict") not in LABELS:
                raise ValueError("objective.target_verdict must be a valid label")
        elif self.attack_type == "indicator_omission":
            if "omit_indicator" not in o:
                raise ValueError("objective.omit_indicator is required")
        elif self.attack_type == "unauthorized_action":
            tool = o.get("target_tool")
            if tool not in KNOWN_TOOLS or tool in ALLOWED_TOOLS:
                raise ValueError("objective.target_tool must be a known, non-permitted simulated tool")
        return self


class Benchmark(BaseModel):
    benchmark_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    version: str
    description: str = ""
    placeholders: dict[str, str] = {}
    templates: list[BenchmarkTemplate] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def _unique(self) -> "Benchmark":
        ids = [t.id for t in self.templates]
        if len(ids) != len(set(ids)):
            raise ValueError("template ids must be unique")
        return self

    def by_type(self) -> dict[str, list[BenchmarkTemplate]]:
        out: dict[str, list[BenchmarkTemplate]] = {}
        for t in self.templates:
            out.setdefault(t.attack_type, []).append(t)
        return out


def load_benchmark(path: str | Path = DEFAULT_BENCHMARK_PATH) -> Benchmark:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_benchmark(json.load(fh))


def parse_benchmark(data: Any) -> Benchmark:
    return Benchmark.model_validate(data)


def render(text: str, src_ip: str, target_indicator: str) -> str:
    return text.replace("{src_ip}", src_ip).replace("{target_indicator}", target_indicator)
