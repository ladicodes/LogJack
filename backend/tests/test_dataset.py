"""Dataset validation and reproducibility tests."""
import json
from collections import Counter

import pytest

from app.config import DATA_DIR
from app.dataset import generator, store
from app.dataset.benchmark import ATTACK_TYPES, load_benchmark, parse_benchmark
from app.soc.parsers import parse_fields

IPV4_DOC = ("203.0.113.", "198.51.100.", "192.0.2.", "10.")


def test_has_200_cases_balanced(cases):
    assert len(cases) == 200
    assert Counter(c["log_type"] for c in cases) == {"nginx": 50, "ssh": 50, "dns": 50, "ids": 50}
    assert Counter(c["label"] for c in cases) == {"benign": 80, "suspicious": 48, "malicious": 72}
    assert set(c["modified"]["injection"]["attack_type"] for c in cases) == set(ATTACK_TYPES)


def test_case_ids_unique_and_schema_valid(cases):
    assert len({c["case_id"] for c in cases}) == 200
    text = "".join(json.dumps(c) + "\n" for c in cases)
    parsed = store.parse_jsonl(text, "check")
    assert len(parsed) == 200


def test_generation_is_byte_for_byte_reproducible():
    on_disk = (DATA_DIR / "datasets" / "logjack-v1.jsonl").read_text(encoding="utf-8")
    regenerated = generator.to_jsonl(generator.generate(seed=generator.DEFAULT_SEED))
    assert regenerated == on_disk
    manifest = json.loads((DATA_DIR / "datasets" / "logjack-v1.manifest.json").read_text())
    assert manifest["sha256"] == generator.sha256_text(on_disk)
    assert manifest["case_count"] == 200


def test_different_seed_changes_dataset():
    a = generator.to_jsonl(generator.generate(seed=1))
    b = generator.to_jsonl(generator.generate(seed=2))
    assert a != b


def test_injected_text_only_in_modified_variant(cases):
    for c in cases:
        inj = c["modified"]["injection"]["injected_text"]
        assert c["clean"]["raw"] != c["modified"]["raw"]
        assert inj not in c["clean"]["raw"]
        # the clean event is preserved: everything but the injected field matches
        changed = [k for k in c["clean"]["fields"] if c["clean"]["fields"][k] != c["modified"]["fields"].get(k)]
        field = c["modified"]["injection"]["field"]
        expected_key = "user_agent" if field == "user_agent" and c["log_type"] == "ids" else field
        if c["log_type"] == "ids":
            expected_key = "http_user_agent"
        assert changed == [expected_key], (c["case_id"], changed)


def test_injection_fields_cover_required_types(cases):
    fields = Counter(c["modified"]["injection"]["field"] for c in cases)
    assert {"user_agent", "path", "referrer", "username", "query"} <= set(fields)


def test_templates_respect_label_applicability(cases):
    bench = {t.id: t for t in load_benchmark().templates}
    for c in cases:
        t = bench[c["modified"]["injection"]["template_id"]]
        assert c["label"] in t.applies_to_labels


def test_only_documentation_or_private_ips(cases):
    import re
    for c in cases:
        for variant in ("clean", "modified"):
            for ip in re.findall(r"(?<![\d./])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", c[variant]["raw"]):
                if ip.startswith("127."):
                    continue
                assert ip.startswith(IPV4_DOC), (c["case_id"], ip)


def test_expected_indicators_present_in_log(cases):
    from app.eval.scoring import indicator_present
    for c in cases:
        for ind in c["expected_indicators"]:
            assert indicator_present(ind, [c["clean"]["raw"]]), (c["case_id"], ind)
        if c["label"] == "benign":
            assert c["expected_indicators"] == []
        else:
            assert c["expected_indicators"]


def test_dns_queries_are_valid_label_lengths(cases):
    for c in cases:
        if c["log_type"] != "dns":
            continue
        q = c["modified"]["fields"]["query"]
        assert all(1 <= len(label) <= 63 for label in q.split(".")), c["case_id"]


def test_parsers_recover_untrusted_fields(cases):
    for c in cases:
        f = parse_fields(c["log_type"], c["modified"]["raw"])
        if c["log_type"] == "nginx":
            assert f["user_agent"] == c["modified"]["fields"]["user_agent"]
            assert f["path"] == c["modified"]["fields"]["path"]
        elif c["log_type"] == "dns":
            assert f["query"] == c["modified"]["fields"]["query"]
        elif c["log_type"] == "ids":
            assert f["user_agent"] == c["modified"]["fields"]["http_user_agent"]
        elif c["log_type"] == "ssh":
            assert "username" in f


def test_benchmark_validation_rejects_bad_input():
    good = json.loads((DATA_DIR / "benchmarks" / "logjack-pi-bench-v1.json").read_text())
    parse_benchmark(good)
    bad = json.loads(json.dumps(good))
    bad["templates"][0]["attack_type"] = "something_else"
    with pytest.raises(Exception):
        parse_benchmark(bad)
    bad = json.loads(json.dumps(good))
    bad["templates"][0]["text"] = "Unknown {placeholder} here please"
    with pytest.raises(Exception):
        parse_benchmark(bad)
    bad = json.loads(json.dumps(good))
    ua = next(t for t in bad["templates"] if t["attack_type"] == "unauthorized_action")
    ua["objective"]["target_tool"] = "lookup_ip_reputation"  # permitted tool is not a valid target
    with pytest.raises(Exception):
        parse_benchmark(bad)
    bad = json.loads(json.dumps(good))
    bad["templates"].append(dict(bad["templates"][0]))
    with pytest.raises(Exception):
        parse_benchmark(bad)


def test_dataset_import_validation_reports_line_errors(cases):
    lines = [json.dumps(cases[0]), "{not json", json.dumps({**cases[1], "label": "evil"})]
    with pytest.raises(store.DatasetValidationError) as exc:
        store.parse_jsonl("\n".join(lines), "x")
    msg = " ".join(exc.value.errors)
    assert "line 2" in msg and "line 3" in msg
