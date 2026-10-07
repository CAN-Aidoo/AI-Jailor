"""The Grafana dashboard must stay valid, laid out sanely, and in sync with what /metrics exports.
With promtool available, every query is also parsed as PromQL and the key ones are evaluated against
sample series."""

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

import pytest
import yaml

DIR = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "grafana"
FILE = DIR / "snapshot-quota.dashboard.json"
PROMTOOL = os.environ.get("PROMTOOL") or shutil.which("promtool")


@pytest.fixture(scope="module")
def dash():
    return json.loads(FILE.read_text())


def exprs(dash):
    return [(p["title"], t["expr"]) for p in dash["panels"] for t in p.get("targets", [])]


def test_structure_ids_and_datasource_variable(dash):
    assert dash["uid"] and dash["title"] and dash["schemaVersion"] >= 36
    ids = [p["id"] for p in dash["panels"]]
    assert len(ids) == len(set(ids))
    variables = {v["name"] for v in dash["templating"]["list"]}
    assert {"datasource", "tenant"} <= variables
    for p in dash["panels"]:
        assert p["datasource"]["uid"] == "${datasource}", p["title"]      # nothing hard-wired
        for t in p["targets"]:
            assert t["datasource"]["uid"] == "${datasource}"
            assert "$tenant" in t["expr"], (p["title"], "ignores the tenant filter")


def test_grid_fits_24_columns_without_overlap(dash):
    cells = set()
    for p in dash["panels"]:
        g = p["gridPos"]
        assert g["x"] >= 0 and g["w"] > 0 and g["x"] + g["w"] <= 24, p["title"]
        for x in range(g["x"], g["x"] + g["w"]):
            for y in range(g["y"], g["y"] + g["h"]):
                assert (x, y) not in cells, f"{p['title']} overlaps at {(x, y)}"
                cells.add((x, y))


def test_only_exported_metrics_are_queried(dash):
    from aijailer.services import quota_metrics
    exported = set(re.findall(r'"(aijailer_snapshot_quota_[a-z_]+)"',
                              pathlib.Path(quota_metrics.__file__).read_text()))
    used = set()
    for _, e in exprs(dash):
        used |= set(re.findall(r"\baijailer_snapshot_quota_[a-z_]+", e))
        assert "aijailer:" not in e, "dashboard must not depend on recording rules being loaded"
    used |= set(re.findall(r"label_values\((\w+),", json.dumps(dash["templating"])))
    assert used and used <= exported, used - exported
    for _, e in exprs(dash):
        for q in re.findall(r'quota="([a-z_]+)"', e):
            assert q in quota_metrics.QUOTAS, q


def test_provisioning_files_parse():
    for f in DIR.rglob("*.yml"):
        assert yaml.safe_load(f.read_text())["apiVersion"] == 1


def _promql(e: str) -> str:
    return e.replace("$tenant", ".+").replace("$__rate_interval", "5m")


@pytest.mark.skipif(not PROMTOOL, reason="promtool not found (set PROMTOOL)")
def test_every_query_parses_as_promql(dash):
    rules = {"groups": [{"name": "dash", "rules": [
        {"record": f"dash:q{i}", "expr": _promql(e)} for i, (_, e) in enumerate(exprs(dash))]}]}
    with tempfile.TemporaryDirectory() as d:
        f = pathlib.Path(d) / "r.yml"
        f.write_text(yaml.safe_dump(rules))
        p = subprocess.run([PROMTOOL, "check", "rules", str(f)], capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr


@pytest.mark.skipif(not PROMTOOL, reason="promtool not found (set PROMTOOL)")
def test_key_queries_return_the_right_answers(dash):
    by_title = dict(exprs(dash))
    series = [
        # t1 snapshots 85/100 (near), t2 100/100 (full), t3 10/100; t1 per-cell 3/10
        ("limit", "t1", "snapshots", "100x120"), ("used", "t1", "snapshots", "85x120"),
        ("limit", "t2", "snapshots", "100x120"), ("used", "t2", "snapshots", "100x120"),
        ("limit", "t3", "snapshots", "100x120"), ("used", "t3", "snapshots", "10x120"),
        ("limit", "t1", "snapshots_per_cell", "10x120"), ("used", "t1", "snapshots_per_cell", "3x120"),
        # t4 grows 1/min on a limit of 3000: (3000-100)/ (1*1440 per day) ~ 2.01 days
        ("limit", "t4", "snapshots", "3000x120"), ("used", "t4", "snapshots", "0+1x120"),
        # t6 grew and has just filled up: deriv > 0 but it is already full, not "0 days from now"
        ("limit", "t6", "snapshots", "60x120"), ("used", "t6", "snapshots", "0+1x60 60x60"),
        # t5 is flat: never projected
        ("limit", "t5", "snapshots", "100x120"), ("used", "t5", "snapshots", "50x120"),
    ]
    inp = [{"series": f'aijailer_snapshot_quota_{k}{{tenant="{t}",quota="{q}"}}', "values": v}
           for k, t, q, v in series]
    inp.append({"series": 'aijailer_snapshot_quota_denied_total{tenant="t2",quota="snapshots"}',
                "values": "0+1x120"})

    def case(title, at, expect):
        return {"expr": _promql(by_title[title]), "eval_time": at, "exp_samples": expect}
    tests = [{"interval": "1m", "input_series": inp, "promql_expr_test": [
        case("Quotas at 100%+", "100m", [{"labels": "{}", "value": 2}]),            # t2 and t6
        case("Quotas at 80-100%", "100m", [{"labels": "{}", "value": 1}]),          # only t1
        case("Tenants exported", "100m", [{"labels": "{}", "value": 6}]),
        case("Refusals (last hour)", "100m", [{"labels": "{}", "value": 60}]),
    ]}]
    with tempfile.TemporaryDirectory() as d:
        f = pathlib.Path(d) / "t.yml"
        f.write_text(yaml.safe_dump({"evaluation_interval": "1m", "tests": tests}))
        p = subprocess.run([PROMTOOL, "test", "rules", str(f)], capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
        # the projection table: only the growing, not-full tenant, ~2 days
        proj = by_title["Projected days until full (growing quotas, < 30 days)"]
        f.write_text(yaml.safe_dump({"evaluation_interval": "1m", "tests": [{
            "interval": "1m", "input_series": inp, "promql_expr_test": [{
                "expr": _promql(proj), "eval_time": "100m",
                "exp_samples": [{"labels": '{quota="snapshots", tenant="t4"}',
                                 "value": (3000 - 100) / (1.0 * 1440)}]}]}]}))
        p = subprocess.run([PROMTOOL, "test", "rules", str(f)], capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
