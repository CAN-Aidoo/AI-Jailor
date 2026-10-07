"""The alert rules must stay in sync with what /metrics really exports, and (when promtool is
available) pass `promtool check rules` and the rule unit tests.

promtool: put it on PATH or set PROMTOOL=/path/to/promtool (https://prometheus.io/download/)."""

import os
import pathlib
import re
import shutil
import subprocess

import pytest
import yaml

DIR = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "prometheus"
RULES = DIR / "snapshot-quota.rules.yml"
PROMTOOL = os.environ.get("PROMTOOL") or shutil.which("promtool")


def _rules():
    return [r for g in yaml.safe_load(RULES.read_text())["groups"] for r in g["rules"]]


def test_every_metric_the_rules_use_is_exported_by_the_service():
    from aijailer.services import quota_metrics
    src = pathlib.Path(quota_metrics.__file__).read_text()
    exported = set(re.findall(r'"(aijailer_snapshot_quota_[a-z_]+)"', src))
    used = set()
    for r in _rules():
        used |= set(re.findall(r"\baijailer_snapshot_quota_[a-z_]+", r["expr"]))
    assert used and used <= exported, used - exported


def test_quota_label_values_in_tests_are_real_quota_names():
    from aijailer.services.quota_metrics import QUOTAS
    text = (DIR / "snapshot-quota.rules.test.yml").read_text()
    for q in set(re.findall(r'quota="([a-z_]+)"', text)):
        assert q in QUOTAS, q


def test_every_alert_has_severity_summary_and_description():
    alerts = [r for r in _rules() if "alert" in r]
    assert {a["alert"] for a in alerts} >= {"SnapshotQuotaNearLimit", "SnapshotQuotaExhausted",
                                            "SnapshotQuotaDenials", "SnapshotQuotaMetricsMissing"}
    for a in alerts:
        assert a["labels"]["severity"] in ("warning", "critical")
        assert a["annotations"]["summary"] and a["annotations"]["description"]


@pytest.mark.skipif(not PROMTOOL, reason="promtool not found (set PROMTOOL)")
def test_promtool_check_and_unit_tests_pass():
    for args in (["check", "rules", str(RULES)],
                 ["test", "rules", "snapshot-quota.rules.test.yml"]):
        p = subprocess.run([PROMTOOL, *args], cwd=DIR, capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stdout + p.stderr
