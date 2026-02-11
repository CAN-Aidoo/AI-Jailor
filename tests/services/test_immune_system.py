"""Tests for the Immune Memory System.

Tests the full pipeline: attack pattern storage → analysis →
constraint generation → propagation.
"""

import pytest

from aijailer.immune.memory import (
    AttackPattern,
    ImmuneMemory,
    ThreatSeverity,
    PatternStatus,
)
from aijailer.immune.analyzer import VulnerabilityAnalyzer
from aijailer.immune.constraint_generator import ConstraintGenerator
from aijailer.immune.propagator import ConstraintPropagator, PropagationEvent
from aijailer.immune.cve_feed import CVEFeed
from aijailer.immune.telemetry import Telemetry, GenerationEvent, GenerationOutcome


# --- Immune Memory Tests ---

class TestImmuneMemory:
    @pytest.mark.asyncio
    async def test_store_and_recall(self):
        mem = ImmuneMemory()
        pattern = AttackPattern(
            pattern_id="test-001",
            cwe_id="CWE-89",
            description="SQL injection via string concat",
            attack_vector="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            severity=ThreatSeverity.CRITICAL,
            detection_signature=r"cursor\.execute\(f['\"]",
            required_constraint="no_string_concat_sql",
            required_component="safe_query_builder",
        )
        stored = await mem.store(pattern)
        assert stored.pattern_id == "test-001"
        recalled = await mem.recall("test-001")
        assert recalled is not None
        assert recalled.cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_find_by_cwe(self):
        mem = ImmuneMemory()
        await mem.store(AttackPattern(
            pattern_id="sqli-1", cwe_id="CWE-89",
            description="SQLi variant 1",
            attack_vector="execute(f'...')",
            severity=ThreatSeverity.CRITICAL,
            detection_signature=r"execute\(f",
            required_constraint=None,
            required_component=None,
        ))
        await mem.store(AttackPattern(
            pattern_id="xss-1", cwe_id="CWE-79",
            description="XSS variant 1",
            attack_vector="innerHTML = user_input",
            severity=ThreatSeverity.HIGH,
            detection_signature=r"innerHTML\s*=",
            required_constraint=None,
            required_component=None,
        ))
        sqli_patterns = await mem.find_by_cwe("CWE-89")
        assert len(sqli_patterns) == 1
        assert sqli_patterns[0].pattern_id == "sqli-1"

    @pytest.mark.asyncio
    async def test_occurrence_counting(self):
        mem = ImmuneMemory()
        p = AttackPattern(
            pattern_id="dup-1", cwe_id="CWE-89",
            description="Dup", attack_vector="x",
            severity=ThreatSeverity.HIGH,
            detection_signature="x",
            required_constraint=None,
            required_component=None,
        )
        await mem.store(p)
        await mem.store(p)
        recalled = await mem.recall("dup-1")
        assert recalled.occurrence_count == 2

    @pytest.mark.asyncio
    async def test_match_code(self):
        mem = ImmuneMemory()
        await mem.store(AttackPattern(
            pattern_id="eval-1", cwe_id="CWE-94",
            description="Eval injection",
            attack_vector="eval(user_input)",
            severity=ThreatSeverity.CRITICAL,
            detection_signature=r"eval\s*\(",
            required_constraint=None,
            required_component=None,
        ))
        matches = await mem.match_code("result = eval(data)")
        assert len(matches) >= 1


# --- Vulnerability Analyzer Tests ---

class TestVulnerabilityAnalyzer:
    @pytest.mark.asyncio
    async def test_detects_sql_injection(self):
        analyzer = VulnerabilityAnalyzer()
        code = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        result = await analyzer.analyze_code(code)
        assert result.total_vulnerabilities > 0
        assert any(p.cwe_id == "CWE-89" for p in result.patterns_found)

    @pytest.mark.asyncio
    async def test_detects_command_injection(self):
        analyzer = VulnerabilityAnalyzer()
        code = '''
import os
os.system(f"cat {filename}")
'''
        result = await analyzer.analyze_code(code)
        assert result.total_vulnerabilities > 0
        assert any(p.cwe_id == "CWE-78" for p in result.patterns_found)

    @pytest.mark.asyncio
    async def test_clean_code_no_findings(self):
        analyzer = VulnerabilityAnalyzer()
        code = '''
def add(a: int, b: int) -> int:
    return a + b
'''
        result = await analyzer.analyze_code(code)
        assert result.total_vulnerabilities == 0

    @pytest.mark.asyncio
    async def test_analyze_report(self):
        analyzer = VulnerabilityAnalyzer()
        report = {
            "vulnerabilities": [{
                "cwe": "CWE-89",
                "description": "SQL injection in login",
                "code_snippet": "cursor.execute(f'SELECT * FROM users')",
                "severity": "critical",
            }]
        }
        patterns = await analyzer.analyze_report(report)
        assert len(patterns) == 1
        assert patterns[0].cwe_id == "CWE-89"


# --- Constraint Generator Tests ---

class TestConstraintGenerator:
    @pytest.mark.asyncio
    async def test_generates_yaml(self):
        gen = ConstraintGenerator()
        pattern = AttackPattern(
            pattern_id="gen-test-1", cwe_id="CWE-89",
            description="SQLi test",
            attack_vector="execute(f'...')",
            severity=ThreatSeverity.CRITICAL,
            detection_signature=r"execute\(f",
            required_constraint="no_string_concat_sql",
            required_component="safe_query_builder",
        )
        constraint = await gen.generate_from_pattern(pattern)
        assert constraint.yaml_content
        assert "CWE-89" in constraint.yaml_content
        assert not constraint.auto_approved  # Critical must need human approval

    @pytest.mark.asyncio
    async def test_low_severity_auto_approved(self):
        gen = ConstraintGenerator()
        pattern = AttackPattern(
            pattern_id="gen-test-2", cwe_id="CWE-20",
            description="Input validation hint",
            attack_vector="x = input()",
            severity=ThreatSeverity.LOW,
            detection_signature=r"input\(\)",
            required_constraint=None,
            required_component=None,
        )
        constraint = await gen.generate_from_pattern(pattern)
        assert constraint.auto_approved

    @pytest.mark.asyncio
    async def test_human_approval_workflow(self):
        gen = ConstraintGenerator()
        pattern = AttackPattern(
            pattern_id="gen-test-3", cwe_id="CWE-79",
            description="XSS", attack_vector="innerHTML=x",
            severity=ThreatSeverity.HIGH,
            detection_signature=r"innerHTML",
            required_constraint=None,
            required_component=None,
        )
        constraint = await gen.generate_from_pattern(pattern)
        assert not constraint.is_active
        approved = await gen.approve(constraint.constraint_id, "admin")
        assert approved.is_active


# --- Propagator Tests ---

class TestConstraintPropagator:
    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self):
        prop = ConstraintPropagator()
        received = []

        async def callback(event):
            received.append(event)

        await prop.subscribe("tenant-1", callback)
        delivered = await prop.broadcast_constraint(
            constraint_id="c-1",
            constraint_yaml="id: c-1\nname: test",
        )
        assert delivered == 1
        assert len(received) == 1
        assert received[0].constraint_id == "c-1"

    @pytest.mark.asyncio
    async def test_multi_tenant_broadcast(self):
        prop = ConstraintPropagator()
        counts = {"t1": 0, "t2": 0}

        async def cb1(event): counts["t1"] += 1
        async def cb2(event): counts["t2"] += 1

        await prop.subscribe("t1", cb1)
        await prop.subscribe("t2", cb2)
        delivered = await prop.broadcast_constraint("c-2", "yaml: test")
        assert delivered == 2
        assert counts["t1"] == 1
        assert counts["t2"] == 1


# --- CVE Feed Tests ---

class TestCVEFeed:
    @pytest.mark.asyncio
    async def test_poll_returns_entries(self):
        feed = CVEFeed()
        entries = await feed.poll()
        assert len(entries) > 0
        assert all(e.cve_id.startswith("CVE-") for e in entries)

    @pytest.mark.asyncio
    async def test_convert_to_patterns(self):
        feed = CVEFeed()
        entries = await feed.poll()
        patterns = await feed.convert_to_patterns(entries)
        assert len(patterns) > 0
        assert all(isinstance(p, AttackPattern) for p in patterns)

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        feed = CVEFeed()
        await feed.poll()
        # Second immediate poll should return empty (rate limited)
        entries = await feed.poll()
        assert len(entries) == 0


# --- Telemetry Tests ---

class TestTelemetry:
    @pytest.mark.asyncio
    async def test_record_and_stats(self):
        tel = Telemetry()
        await tel.record(GenerationEvent(
            event_id="e-1", tenant_id="t-1",
            intent_hash="abc123", action="read",
            outcome=GenerationOutcome.SUCCESS,
            constraints_applied=["no_sql_injection"],
            constraints_violated=[],
            components_used=["safe_query_builder"],
            latency_ms=45.2,
        ))
        stats = await tel.get_stats()
        assert stats["total"] == 1
        assert stats["success"] == 1

    @pytest.mark.asyncio
    async def test_block_rate(self):
        tel = Telemetry()
        for i in range(8):
            await tel.record(GenerationEvent(
                event_id=f"s-{i}", tenant_id="t-1",
                intent_hash="x", action="read",
                outcome=GenerationOutcome.SUCCESS,
                constraints_applied=[], constraints_violated=[],
                components_used=[],
            ))
        for i in range(2):
            await tel.record(GenerationEvent(
                event_id=f"b-{i}", tenant_id="t-1",
                intent_hash="x", action="read",
                outcome=GenerationOutcome.BLOCKED,
                constraints_applied=[], constraints_violated=["bad"],
                components_used=[],
            ))
        stats = await tel.get_stats()
        assert stats["total"] == 10
        assert abs(stats["block_rate"] - 0.2) < 0.01

    @pytest.mark.asyncio
    async def test_component_usage(self):
        tel = Telemetry()
        await tel.record(GenerationEvent(
            event_id="c-1", tenant_id="t-1",
            intent_hash="x", action="read",
            outcome=GenerationOutcome.SUCCESS,
            constraints_applied=[], constraints_violated=[],
            components_used=["safe_query_builder", "input_validator"],
        ))
        usage = await tel.get_component_usage()
        assert "safe_query_builder" in usage
        assert "input_validator" in usage
