"""Immune Analyzer — Vulnerability Classification.

Extracts vulnerability class (CWE), attack vector pattern,
and required constraint from vulnerability reports.
Converts raw reports into structured AttackPatterns for immune memory.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Any

import structlog

from aijailer.immune.memory import AttackPattern, ThreatSeverity

logger = structlog.get_logger(__name__)


# CWE detection rules: regex patterns → CWE mapping
_CWE_DETECTION_RULES: list[dict[str, Any]] = [
    {
        "cwe": "CWE-89",
        "name": "SQL Injection",
        "patterns": [
            r"(?:execute|cursor\.execute)\s*\(\s*[\"'].*%[sd]",
            r"(?:execute|cursor\.execute)\s*\(\s*f[\"']",
            r"\.format\s*\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)",
            r"[\"']\s*\+\s*\w+\s*\+\s*[\"'].*(?:SELECT|INSERT|UPDATE|DELETE)",
        ],
        "severity": ThreatSeverity.CRITICAL,
        "constraint": "no_string_concat_sql",
        "component": "safe_query_builder",
    },
    {
        "cwe": "CWE-79",
        "name": "Cross-Site Scripting",
        "patterns": [
            r"innerHTML\s*=",
            r"document\.write\s*\(",
            r"\.outerHTML\s*=",
            r"v-html\s*=",
            r"\{\{.*\|.*safe\s*\}\}",
        ],
        "severity": ThreatSeverity.HIGH,
        "constraint": "require_output_encoding",
        "component": "output_encoder",
    },
    {
        "cwe": "CWE-78",
        "name": "OS Command Injection",
        "patterns": [
            r"os\.system\s*\(",
            r"subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True",
            r"os\.popen\s*\(",
            r"exec\s*\(",
            r"eval\s*\(",
        ],
        "severity": ThreatSeverity.CRITICAL,
        "constraint": "no_shell_execution",
        "component": "safe_subprocess",
    },
    {
        "cwe": "CWE-22",
        "name": "Path Traversal",
        "patterns": [
            r"open\s*\(.*\+.*\)",
            r"os\.path\.join\s*\(.*request\.",
            r"send_file\s*\(.*\+",
            r"pathlib\.Path\s*\(.*user",
        ],
        "severity": ThreatSeverity.HIGH,
        "constraint": "require_path_validation",
        "component": "safe_file_io",
    },
    {
        "cwe": "CWE-327",
        "name": "Broken Crypto",
        "patterns": [
            r"hashlib\.md5\s*\(",
            r"hashlib\.sha1\s*\(",
            r"DES\s*\.",
            r"RC4",
            r"AES\.MODE_ECB",
        ],
        "severity": ThreatSeverity.HIGH,
        "constraint": "require_approved_crypto",
        "component": "encryption",
    },
    {
        "cwe": "CWE-918",
        "name": "SSRF",
        "patterns": [
            r"requests\.get\s*\(.*user",
            r"urllib\.request\.urlopen\s*\(.*\+",
            r"httpx\.get\s*\(.*input",
            r"fetch\s*\(.*req\.",
        ],
        "severity": ThreatSeverity.HIGH,
        "constraint": "require_url_validation",
        "component": "http_client",
    },
    {
        "cwe": "CWE-384",
        "name": "Session Fixation",
        "patterns": [
            r"session\[.*\]\s*=.*request\.",
            r"session_id\s*=\s*request\.",
            r"set_cookie.*session.*=.*request\.",
        ],
        "severity": ThreatSeverity.HIGH,
        "constraint": "require_session_regeneration",
        "component": "session_manager",
    },
    {
        "cwe": "CWE-916",
        "name": "Weak Password Hashing",
        "patterns": [
            r"hashlib\.\w+\(.*password",
            r"bcrypt.*rounds\s*=\s*[1-9]\b",
            r"md5\(.*pass",
            r"sha256\(.*password",
        ],
        "severity": ThreatSeverity.HIGH,
        "constraint": "require_argon2id",
        "component": "hashing",
    },
]


@dataclass
class AnalysisResult:
    """Result of analyzing a vulnerability report."""

    patterns_found: list[AttackPattern]
    total_vulnerabilities: int
    severity_summary: dict[str, int]
    recommendations: list[str]


class VulnerabilityAnalyzer:
    """Analyzes code or vulnerability reports to extract attack patterns.

    Maps vulnerabilities to:
    1. CWE classifications
    2. Detection signatures (regex patterns)
    3. Required constraints to prevent them
    4. Certified components that address them
    """

    def __init__(self, custom_rules: list[dict[str, Any]] | None = None) -> None:
        self._rules = list(_CWE_DETECTION_RULES)
        if custom_rules:
            self._rules.extend(custom_rules)

    async def analyze_code(self, code: str, source: str = "scan") -> AnalysisResult:
        """Analyze code for vulnerability patterns.

        Scans the code against all CWE detection rules and returns
        structured AttackPatterns for storage in immune memory.
        """
        patterns_found: list[AttackPattern] = []
        severity_counts: dict[str, int] = {}
        recommendations: list[str] = []

        for rule in self._rules:
            for pattern_str in rule["patterns"]:
                try:
                    matches = list(re.finditer(pattern_str, code, re.MULTILINE | re.IGNORECASE))
                    if matches:
                        # Create an attack pattern for this finding
                        attack_pattern = AttackPattern(
                            pattern_id=self._generate_pattern_id(rule["cwe"], pattern_str, code),
                            cwe_id=rule["cwe"],
                            description=f"{rule['name']} vulnerability detected",
                            attack_vector=self._extract_context(code, matches[0]),
                            severity=rule["severity"],
                            detection_signature=pattern_str,
                            required_constraint=rule.get("constraint"),
                            required_component=rule.get("component"),
                            occurrence_count=len(matches),
                            source=source,
                        )
                        patterns_found.append(attack_pattern)

                        sev = rule["severity"].value
                        severity_counts[sev] = severity_counts.get(sev, 0) + len(matches)

                        rec = (
                            f"Use certified component '{rule.get('component', 'N/A')}' "
                            f"to prevent {rule['name']} ({rule['cwe']})"
                        )
                        if rec not in recommendations:
                            recommendations.append(rec)

                except re.error:
                    logger.warning("analyzer.invalid_pattern", pattern=pattern_str)

        logger.info(
            "analyzer.scan_complete",
            vulnerabilities=len(patterns_found),
            source=source,
        )

        return AnalysisResult(
            patterns_found=patterns_found,
            total_vulnerabilities=len(patterns_found),
            severity_summary=severity_counts,
            recommendations=recommendations,
        )

    async def analyze_report(
        self,
        report: dict[str, Any],
    ) -> list[AttackPattern]:
        """Analyze a structured vulnerability report.

        Expected format:
        {
            "vulnerabilities": [
                {
                    "cwe": "CWE-89",
                    "description": "SQL injection in login form",
                    "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
                    "severity": "critical",
                    "file": "auth.py",
                    "line": 42,
                }
            ]
        }
        """
        patterns: list[AttackPattern] = []

        for vuln in report.get("vulnerabilities", []):
            cwe = vuln.get("cwe", "CWE-unknown")
            severity = self._parse_severity(vuln.get("severity", "medium"))

            # Find matching rule for the CWE
            rule = self._find_rule_for_cwe(cwe)
            constraint = rule.get("constraint") if rule else None
            component = rule.get("component") if rule else None

            # Build detection signature from code snippet
            snippet = vuln.get("code_snippet", "")
            signature = self._build_signature(snippet) if snippet else cwe

            pattern = AttackPattern(
                pattern_id=self._generate_pattern_id(
                    cwe, signature, vuln.get("description", "")
                ),
                cwe_id=cwe,
                description=vuln.get("description", f"Vulnerability: {cwe}"),
                attack_vector=snippet,
                severity=severity,
                detection_signature=signature,
                required_constraint=constraint,
                required_component=component,
                source="report",
                metadata={
                    "file": vuln.get("file"),
                    "line": vuln.get("line"),
                },
            )
            patterns.append(pattern)

        return patterns

    def _find_rule_for_cwe(self, cwe_id: str) -> dict[str, Any] | None:
        """Find the detection rule for a CWE."""
        for rule in self._rules:
            if rule["cwe"] == cwe_id:
                return rule
        return None

    @staticmethod
    def _extract_context(code: str, match: re.Match, context_lines: int = 2) -> str:
        """Extract surrounding context around a regex match."""
        start = max(0, code.rfind("\n", 0, match.start()) + 1)
        # Look back further for more context
        for _ in range(context_lines):
            prev = code.rfind("\n", 0, max(0, start - 1))
            if prev >= 0:
                start = prev + 1
            else:
                start = 0
                break

        end = code.find("\n", match.end())
        if end < 0:
            end = len(code)
        # Look forward for more context
        for _ in range(context_lines):
            next_end = code.find("\n", end + 1)
            if next_end >= 0:
                end = next_end
            else:
                end = len(code)
                break

        return code[start:end].strip()

    @staticmethod
    def _build_signature(code_snippet: str) -> str:
        """Build a detection regex from a code snippet.

        Generalizes specific values to create a broader pattern.
        """
        # Escape regex special chars
        pattern = re.escape(code_snippet)
        # Generalize variable names
        pattern = re.sub(r"\\\w+", r"\\w+", pattern)
        # Generalize string contents
        pattern = re.sub(r"'[^']*'", r"'[^']*'", pattern)
        pattern = re.sub(r'"[^"]*"', r'"[^"]*"', pattern)
        return pattern

    @staticmethod
    def _parse_severity(severity_str: str) -> ThreatSeverity:
        """Parse a severity string to enum."""
        mapping = {
            "critical": ThreatSeverity.CRITICAL,
            "high": ThreatSeverity.HIGH,
            "medium": ThreatSeverity.MEDIUM,
            "low": ThreatSeverity.LOW,
            "info": ThreatSeverity.INFO,
            "informational": ThreatSeverity.INFO,
        }
        return mapping.get(severity_str.lower(), ThreatSeverity.MEDIUM)

    @staticmethod
    def _generate_pattern_id(cwe: str, pattern: str, context: str) -> str:
        """Generate a deterministic pattern ID."""
        content = f"{cwe}:{pattern}:{context}"
        return f"pat-{hashlib.sha256(content.encode()).hexdigest()[:12]}"
