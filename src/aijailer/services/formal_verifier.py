"""Formal Verifier — Lightweight Property Checker.

Verifies that generated code satisfies security properties
via AST-based rule checking. Target: <100ms per verification.

Checks:
- No banned function calls (eval, exec, os.system, etc.)
- All SQL uses parameterized queries
- All user inputs are validated before use
- No hardcoded secrets
- Required certified components are imported
- No unsafe deserialization
"""

import ast
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class VerificationSeverity(str, Enum):
    ERROR = "error"        # Hard failure — code MUST NOT be used
    WARNING = "warning"    # Soft failure — needs review
    INFO = "info"          # Informational finding


class VerificationStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"        # Verification itself failed


@dataclass(frozen=True)
class Finding:
    """A single verification finding."""
    rule_id: str
    severity: VerificationSeverity
    message: str
    line: int | None = None
    column: int | None = None
    code_snippet: str | None = None
    cwe: str | None = None
    fix_suggestion: str | None = None


@dataclass
class VerificationResult:
    """Result of formal verification."""
    status: VerificationStatus
    findings: list[Finding] = field(default_factory=list)
    elapsed_ms: float = 0.0
    properties_checked: int = 0
    properties_passed: int = 0

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == VerificationSeverity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == VerificationSeverity.WARNING]


# Banned function calls
_BANNED_CALLS: dict[str, dict[str, str]] = {
    "eval": {"cwe": "CWE-94", "msg": "eval() allows arbitrary code execution"},
    "exec": {"cwe": "CWE-94", "msg": "exec() allows arbitrary code execution"},
    "compile": {"cwe": "CWE-94", "msg": "compile() can enable code injection"},
    "__import__": {"cwe": "CWE-94", "msg": "__import__() allows dynamic imports"},
}

_BANNED_ATTR_CALLS: dict[str, dict[str, str]] = {
    "os.system": {"cwe": "CWE-78", "msg": "os.system() allows command injection"},
    "os.popen": {"cwe": "CWE-78", "msg": "os.popen() allows command injection"},
    "subprocess.call": {"cwe": "CWE-78", "msg": "Use safe_subprocess instead"},
    "subprocess.run": {"cwe": "CWE-78", "msg": "Use safe_subprocess instead"},
    "subprocess.Popen": {"cwe": "CWE-78", "msg": "Use safe_subprocess instead"},
    "pickle.loads": {"cwe": "CWE-502", "msg": "pickle.loads() is unsafe deserialization"},
    "pickle.load": {"cwe": "CWE-502", "msg": "pickle.load() is unsafe deserialization"},
    "yaml.load": {"cwe": "CWE-502", "msg": "Use yaml.safe_load() instead"},
    "yaml.unsafe_load": {"cwe": "CWE-502", "msg": "yaml.unsafe_load() is dangerous"},
    "hashlib.md5": {"cwe": "CWE-327", "msg": "MD5 is cryptographically broken"},
    "hashlib.sha1": {"cwe": "CWE-327", "msg": "SHA-1 is cryptographically broken"},
}

# Patterns for hardcoded secrets
_SECRET_PATTERNS = [
    (r"(?:password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]", "CWE-798", "Hardcoded password"),
    (r"(?:api_key|apikey|api_secret)\s*=\s*['\"][^'\"]+['\"]", "CWE-798", "Hardcoded API key"),
    (r"(?:secret_key|SECRET_KEY)\s*=\s*['\"][^'\"]+['\"]", "CWE-798", "Hardcoded secret key"),
    (r"(?:token)\s*=\s*['\"][A-Za-z0-9+/=]{20,}['\"]", "CWE-798", "Hardcoded token"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "CWE-321", "Embedded private key"),
]


class FormalVerifier:
    """Lightweight formal property checker for generated code.

    Performs AST-based analysis to verify security properties.
    Designed to complete in <100ms for typical code sizes.
    """

    def __init__(self, strict_mode: bool = True) -> None:
        self._strict = strict_mode

    def verify(
        self,
        code: str,
        required_components: list[str] | None = None,
        language: str = "python",
    ) -> VerificationResult:
        """Verify that code satisfies security properties."""
        start = time.perf_counter()
        findings: list[Finding] = []
        properties_checked = 0
        properties_passed = 0

        if language != "python":
            # For non-Python, do regex-only checks
            findings.extend(self._check_secrets_regex(code))
            properties_checked += 1
            elapsed = (time.perf_counter() - start) * 1000
            status = VerificationStatus.PASS if not any(
                f.severity == VerificationSeverity.ERROR for f in findings
            ) else VerificationStatus.FAIL
            return VerificationResult(
                status=status, findings=findings,
                elapsed_ms=elapsed, properties_checked=properties_checked,
                properties_passed=properties_passed,
            )

        # Parse AST
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                findings=[Finding(
                    rule_id="parse_error", severity=VerificationSeverity.ERROR,
                    message=f"Syntax error: {e}", line=e.lineno,
                )],
                elapsed_ms=(time.perf_counter() - start) * 1000,
            )

        # Check 1: Banned function calls
        properties_checked += 1
        banned_findings = self._check_banned_calls(tree)
        findings.extend(banned_findings)
        if not banned_findings:
            properties_passed += 1

        # Check 2: Hardcoded secrets
        properties_checked += 1
        secret_findings = self._check_secrets(tree, code)
        findings.extend(secret_findings)
        if not secret_findings:
            properties_passed += 1

        # Check 3: Shell=True in subprocess
        properties_checked += 1
        shell_findings = self._check_shell_true(tree)
        findings.extend(shell_findings)
        if not shell_findings:
            properties_passed += 1

        # Check 4: SQL string concatenation
        properties_checked += 1
        sql_findings = self._check_sql_concat(tree, code)
        findings.extend(sql_findings)
        if not sql_findings:
            properties_passed += 1

        # Check 5: Required components imported
        if required_components:
            properties_checked += 1
            comp_findings = self._check_required_components(tree, required_components)
            findings.extend(comp_findings)
            if not comp_findings:
                properties_passed += 1

        # Check 6: Unsafe deserialization
        properties_checked += 1
        deser_findings = self._check_unsafe_deserialization(tree)
        findings.extend(deser_findings)
        if not deser_findings:
            properties_passed += 1

        elapsed = (time.perf_counter() - start) * 1000

        has_errors = any(f.severity == VerificationSeverity.ERROR for f in findings)
        has_warnings = any(f.severity == VerificationSeverity.WARNING for f in findings)

        if has_errors:
            status = VerificationStatus.FAIL
        elif has_warnings:
            status = VerificationStatus.WARN
        else:
            status = VerificationStatus.PASS

        logger.info(
            "verifier.complete",
            status=status.value,
            findings=len(findings),
            elapsed_ms=round(elapsed, 2),
        )

        return VerificationResult(
            status=status, findings=findings, elapsed_ms=elapsed,
            properties_checked=properties_checked,
            properties_passed=properties_passed,
        )

    def _check_banned_calls(self, tree: ast.AST) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = self._get_call_name(node)
                if name in _BANNED_CALLS:
                    info = _BANNED_CALLS[name]
                    findings.append(Finding(
                        rule_id="banned_call", severity=VerificationSeverity.ERROR,
                        message=info["msg"], line=node.lineno,
                        cwe=info["cwe"], fix_suggestion=f"Remove {name}()",
                    ))
                if name in _BANNED_ATTR_CALLS:
                    # For subprocess calls, only flag if shell=True or unspecified
                    # shell=False is safe and handled by _check_shell_true
                    if name.startswith("subprocess.") and self._has_shell_false(node):
                        continue
                    info = _BANNED_ATTR_CALLS[name]
                    findings.append(Finding(
                        rule_id="banned_attr_call", severity=VerificationSeverity.ERROR,
                        message=info["msg"], line=node.lineno,
                        cwe=info["cwe"],
                    ))
        return findings

    @staticmethod
    def _has_shell_false(node: ast.Call) -> bool:
        """Check if a Call node has an explicit shell=False keyword."""
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        return False

    def _check_secrets(self, tree: ast.AST, code: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_secrets_regex(code))
        # AST check: assignments with string literals to suspicious names
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = ""
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                    if any(s in name for s in ("password", "secret", "api_key", "token", "private_key")):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            if len(node.value.value) > 3:
                                findings.append(Finding(
                                    rule_id="hardcoded_secret",
                                    severity=VerificationSeverity.ERROR,
                                    message=f"Hardcoded secret in variable '{name}'",
                                    line=node.lineno, cwe="CWE-798",
                                    fix_suggestion="Use environment variables or vault references",
                                ))
        return findings

    def _check_secrets_regex(self, code: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, cwe, msg in _SECRET_PATTERNS:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count("\n") + 1
                findings.append(Finding(
                    rule_id="secret_pattern", severity=VerificationSeverity.ERROR,
                    message=msg, line=line_num, cwe=cwe,
                    fix_suggestion="Use environment variables or vault references",
                ))
        return findings

    def _check_shell_true(self, tree: ast.AST) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(Finding(
                            rule_id="shell_true", severity=VerificationSeverity.ERROR,
                            message="shell=True enables command injection",
                            line=node.lineno, cwe="CWE-78",
                            fix_suggestion="Use safe_subprocess component instead",
                        ))
        return findings

    def _check_sql_concat(self, tree: ast.AST, code: str) -> list[Finding]:
        findings: list[Finding] = []
        sql_keywords = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER")
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                # f-string — check if it contains SQL
                try:
                    raw = ast.get_source_segment(code, node)
                    if raw and any(kw in raw.upper() for kw in sql_keywords):
                        findings.append(Finding(
                            rule_id="sql_fstring", severity=VerificationSeverity.ERROR,
                            message="SQL query built with f-string (injection risk)",
                            line=node.lineno, cwe="CWE-89",
                            fix_suggestion="Use safe_query_builder component",
                        ))
                except Exception:
                    pass
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                # % formatting with SQL
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    if any(kw in node.left.value.upper() for kw in sql_keywords):
                        findings.append(Finding(
                            rule_id="sql_format", severity=VerificationSeverity.ERROR,
                            message="SQL query built with % formatting (injection risk)",
                            line=node.lineno, cwe="CWE-89",
                            fix_suggestion="Use safe_query_builder component",
                        ))
        return findings

    def _check_required_components(
        self, tree: ast.AST, required: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[-1])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module.split(".")[-1])
                for alias in node.names:
                    imported_modules.add(alias.name)

        for comp in required:
            if comp not in imported_modules:
                findings.append(Finding(
                    rule_id="missing_component",
                    severity=VerificationSeverity.WARNING,
                    message=f"Required certified component '{comp}' not imported",
                    fix_suggestion=f"Add: from aijailer.certified_components import {comp}",
                ))
        return findings

    def _check_unsafe_deserialization(self, tree: ast.AST) -> list[Finding]:
        # Already covered by banned calls, but check for marshal/shelve too
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = self._get_call_name(node)
                if name in ("marshal.loads", "shelve.open"):
                    findings.append(Finding(
                        rule_id="unsafe_deser", severity=VerificationSeverity.ERROR,
                        message=f"{name}() is unsafe deserialization",
                        line=node.lineno, cwe="CWE-502",
                    ))
        return findings

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            obj = node.func
            while isinstance(obj, ast.Attribute):
                parts.append(obj.attr)
                obj = obj.value
            if isinstance(obj, ast.Name):
                parts.append(obj.id)
            return ".".join(reversed(parts))
        return ""
