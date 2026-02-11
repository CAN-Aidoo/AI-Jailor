"""Tests for the Formal Verifier.

Validates AST-based security property checks.
"""

import pytest

from aijailer.services.formal_verifier import (
    FormalVerifier,
    VerificationStatus,
    VerificationSeverity,
)


@pytest.fixture
def verifier():
    return FormalVerifier(strict_mode=True)


class TestBannedCalls:
    def test_detects_eval(self, verifier):
        result = verifier.verify("x = eval(input())")
        assert result.status == VerificationStatus.FAIL
        assert any(f.cwe == "CWE-94" for f in result.errors)

    def test_detects_exec(self, verifier):
        result = verifier.verify("exec('import os')")
        assert result.status == VerificationStatus.FAIL

    def test_detects_os_system(self, verifier):
        result = verifier.verify("import os\nos.system('ls')")
        assert result.status == VerificationStatus.FAIL
        assert any(f.cwe == "CWE-78" for f in result.errors)

    def test_detects_pickle_loads(self, verifier):
        result = verifier.verify("import pickle\npickle.loads(data)")
        assert result.status == VerificationStatus.FAIL
        assert any(f.cwe == "CWE-502" for f in result.errors)

    def test_allows_safe_code(self, verifier):
        result = verifier.verify("def add(a, b):\n    return a + b")
        assert result.status == VerificationStatus.PASS


class TestHardcodedSecrets:
    def test_detects_hardcoded_password(self, verifier):
        result = verifier.verify('password = "super_secret_123"')
        assert result.status == VerificationStatus.FAIL
        assert any(f.cwe == "CWE-798" for f in result.findings)

    def test_detects_api_key(self, verifier):
        result = verifier.verify('api_key = "sk-1234567890abcdef1234567890"')
        assert result.status == VerificationStatus.FAIL

    def test_detects_private_key(self, verifier):
        code = 'key = """-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----"""'
        result = verifier.verify(code)
        assert result.status == VerificationStatus.FAIL


class TestShellTrue:
    def test_detects_shell_true(self, verifier):
        result = verifier.verify("import subprocess\nsubprocess.run('ls', shell=True)")
        assert result.status == VerificationStatus.FAIL
        assert any(f.rule_id == "shell_true" for f in result.errors)

    def test_allows_shell_false(self, verifier):
        result = verifier.verify("import subprocess\nsubprocess.run(['ls'], shell=False)")
        assert result.status == VerificationStatus.PASS


class TestSqlConcat:
    def test_detects_fstring_sql(self, verifier):
        code = 'query = f"SELECT * FROM users WHERE id = {uid}"'
        result = verifier.verify(code)
        assert any(f.cwe == "CWE-89" for f in result.findings)

    def test_detects_percent_format_sql(self, verifier):
        code = 'query = "SELECT * FROM users WHERE id = %s" % user_id'
        result = verifier.verify(code)
        assert any(f.cwe == "CWE-89" for f in result.findings)


class TestRequiredComponents:
    def test_warns_missing_component(self, verifier):
        code = "def handler():\n    pass"
        result = verifier.verify(code, required_components=["safe_query_builder"])
        assert any(f.rule_id == "missing_component" for f in result.warnings)

    def test_passes_with_imported_component(self, verifier):
        code = "from aijailer.certified_components import safe_query_builder\ndef handler(): pass"
        result = verifier.verify(code, required_components=["safe_query_builder"])
        assert not any(f.rule_id == "missing_component" for f in result.findings)


class TestPerformance:
    def test_completes_under_100ms(self, verifier):
        """Verifier should complete in <100ms for typical code."""
        code = "\n".join([f"x_{i} = {i}" for i in range(200)])
        result = verifier.verify(code)
        assert result.elapsed_ms < 100

    def test_handles_syntax_error(self, verifier):
        result = verifier.verify("def broken(:\n    pass")
        assert result.status == VerificationStatus.ERROR
