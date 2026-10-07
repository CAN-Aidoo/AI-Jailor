"""Tests for Certified Components.

Validates that each certified component raises SecurityViolation
on misuse and enforces safe defaults.
"""

import pytest

from aijailer.core.exceptions import AiJailerError


# --- Session Manager Tests ---

class TestSessionManager:
    def test_httponly_cannot_be_disabled(self):
        from aijailer.certified_components.auth.session_manager import (
            SessionConfig, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            SessionConfig(httponly=False)

    def test_secure_cannot_be_disabled(self):
        from aijailer.certified_components.auth.session_manager import (
            SessionConfig, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            SessionConfig(secure=False)

    def test_samesite_rejects_none(self):
        from aijailer.certified_components.auth.session_manager import (
            SessionConfig, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            SessionConfig(samesite="None")

    @pytest.mark.asyncio
    async def test_create_session(self):
        from aijailer.certified_components.auth.session_manager import (
            SessionManager, SessionConfig,
        )
        mgr = SessionManager()
        session = await mgr.create(user_id="user-1")
        assert session.user_id == "user-1"
        assert session.csrf_token
        assert not session.is_expired

    @pytest.mark.asyncio
    async def test_session_fixation_prevention(self):
        from aijailer.certified_components.auth.session_manager import SessionManager
        mgr = SessionManager()
        s1 = await mgr.create(user_id="user-1")
        s2 = await mgr.create(user_id="user-1")
        # Old session should be invalidated
        assert await mgr.validate(s1.session_id) is None
        assert await mgr.validate(s2.session_id) is not None


# --- JWT Handler Tests ---

class TestJWTHandler:
    def test_rejects_weak_secret(self):
        from aijailer.certified_components.auth.jwt_handler import (
            JWTHandler, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            JWTHandler(secret_key="short")

    def test_rejects_none_algorithm(self):
        from aijailer.certified_components.auth.jwt_handler import (
            JWTConfig, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            JWTConfig(algorithm="none")

    def test_create_and_verify_token(self):
        from aijailer.certified_components.auth.jwt_handler import JWTHandler
        handler = JWTHandler(secret_key="a" * 32)
        pair = handler.create_token_pair(user_id="user-1")
        claims = handler.verify_token(pair.access_token)
        assert claims.sub == "user-1"
        assert claims.token_type == "access"

    def test_refresh_token_single_use(self):
        from aijailer.certified_components.auth.jwt_handler import (
            JWTHandler, SecurityViolation,
        )
        handler = JWTHandler(secret_key="b" * 32)
        pair = handler.create_token_pair(user_id="user-2")
        handler.refresh(pair.refresh_token)
        with pytest.raises(SecurityViolation, match="already used"):
            handler.refresh(pair.refresh_token)


# --- Safe Query Builder Tests ---

class TestSafeQueryBuilder:
    def test_select_query(self):
        from aijailer.certified_components.data_access.safe_query_builder import (
            SafeQueryBuilder, WhereClause,
        )
        builder = SafeQueryBuilder()
        where = WhereClause().eq("id", 42)
        query = builder.select("users", columns=["id", "name"], where=where)
        assert "SELECT" in query.sql
        assert "$1" in query.sql
        assert 42 in query.params

    def test_rejects_sql_identifier_injection(self):
        from aijailer.certified_components.data_access.safe_query_builder import (
            WhereClause, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            WhereClause().eq("id; DROP TABLE users", 1)

    @pytest.mark.asyncio
    async def test_update_requires_where(self):
        from aijailer.certified_components.data_access.safe_query_builder import (
            SafeQueryBuilder, SecurityViolation,
        )
        builder = SafeQueryBuilder()
        with pytest.raises(SecurityViolation, match="WHERE"):
            await builder.update("users", {"name": "test"})

    @pytest.mark.asyncio
    async def test_delete_requires_where(self):
        from aijailer.certified_components.data_access.safe_query_builder import (
            SafeQueryBuilder, WhereClause, SecurityViolation,
        )
        builder = SafeQueryBuilder()
        with pytest.raises(SecurityViolation, match="WHERE"):
            await builder.delete("users", WhereClause())


# --- Input Validator Tests ---

class TestInputValidator:
    def test_email_validation(self):
        from aijailer.certified_components.data_access.input_validator import (
            InputValidator, ValidationRule, FieldType,
        )
        validator = InputValidator()
        result = validator.validate(
            {"email": "user@example.com"},
            [ValidationRule(field_name="email", field_type=FieldType.EMAIL)],
        )
        assert result.valid

    def test_rejects_xss_in_input(self):
        from aijailer.certified_components.data_access.input_validator import (
            InputValidator, ValidationRule, FieldType,
        )
        validator = InputValidator()
        result = validator.validate(
            {"name": '<script>alert("xss")</script>'},
            [ValidationRule(field_name="name", field_type=FieldType.NAME)],
        )
        assert not result.valid

    def test_strips_null_bytes(self):
        from aijailer.certified_components.data_access.input_validator import (
            InputValidator, ValidationRule, FieldType,
        )
        validator = InputValidator()
        result = validator.validate(
            {"name": "hello\x00world"},
            [ValidationRule(field_name="name", field_type=FieldType.NAME)],
        )
        assert result.valid
        assert "\x00" not in result.sanitized_data["name"]


# --- Output Encoder Tests ---

class TestOutputEncoder:
    def test_html_encoding(self):
        from aijailer.certified_components.data_access.output_encoder import (
            OutputEncoder, OutputContext,
        )
        encoder = OutputEncoder()
        result = encoder.encode("<script>alert('xss')</script>", OutputContext.HTML_CONTENT)
        assert "<script>" not in result
        assert "&lt;" in result

    def test_url_encoding(self):
        from aijailer.certified_components.data_access.output_encoder import (
            OutputEncoder, OutputContext,
        )
        encoder = OutputEncoder()
        result = encoder.encode("hello world&foo=bar", OutputContext.URL)
        assert " " not in result
        assert "&" not in result

    def test_log_redacts_email(self):
        from aijailer.certified_components.data_access.output_encoder import (
            OutputEncoder, OutputContext,
        )
        encoder = OutputEncoder()
        result = encoder.encode("user email is test@example.com", OutputContext.LOG)
        assert "test@example.com" not in result
        assert "EMAIL_REDACTED" in result

    def test_css_blocks_url_function(self):
        from aijailer.certified_components.data_access.output_encoder import (
            OutputEncoder, OutputContext, SecurityViolation,
        )
        encoder = OutputEncoder()
        with pytest.raises(SecurityViolation):
            encoder.encode("url(javascript:alert(1))", OutputContext.CSS)


# --- Encryption Tests ---

class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        from aijailer.certified_components.crypto.encryption import (
            Encryption, VaultKeyReference,
        )
        enc = Encryption(VaultKeyReference(vault_path="test/key"))
        payload = enc.encrypt(b"hello world")
        decrypted = enc.decrypt(payload)
        assert decrypted == b"hello world"

    def test_different_nonces(self):
        from aijailer.certified_components.crypto.encryption import (
            Encryption, VaultKeyReference,
        )
        enc = Encryption(VaultKeyReference(vault_path="test/key"))
        p1 = enc.encrypt(b"same data")
        p2 = enc.encrypt(b"same data")
        assert p1.nonce != p2.nonce


# --- Hashing Tests ---

class TestHashing:
    @pytest.mark.asyncio
    async def test_hash_and_verify(self):
        from aijailer.certified_components.crypto.hashing import Hashing
        h = Hashing()
        hashed = await h.hash_password("securePassword123!")
        assert await h.verify_password("securePassword123!", hashed)
        assert not await h.verify_password("wrong_password!!", hashed)

    def test_rejects_short_password(self):
        from aijailer.certified_components.crypto.hashing import (
            Hashing, SecurityViolation,
        )
        h = Hashing()
        with pytest.raises(SecurityViolation):
            import asyncio
            asyncio.run(h.hash_password("short"))

    def test_rejects_weak_config(self):
        from aijailer.certified_components.crypto.hashing import (
            HashConfig, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            HashConfig(time_cost=1)


# --- HTTP Client Tests ---

class TestSecureHttpClient:
    def test_blocks_http(self):
        from aijailer.certified_components.network.http_client import (
            SecureHttpClient, SecurityViolation,
        )
        client = SecureHttpClient()
        with pytest.raises(SecurityViolation, match="HTTPS"):
            client.validate_url("http://example.com")

    def test_blocks_private_ip(self):
        from aijailer.certified_components.network.http_client import (
            SecureHttpClient, SecurityViolation,
        )
        client = SecureHttpClient()
        with pytest.raises(SecurityViolation, match="SSRF"):
            client.validate_url("https://127.0.0.1/api")

    def test_ssl_cannot_be_disabled(self):
        from aijailer.certified_components.network.http_client import (
            HttpClientConfig, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            HttpClientConfig(verify_ssl=False)


# --- Safe File IO Tests ---

class TestSafeFileIO:
    def test_blocks_path_traversal(self):
        import tempfile
        from aijailer.certified_components.primitives.safe_file_io import (
            SafeFileIO, FileIOConfig, SecurityViolation,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            fio = SafeFileIO(FileIOConfig(allowed_directories=[tmpdir]))
            with pytest.raises(SecurityViolation):
                fio.validate_path(f"{tmpdir}/../etc/passwd")

    def test_requires_allowed_dirs(self):
        from aijailer.certified_components.primitives.safe_file_io import (
            FileIOConfig, SecurityViolation,
        )
        with pytest.raises(SecurityViolation):
            FileIOConfig(allowed_directories=[])


# --- Safe Subprocess Tests ---

class TestSafeSubprocess:
    @pytest.mark.asyncio
    async def test_rejects_unlisted_command(self):
        from aijailer.certified_components.primitives.safe_subprocess import (
            SafeSubprocess, SecurityViolation,
        )
        sp = SafeSubprocess()
        with pytest.raises(SecurityViolation, match="allowlist"):
            await sp.execute("rm", args=["-rf", "/"])

    @pytest.mark.asyncio
    async def test_blocks_shell_metacharacters(self):
        from aijailer.certified_components.primitives.safe_subprocess import (
            SafeSubprocess, CommandPolicy, SecurityViolation,
        )
        sp = SafeSubprocess([CommandPolicy(command="echo")])
        with pytest.raises(SecurityViolation, match="metacharacter"):
            await sp.execute("echo", args=["hello; rm -rf /"])
