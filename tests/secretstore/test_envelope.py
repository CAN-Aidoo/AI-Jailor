import os
import uuid

import pytest

from aijailer.secretstore.envelope import build_aad, open_sealed, rewrap, seal
from aijailer.secretstore.keys import (
    IntegrityError, KeyUnavailableError, LocalKeyProvider, SecretStoreError)
from aijailer.secretstore.validation import (
    ValidationError, validate_host, validate_hosts, validate_name, validate_value)

T = uuid.uuid4()


def prov(*ids, primary=None):
    return LocalKeyProvider({i: os.urandom(32) for i in ids}, primary or ids[0])


def aad(**kw):
    base = dict(tenant_id=T, name="gh", version=1, hosts=["api.github.com"], expires_at=None)
    base.update(kw)
    return build_aad(**base)


def test_roundtrip_and_ciphertext_does_not_contain_plaintext():
    p = prov("k1")
    s = seal(b"ghp_supersecret", aad(), p)
    assert b"ghp_supersecret" not in s.ciphertext + s.wrapped_dek
    assert open_sealed(s, aad(), p) == b"ghp_supersecret"


def test_every_seal_uses_fresh_key_and_nonce():
    p = prov("k1")
    a, b = seal(b"same", aad(), p), seal(b"same", aad(), p)
    assert a.ciphertext != b.ciphertext and a.nonce != b.nonce and a.wrapped_dek != b.wrapped_dek


@pytest.mark.parametrize("change", [
    dict(tenant_id=uuid.uuid4()), dict(name="other"), dict(version=2),
    dict(hosts=["evil.example"]), dict(hosts=["api.github.com", "evil.example"]),
    dict(expires_at=9999999999.0)])
def test_any_bound_metadata_change_fails_closed(change):
    p = prov("k1")
    s = seal(b"v", aad(), p)
    with pytest.raises(IntegrityError):
        open_sealed(s, aad(**change), p)


def test_host_order_is_irrelevant_to_binding():
    p = prov("k1")
    s = seal(b"v", aad(hosts=["a.test", "b.test"]), p)
    assert open_sealed(s, aad(hosts=["b.test", "a.test"]), p) == b"v"


def test_bit_flips_anywhere_are_detected():
    p = prov("k1")
    s = seal(b"value", aad(), p)
    for field in ("ciphertext", "wrapped_dek", "nonce"):
        raw = bytearray(getattr(s, field))
        raw[len(raw) // 2] ^= 1
        bad = type(s)(**{**s.__dict__, field: bytes(raw)})
        with pytest.raises(IntegrityError):
            open_sealed(bad, aad(), p)


def test_wrong_or_missing_master_key():
    s = seal(b"v", aad(), prov("k1"))
    with pytest.raises(KeyUnavailableError):
        open_sealed(s, aad(), prov("k2"))                       # k1 removed
    other = LocalKeyProvider({"k1": os.urandom(32)}, "k1")      # same id, different key material
    with pytest.raises(IntegrityError):
        open_sealed(s, aad(), other)


def test_kek_rotation_rewraps_without_touching_ciphertext():
    k1, k2 = os.urandom(32), os.urandom(32)
    s = seal(b"v", aad(), LocalKeyProvider({"k1": k1}, "k1"))
    both = LocalKeyProvider({"k1": k1, "k2": k2}, "k2")
    assert open_sealed(s, aad(), both) == b"v"                  # old key still readable
    r = rewrap(s, aad(), both)
    assert r.key_id == "k2" and r.ciphertext == s.ciphertext and r.nonce == s.nonce
    only_new = LocalKeyProvider({"k2": k2}, "k2")               # old key retired
    assert open_sealed(r, aad(), only_new) == b"v"
    with pytest.raises(KeyUnavailableError):
        open_sealed(s, aad(), only_new)                         # un-migrated row is detected


def test_provider_config_parsing_and_validation():
    k = LocalKeyProvider.generate_key()
    p = LocalKeyProvider.from_spec(f"a:{k}")
    assert p.primary_id == "a"
    two = f"a:{k},b:{LocalKeyProvider.generate_key()}"
    with pytest.raises(SecretStoreError, match="PRIMARY"):
        LocalKeyProvider.from_spec(two)
    assert LocalKeyProvider.from_spec(two, "b").primary_id == "b"
    for bad in ("nokey", "a:!!!", f"a:{k},a:{k}", "a:c2hvcnQ="):    # no sep, bad b64, dup, short
        with pytest.raises(SecretStoreError):
            LocalKeyProvider.from_spec(bad)
    with pytest.raises(SecretStoreError):
        LocalKeyProvider.from_spec(f"a:{k}", "zzz")
    with pytest.raises(SecretStoreError):
        LocalKeyProvider({}, "a")
    with pytest.raises(SecretStoreError):
        LocalKeyProvider({"bad id!": os.urandom(32)}, "bad id!")


def test_value_validation_blocks_header_injection():
    assert validate_value("ghp_abc123") == b"ghp_abc123"
    for bad in ("", "a\r\nX-Evil: 1", "a\nb", "a\x00b", "a\x7fb", "x" * 20000, 5):
        with pytest.raises(ValidationError):
            validate_value(bad)


def test_name_and_host_validation():
    assert validate_name("github.token-1_a") == "github.token-1_a"
    for bad in ("", "-x", ".x", "a b", "a}}", "a" * 64, "{{secret:x}}"):
        with pytest.raises(ValidationError):
            validate_name(bad)
    assert validate_host(" API.GitHub.com. ") == "api.github.com"
    assert validate_host("*.github.com") == "*.github.com" and validate_host("10.1.2.3")
    for bad in ("*", "*.com", "com", "*.*.com", "a..b", "-a.com", "http://a.com", "a.com/x",
                "::1", "a b.com", "*"):
        with pytest.raises(ValidationError):
            validate_host(bad)
    assert validate_hosts(["B.test", "a.test", "a.test"]) == ["a.test", "b.test"]
    for bad in ([], "a.test", ["a.test"] * 0, [f"h{i}.test" for i in range(21)]):
        with pytest.raises(ValidationError):
            validate_hosts(bad)
