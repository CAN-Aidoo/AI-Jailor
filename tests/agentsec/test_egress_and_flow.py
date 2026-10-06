import pytest

from aijailer.agentsec.egress import EgressBroker, EgressRequest, EgressRule, SecretBinding
from aijailer.agentsec.flow import Label, Labeled, Source, combine_all


def broker(resolver=None, **kw):
    return EgressBroker(
        rules=[EgressRule("api.github.com"), EgressRule("*.pypi.org")],
        secrets=[SecretBinding("github", "ghp_REAL", ("api.github.com",))],
        resolver=resolver or (lambda h: ["140.82.112.5"]),
        **kw,
    )


def test_allowlisted_request_passes_and_pins_ip():
    d = broker().evaluate(EgressRequest("GET", "api.github.com"))
    assert d.allowed and d.pinned_ip == "140.82.112.5"


def test_default_deny():
    assert not broker().evaluate(EgressRequest("GET", "evil.example")).allowed


def test_wildcard_does_not_match_apex_or_lookalike():
    b = broker()
    assert b.evaluate(EgressRequest("GET", "files.pypi.org")).allowed
    assert not b.evaluate(EgressRequest("GET", "pypi.org")).allowed
    assert not b.evaluate(EgressRequest("GET", "evilpypi.org")).allowed


def test_port_and_method_enforced():
    b = broker()
    assert not b.evaluate(EgressRequest("GET", "api.github.com", port=22)).allowed


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1"])
def test_ssrf_private_resolution_blocked(ip):
    d = broker(resolver=lambda h: [ip]).evaluate(EgressRequest("GET", "api.github.com"))
    assert not d.allowed and "SSRF" in d.reason


def test_mixed_dns_answer_blocked_as_rebinding():
    d = broker(resolver=lambda h: ["140.82.112.5", "10.0.0.1"]).evaluate(
        EgressRequest("GET", "api.github.com"))
    assert not d.allowed


def test_metadata_hostname_blocked_even_if_allowlisted():
    b = EgressBroker([EgressRule("metadata.google.internal")], resolver=lambda h: ["8.8.8.8"])
    assert not b.evaluate(EgressRequest("GET", "metadata.google.internal")).allowed


def test_secret_injected_only_for_bound_host_and_redacted_in_audit():
    d = broker().evaluate(EgressRequest(
        "GET", "api.github.com", headers={"Authorization": "Bearer {{secret:github}}"}))
    assert d.allowed and d.headers["Authorization"] == "Bearer ghp_REAL"
    assert "ghp_REAL" not in str(d.audit) and d.audit["secrets_used"] == ["github"]


def test_secret_not_sent_to_other_allowed_host():
    d = broker().evaluate(EgressRequest(
        "GET", "files.pypi.org", headers={"Authorization": "{{secret:github}}"}))
    assert not d.allowed and "not bound" in d.reason


def test_unknown_secret_and_body_placeholder_rejected():
    b = broker()
    assert not b.evaluate(EgressRequest("GET", "api.github.com",
                                        headers={"X": "{{secret:nope}}"})).allowed
    assert not b.evaluate(EgressRequest("POST", "api.github.com",
                                        body="{{secret:github}}")).allowed


def test_flow_label_blocks_exfiltration_to_wrong_host():
    secret = Labeled.secret("customer-record", readers={"api.github.com"})
    ok = broker().evaluate(EgressRequest("POST", "api.github.com", body_label=secret.label))
    bad = broker().evaluate(EgressRequest("POST", "files.pypi.org", body_label=secret.label))
    assert ok.allowed and not bad.allowed and "exfiltration" in bad.reason


def test_combining_with_secret_cannot_launder_readers():
    secret = Labeled.secret("k", {"a.example"})
    web = Labeled.untrusted("page text")
    merged = combine_all([secret.label, web.label])
    assert merged.readers == frozenset({"a.example"})
    assert merged.untrusted and Source.SECRET in merged.sources
    assert not merged.can_flow_to("evil.example")
