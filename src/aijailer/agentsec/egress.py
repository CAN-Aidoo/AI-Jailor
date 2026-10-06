"""Egress broker: the only path from a cell to the network.

Design (see docs/RESEARCH_ALIGNMENT.md):
* Default-deny allowlist by host (exact or ``*.suffix``), port and method.
* SSRF / DNS-rebinding defence: the broker resolves the name itself, rejects
  private, loopback, link-local and cloud-metadata addresses, and connects to
  the *pinned* IP, so a second DNS answer cannot redirect the request.
* Credential injection: the cell only ever holds opaque placeholders
  (``{{secret:github}}``). The broker substitutes the real value, and only for
  hosts that secret is bound to. A prompt-injected agent cannot read, print or
  send a credential it never possessed.
* Information-flow check: bodies/headers carry labels; a value whose readers
  do not include the destination host is refused (exfiltration of a secret or
  private record to an attacker-chosen host).
* Every decision, allowed or not, returns an audit record with secrets redacted.
"""

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from aijailer.agentsec.flow import FlowViolation, Label, Labeled, combine_all

_PLACEHOLDER = re.compile(r"\{\{secret:([A-Za-z0-9_.-]+)\}\}")
_METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}


@dataclass(frozen=True)
class EgressRule:
    host: str                       # "api.github.com" or "*.github.com"
    ports: tuple = (443,)
    methods: tuple = ("GET", "POST", "PUT", "PATCH", "DELETE")

    def matches(self, host: str, port: int, method: str) -> bool:
        h = host.lower().rstrip(".")
        pat = self.host.lower()
        host_ok = h == pat or (pat.startswith("*.") and h.endswith(pat[1:]) and h != pat[2:])
        return host_ok and port in self.ports and method.upper() in self.methods


@dataclass(frozen=True)
class SecretBinding:
    name: str
    value: str
    hosts: tuple                    # hosts allowed to receive this secret


@dataclass
class EgressRequest:
    method: str
    host: str
    port: int = 443
    path: str = "/"
    headers: dict = field(default_factory=dict)
    body: object = ""
    # Optional labels for the data being sent (from the flow tracker).
    body_label: Label | None = None


@dataclass
class EgressDecision:
    allowed: bool
    reason: str
    pinned_ip: str | None = None
    headers: dict = field(default_factory=dict)   # with secrets injected (never logged)
    audit: dict = field(default_factory=dict)     # redacted, safe to persist


def _unsafe_ip(ip: ipaddress._BaseAddress) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified)


class EgressBroker:
    def __init__(self, rules: list[EgressRule], secrets: list[SecretBinding] | None = None,
                 resolver: Callable[[str], list[str]] | None = None,
                 allow_private_cidrs: list[str] | None = None):
        self._rules = rules
        self._secrets = {s.name: s for s in (secrets or [])}
        self._resolver = resolver or self._default_resolver
        self._allow_private = [ipaddress.ip_network(c) for c in (allow_private_cidrs or [])]

    @staticmethod
    def _default_resolver(host: str) -> list[str]:
        import socket
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})

    def _ip_permitted(self, ip: ipaddress._BaseAddress) -> bool:
        if any(ip in net for net in self._allow_private):
            return True
        return not _unsafe_ip(ip)

    def evaluate(self, req: EgressRequest) -> EgressDecision:
        host = req.host.lower().rstrip(".")
        audit = {"method": req.method.upper(), "host": host, "port": req.port, "path": req.path}

        def deny(reason: str) -> EgressDecision:
            audit["decision"] = "deny"
            audit["reason"] = reason
            return EgressDecision(False, reason, audit=audit)

        if host in _METADATA_HOSTS:
            return deny("cloud metadata endpoint is never reachable")
        if not any(r.matches(host, req.port, req.method) for r in self._rules):
            return deny("destination not in egress allowlist")

        # Literal IPs are checked directly; names are resolved by the broker.
        try:
            addrs = [str(ipaddress.ip_address(host))]
        except ValueError:
            try:
                addrs = self._resolver(host)
            except OSError:
                return deny("DNS resolution failed")
        if not addrs:
            return deny("DNS returned no addresses")
        parsed = [ipaddress.ip_address(a) for a in addrs]
        # Reject if ANY answer is unsafe: a mixed answer is a rebinding signature.
        if not all(self._ip_permitted(ip) for ip in parsed):
            return deny("resolves to a private/loopback/link-local address (SSRF)")
        pinned = str(parsed[0])

        # Information-flow: may this data be sent to this host?
        labels = []
        if req.body_label is not None:
            labels.append(req.body_label)
        lab = combine_all(labels)
        if not lab.can_flow_to(host):
            return deny("data label forbids flowing to this destination (exfiltration blocked)")

        # Credential injection, restricted to bound hosts.
        out_headers = {}
        for k, v in req.headers.items():
            def sub(m, _host=host):
                sec = self._secrets.get(m.group(1))
                if sec is None:
                    raise FlowViolation(f"unknown secret '{m.group(1)}'")
                if not any(EgressRule(h).matches(_host, 443, "GET") or h == _host
                           for h in sec.hosts):
                    raise FlowViolation(f"secret '{sec.name}' is not bound to {_host}")
                return sec.value
            try:
                out_headers[k] = _PLACEHOLDER.sub(sub, str(v))
            except FlowViolation as exc:
                return deny(str(exc))
        if _PLACEHOLDER.search(str(req.body)):
            return deny("secret placeholders are only substituted in headers")

        audit["decision"] = "allow"
        audit["pinned_ip"] = pinned
        audit["secrets_used"] = sorted({m.group(1) for v in req.headers.values()
                                        for m in _PLACEHOLDER.finditer(str(v))})
        return EgressDecision(True, "allowed", pinned_ip=pinned, headers=out_headers, audit=audit)
