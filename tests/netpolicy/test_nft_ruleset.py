"""Unit tests for ruleset generation, validation and allocation (no kernel needed)."""

import ipaddress
import re
import uuid

import pytest

from aijailer.netpolicy.nft import (
    CellNet, NetAllocator, NetPolicyManager, NftError, base_ruleset, full_ruleset, ifname_for)


class FakeNft:
    def __init__(self, fail_on=None):
        self.scripts, self.fail_on = [], fail_on

    async def run(self, script, check_only=False):
        if self.fail_on and self.fail_on in script:
            raise NftError("boom")
        self.scripts.append(script)
        return ""


def test_ruleset_default_deny_shape():
    rs = base_ruleset()
    chain = re.search(r"chain from_cell \{(.*?)\n  \}", rs, re.S).group(1)
    accepts = [ln for ln in chain.splitlines() if re.search(r"\baccept\b", ln)]
    assert len(accepts) == 1
    # The one accept is bound to the full (iface, src, dst, dport) tuple, IPv4 only.
    assert "iifname . ip saddr . ip daddr . tcp dport @broker" in accepts[0]
    # ...and the chain ends in an unconditional drop (covers IPv6, ICMP, UDP, other ports).
    assert chain.strip().splitlines()[-1].strip() == "counter drop"
    # Prefix match, never set membership: unregistered cell ifaces stay denied (fail closed).
    assert 'iifname "aj*" counter drop' in rs and 'oifname "aj*" counter drop' in rs
    assert 'oifname "aj*" ct state new counter drop' in rs and "@cells" not in rs


def test_cellnet_validation():
    cid = uuid.uuid4()
    ok = dict(cell_id=cid, ifname="aj123", host_ip=ipaddress.IPv4Address("10.0.0.1"),
              guest_ip=ipaddress.IPv4Address("10.0.0.2"), prefix=30, broker_port=3128)
    CellNet(**ok)
    for bad in ({"ifname": 'x" ; flush ruleset ; "'}, {"ifname": "a" * 16}, {"ifname": "eth0"}, {"ifname": ""},
                {"broker_port": 0}, {"broker_port": 70000},
                {"guest_ip": ipaddress.IPv4Address("10.0.0.1")},
                {"guest_ip": ipaddress.IPv4Address("10.9.9.9")}):
        with pytest.raises(ValueError):
            CellNet(**{**ok, **bad})


def test_ifname_fits_ifnamsiz():
    assert len(ifname_for(uuid.uuid4())) <= 15


def test_allocator_unique_reuse_and_exhaustion():
    a = NetAllocator("10.1.0.0/28")  # 4 /30 subnets
    ids = [uuid.uuid4() for _ in range(4)]
    nets = [a.allocate(i) for i in ids]
    assert len(set(nets)) == 4
    assert a.allocate(ids[0]) == nets[0]  # idempotent
    with pytest.raises(NftError):
        a.allocate(uuid.uuid4())
    a.release(ids[1])
    assert a.allocate(uuid.uuid4()) == nets[1]


@pytest.mark.asyncio
async def test_register_installs_base_then_adds_elements_atomically():
    f = FakeNft()
    m = NetPolicyManager(runner=f, allocator=NetAllocator("10.2.0.0/24"))
    c = await m.register(uuid.uuid4())
    assert f.scripts[0].startswith("add table")
    assert "add element inet aijailer broker" in f.scripts[-1]
    assert str(c.guest_ip) in f.scripts[-1] and c.ifname in f.scripts[-1]
    assert (await m.register(c.cell_id)) is c  # idempotent


@pytest.mark.asyncio
async def test_failed_apply_does_not_leak_address_or_registry():
    f = FakeNft()
    m = NetPolicyManager(runner=f, allocator=NetAllocator("10.3.0.0/30"))
    await m.install()
    f.fail_on = "add element"
    with pytest.raises(NftError):
        await m.register(uuid.uuid4())
    f.fail_on = None
    assert m.cells == []
    await m.register(uuid.uuid4())  # the single /30 was released, so this succeeds


@pytest.mark.asyncio
async def test_unregister_revokes_before_freeing():
    f = FakeNft()
    m = NetPolicyManager(runner=f, allocator=NetAllocator("10.4.0.0/24"))
    c = await m.register(uuid.uuid4())
    await m.unregister(c.cell_id)
    assert "delete element inet aijailer broker" in f.scripts[-1]
    assert m.cells == []
    await m.unregister(c.cell_id)  # idempotent


@pytest.mark.asyncio
async def test_full_ruleset_contains_every_cell():
    m = NetPolicyManager(runner=FakeNft(), allocator=NetAllocator("10.5.0.0/24"))
    cs = [await m.register(uuid.uuid4()) for _ in range(3)]
    rs = full_ruleset(cs)
    for c in cs:
        assert c.ifname in rs and str(c.guest_ip) in rs
