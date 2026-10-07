"""Claiming a specific /30 (a restored guest keeps its address)."""

import ipaddress
import uuid

import pytest

from aijailer.netpolicy.nft import NetAllocator, NftError

SN = ipaddress.ip_network("10.97.0.8/30")


def test_claim_free_subnet_then_nobody_else_gets_it():
    a, c1, c2 = NetAllocator("10.97.0.0/24"), uuid.uuid4(), uuid.uuid4()
    a.claim(c1, SN)
    assert not a.is_available(c2, SN) and a.is_available(c1, SN)
    got = {a.allocate(uuid.uuid4()) for _ in range(5)}
    assert SN not in got                                    # bump pointer skips the claimed slot
    with pytest.raises(NftError):
        a.claim(c2, SN)


def test_claim_refuses_taken_external_and_foreign_subnets():
    a, c1 = NetAllocator("10.97.0.0/24"), uuid.uuid4()
    a.set_external([SN])                                    # exists on the host under another name
    assert not a.is_available(c1, SN)
    with pytest.raises(NftError):
        a.claim(c1, SN)
    with pytest.raises(NftError):
        a.claim(c1, ipaddress.ip_network("192.168.0.0/30"))
    with pytest.raises(NftError):
        a.is_available(c1, ipaddress.ip_network("10.97.0.0/29"))


def test_claim_removes_the_slot_from_the_free_list_and_release_returns_it():
    a, c1, c2 = NetAllocator("10.97.0.0/24"), uuid.uuid4(), uuid.uuid4()
    first = a.allocate(c1)
    a.release(c1)                                           # now on the free list
    a.claim(c2, first)
    assert a.allocate(uuid.uuid4()) != first                # not handed out twice
    a.release(c2)
    assert a.allocate(uuid.uuid4()) == first


@pytest.mark.asyncio
async def test_manager_register_pins_the_subnet_and_fails_without_state():
    from aijailer.netpolicy.nft import NetPolicyManager

    class Nft:
        async def run(self, script):
            pass
    m = NetPolicyManager(runner=Nft(), allocator=NetAllocator("10.97.0.0/24"))
    c1, c2 = uuid.uuid4(), uuid.uuid4()
    cell = await m.register(c1, subnet=str(SN))
    assert str(cell.guest_ip) == "10.97.0.10" and str(cell.host_ip) == "10.97.0.9"
    assert not m.subnet_available(c2, str(SN))
    with pytest.raises(NftError):
        await m.register(c2, subnet=str(SN))
    assert c2 not in {c.cell_id for c in m.cells}
