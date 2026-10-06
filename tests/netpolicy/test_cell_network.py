"""CellNetwork orchestration: ordering, rollback, idempotency, policy mapping (no kernel)."""

import uuid

import pytest

from aijailer.agentsec.egress import EgressRequest
from aijailer.netpolicy.cell_network import CellNetwork, broker_from_policy
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager

LOG: list[str] = []


class FakeNft:
    async def run(self, script, check_only=False):
        if script.startswith("delete element"):
            LOG.append("fw:revoke")
        elif "add element" in script:
            LOG.append("fw:register")
        return ""


class FakeLinks:
    def __init__(self, fail_setup=False, fail_teardown=False, fail_shape=False):
        self.fail_setup, self.fail_teardown, self.up = fail_setup, fail_teardown, set()
        self.fail_shape, self.shaped = fail_shape, []

    async def set_bandwidth(self, cell, bw):
        if self.fail_shape:
            raise OSError("tbf unsupported")
        LOG.append("shape")
        self.shaped.append((cell.cell_id, bw))

    async def setup(self, cell):
        if self.fail_setup:
            raise OSError("tap create failed")
        LOG.append("link:up")
        self.up.add(cell.ifname)

    async def teardown(self, ifname):
        if self.fail_teardown:
            raise OSError("busy")
        LOG.append("link:down")
        self.up.discard(ifname)


class FakeProxy:
    instances = []

    def __init__(self, cell_id, ip, port, broker, audit=None, **kw):
        self.cell_id, self.ip, self.port, self.broker, self.audit = cell_id, ip, port, broker, audit
        self.started = self.stopped = False
        FakeProxy.instances.append(self)

    async def start(self):
        if getattr(FakeProxy, "fail_start", False):
            raise OSError("bind failed")
        LOG.append("proxy:start")
        self.started = True

    async def stop(self):
        LOG.append("proxy:stop")
        self.stopped = True


@pytest.fixture(autouse=True)
def reset():
    LOG.clear()
    FakeProxy.instances.clear()
    FakeProxy.fail_start = False


def mk(links=None, pool="10.50.0.0/28", audit=None):
    mgr = NetPolicyManager(runner=FakeNft(), allocator=NetAllocator(pool))
    links = links or FakeLinks()
    return CellNetwork(mgr, links, proxy_factory=FakeProxy, audit=audit), mgr, links


POLICY = {"default": "deny", "egress": [
    {"action": "allow", "destinations": [{"domain": "api.github.com"}, {"domain": "*.pypi.org"}],
     "protocols": ["tcp"], "ports": [443]}]}


@pytest.mark.asyncio
async def test_provision_order_and_env():
    n, _, _ = mk()
    cid = uuid.uuid4()
    p = await n.provision(cid, uuid.uuid4(), POLICY)
    LOG[:] = [x for x in LOG if x != "fw:register" or True]
    assert LOG.index("fw:register") < LOG.index("link:up") < LOG.index("proxy:start")
    assert p.proxy_url == f"http://{p.net.host_ip}:{p.net.broker_port}"
    assert p.env["https_proxy"] == p.proxy_url
    assert FakeProxy.instances[0].ip == str(p.net.host_ip)  # bound to the cell's link only


@pytest.mark.asyncio
async def test_teardown_revokes_firewall_first_then_proxy_then_link_then_frees_address():
    n, mgr, _ = mk(pool="10.51.0.0/30")  # exactly one /30
    cid = uuid.uuid4()
    await n.provision(cid, uuid.uuid4(), POLICY)
    LOG.clear()
    assert await n.deprovision(cid) == []
    assert LOG == ["fw:revoke", "proxy:stop", "link:down"]
    await n.provision(uuid.uuid4(), uuid.uuid4(), POLICY)  # address was released -> reusable


@pytest.mark.asyncio
async def test_address_not_reused_until_link_is_gone():
    links = FakeLinks(fail_teardown=True)
    n, _, _ = mk(links=links, pool="10.52.0.0/30")
    cid = uuid.uuid4()
    await n.provision(cid, uuid.uuid4(), POLICY)
    errors = await n.deprovision(cid)
    assert errors and "link" in errors[0]
    with pytest.raises(Exception, match="exhausted"):  # still reserved: TAP may still carry it
        await n.provision(uuid.uuid4(), uuid.uuid4(), POLICY)


@pytest.mark.asyncio
async def test_failure_at_each_step_rolls_everything_back():
    # link setup fails
    n, mgr, _ = mk(links=FakeLinks(fail_setup=True))
    with pytest.raises(OSError):
        await n.provision(uuid.uuid4(), uuid.uuid4(), POLICY)
    assert mgr.cells == [] and n.provisioned == set() and "fw:revoke" in LOG
    # proxy bind fails after link is up -> link torn down too
    LOG.clear()
    FakeProxy.fail_start = True
    n2, mgr2, links2 = mk()
    with pytest.raises(OSError):
        await n2.provision(uuid.uuid4(), uuid.uuid4(), POLICY)
    assert mgr2.cells == [] and links2.up == set() and n2.provisioned == set()
    assert LOG[-2:] == ["fw:revoke", "link:down"] or "link:down" in LOG


@pytest.mark.asyncio
async def test_deprovision_idempotent_and_unknown_is_noop():
    n, _, _ = mk()
    cid = uuid.uuid4()
    await n.provision(cid, uuid.uuid4(), POLICY)
    assert await n.deprovision(cid) == []
    assert await n.deprovision(cid) == []
    assert await n.deprovision(uuid.uuid4()) == []


@pytest.mark.asyncio
async def test_double_provision_rejected():
    n, _, _ = mk()
    cid, t = uuid.uuid4(), uuid.uuid4()
    await n.provision(cid, t, POLICY)
    with pytest.raises(RuntimeError):
        await n.provision(cid, t, POLICY)


@pytest.mark.asyncio
async def test_reconcile_removes_leaked_networks_only():
    n, mgr, _ = mk()
    a, b = uuid.uuid4(), uuid.uuid4()
    await n.provision(a, uuid.uuid4(), POLICY)
    await n.provision(b, uuid.uuid4(), POLICY)
    stale = await n.reconcile({a})
    assert stale == [b] and n.provisioned == {a} and [c.cell_id for c in mgr.cells] == [a]


@pytest.mark.asyncio
async def test_proxy_audit_events_are_forwarded_with_cell_id():
    seen = []
    n, _, _ = mk(audit=lambda cid, ev: seen.append((cid, ev)))
    cid = uuid.uuid4()
    await n.provision(cid, uuid.uuid4(), POLICY)
    FakeProxy.instances[0].audit({"decision": "deny"})
    assert seen == [(cid, {"decision": "deny"})]


def test_policy_mapping_allows_listed_denies_rest():
    broker, skipped = broker_from_policy(POLICY, [])
    ok = lambda h, port=443: broker.evaluate(EgressRequest("GET", h, port)).reason  # noqa: E731
    broker._resolver = lambda h: ["140.82.112.5"]
    assert broker.evaluate(EgressRequest("GET", "api.github.com")).allowed
    assert broker.evaluate(EgressRequest("GET", "files.pypi.org")).allowed
    assert not broker.evaluate(EgressRequest("GET", "evil.example")).allowed
    assert not broker.evaluate(EgressRequest("GET", "api.github.com", port=22)).allowed
    assert skipped == [] and ok("evil.example")


def test_policy_mapping_is_strict_about_what_it_cannot_enforce():
    pol = {"egress": [
        {"action": "allow", "destinations": [{"ip": "10.0.0.0/8"}], "ports": [443]},
        {"action": "allow", "destinations": [{"domain": "dns.test"}], "protocols": ["udp"]},
        {"action": "deny", "destinations": [{"domain": "x.test"}]},
        {"action": "allow", "destinations": [{"ip": "10.1.2.3"}], "ports": [8080]},
    ]}
    broker, skipped = broker_from_policy(pol, [])
    broker._resolver = lambda h: [h] if h[0].isdigit() else ["8.8.8.8"]
    assert len(skipped) == 2  # CIDR + udp
    assert not broker.evaluate(EgressRequest("GET", "10.9.9.9", 443)).allowed  # CIDR not honoured
    assert not broker.evaluate(EgressRequest("GET", "dns.test", 443)).allowed
    assert not broker.evaluate(EgressRequest("GET", "x.test", 443)).allowed
    # an explicitly allowed single internal IP works, exactly that IP and port
    assert broker.evaluate(EgressRequest("GET", "10.1.2.3", 8080)).allowed
    assert not broker.evaluate(EgressRequest("GET", "10.1.2.4", 8080)).allowed


def test_empty_or_missing_policy_means_no_egress_at_all():
    for pol in (None, {}, {"default": "allow"}, {"egress": []}):
        broker, _ = broker_from_policy(pol, [])
        broker._resolver = lambda h: ["8.8.8.8"]
        assert not broker.evaluate(EgressRequest("GET", "api.github.com")).allowed


@pytest.mark.asyncio
async def test_runtime_installs_ruleset_and_aborts_startup_on_failure(monkeypatch):
    from aijailer.netpolicy import runtime

    class Eng:
        needs_network = True

    n, mgr, _ = mk()
    monkeypatch.setattr(runtime, "get_cell_network", lambda: n)
    rt = await runtime.start_network_runtime(Eng(), interval=0.01)
    assert rt is not None and mgr._installed is True
    await rt.stop()

    async def boom(*a, **k):
        raise RuntimeError("nft missing")
    monkeypatch.setattr(mgr, "install", boom)
    with pytest.raises(RuntimeError, match="nft missing"):  # fail closed: no firewall, no service
        await runtime.start_network_runtime(Eng())

    class NoNic:
        needs_network = False
    assert await runtime.start_network_runtime(NoNic()) is None


from aijailer.netpolicy.shaping import Bandwidth, tbf_params  # noqa: E402


@pytest.mark.asyncio
async def test_bandwidth_applied_after_link_and_before_proxy():
    n, _, links = mk()
    cid = uuid.uuid4()
    await n.provision(cid, uuid.uuid4(), POLICY, Bandwidth(8000, 4000))
    assert LOG.index("link:up") < LOG.index("shape") < LOG.index("proxy:start")
    assert links.shaped == [(cid, Bandwidth(8000, 4000))]


@pytest.mark.asyncio
async def test_no_bandwidth_means_no_shaping_call():
    n, _, links = mk()
    await n.provision(uuid.uuid4(), uuid.uuid4(), POLICY)
    assert links.shaped == []


@pytest.mark.asyncio
async def test_shaping_failure_rolls_back_whole_network():
    links = FakeLinks(fail_shape=True)
    n, mgr, _ = mk(links=links)
    with pytest.raises(OSError, match="tbf"):
        await n.provision(uuid.uuid4(), uuid.uuid4(), POLICY, Bandwidth(1000, 1000))
    assert mgr.cells == [] and links.up == set() and n.provisioned == set()
    assert not FakeProxy.instances  # proxy never started: a cell never runs unshaped


@pytest.mark.asyncio
async def test_hot_update_bandwidth():
    n, _, links = mk()
    cid = uuid.uuid4()
    await n.provision(cid, uuid.uuid4(), POLICY, Bandwidth(1000, 1000))
    await n.set_bandwidth(cid, Bandwidth(2000, None))
    assert links.shaped[-1] == (cid, Bandwidth(2000, None))
    with pytest.raises(LookupError):
        await n.set_bandwidth(uuid.uuid4(), Bandwidth(1000, 1000))
    await n.deprovision(cid)
    with pytest.raises(LookupError):  # gone after teardown
        await n.set_bandwidth(cid, Bandwidth(1000, 1000))


def test_bandwidth_validation():
    assert Bandwidth.symmetric_mbps(100) == Bandwidth(100_000, 100_000)
    assert Bandwidth.symmetric_mbps(0) == Bandwidth() == Bandwidth.symmetric_mbps(None)
    for bad in (0, 63, -5, 10_000_001, 1.5, "10", True):
        with pytest.raises(ValueError):
            Bandwidth(down_kbit=bad)
        with pytest.raises(ValueError):
            Bandwidth(up_kbit=bad)


def test_tbf_params_burst_floor_and_scaling():
    low = tbf_params(64)
    assert low["rate"] == "64kbit" and low["burst"] == 32 * 1024  # floor
    hi = tbf_params(1_000_000)  # 1 Gbit/s -> 100 ms of traffic
    assert hi["burst"] == 12_500_000 and hi["latency"] == "50ms"
