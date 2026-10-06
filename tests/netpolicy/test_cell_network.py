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

    def replace_broker(self, broker):
        self.broker = broker

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


# ----------------------------------------------------------------- sweep / adopt
import ipaddress  # noqa: E402

from aijailer.netpolicy import discovery  # noqa: E402
from aijailer.netpolicy.cell_network import LiveCell  # noqa: E402
from aijailer.netpolicy.nft import ifname_for  # noqa: E402


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def host_state(*cells, addr=None, with_ns=True, orphans=()):
    """Kernel state as the scanner would report it for the given cell ids (+ orphan names)."""
    st = discovery.HostNetState()
    for i, cid in enumerate(cells):
        n = ifname_for(cid)
        st.veths[n] = addr.get(cid) if isinstance(addr, dict) else (
            ipaddress.IPv4Address(f"10.50.0.{1 + 4 * i}"), 30)
        if with_ns:
            st.netns.add(n)
    for n in orphans:
        st.veths[n] = (ipaddress.IPv4Address("10.50.0.253"), 30)
        st.netns.add(n)
    return st


def mk_sweep(state_fn, pool="10.50.0.0/24", links=None, clock=None):
    mgr = NetPolicyManager(runner=FakeNft(), allocator=NetAllocator(pool))
    links = links or FakeLinks()
    n = CellNetwork(mgr, links, proxy_factory=FakeProxy, scan=state_fn, clock=clock or Clock())
    return n, mgr, links


LIVE = LiveCell(uuid.uuid4(), POLICY, 10)


@pytest.mark.asyncio
async def test_sweep_adopts_live_cell_after_restart():
    cid = uuid.uuid4()
    n, mgr, links = mk_sweep(lambda: host_state(cid))
    rep = await n.sweep({cid: LiveCell(uuid.uuid4(), POLICY, 10)}, set())
    assert rep.adopted == [cid] and rep.broken == [] and not rep.changed is False
    assert n.provisioned == {cid}
    net = mgr.cells[0]
    assert (str(net.host_ip), str(net.guest_ip)) == ("10.50.0.1", "10.50.0.2")
    assert FakeProxy.instances[0].started and FakeProxy.instances[0].ip == "10.50.0.1"
    assert links.shaped == [(cid, Bandwidth(10_000, 10_000))]  # limit re-asserted
    # the adopted /30 is reserved: a new cell must not receive it
    p = await n.provision(uuid.uuid4(), uuid.uuid4(), POLICY)
    assert str(p.net.host_ip) != "10.50.0.1"
    # second sweep is a no-op
    rep2 = await n.sweep({cid: LIVE}, set())
    assert rep2.kept == [cid] and rep2.adopted == [] and rep2.errors == []


@pytest.mark.asyncio
async def test_sweep_removes_orphans_but_never_foreign_names():
    live, orphan = uuid.uuid4(), uuid.uuid4()
    st = host_state(live, orphans=[ifname_for(orphan)])
    st.veths["eth0"] = None          # foreign names must be invisible to the sweep
    st.netns.add("docker0")
    n, _, links = mk_sweep(lambda: st)
    torn = []
    orig = links.teardown

    async def spy(name):
        torn.append(name)
        await orig(name)
    links.teardown = spy
    rep = await n.sweep({live: LIVE}, set())
    assert rep.orphans_removed == [ifname_for(orphan)] and rep.adopted == [live]
    assert torn == [ifname_for(orphan)]


@pytest.mark.asyncio
async def test_known_cell_not_live_removed_only_after_grace():
    clock = Clock()
    n, mgr, _ = mk_sweep(lambda: host_state(), clock=clock)
    cid = uuid.uuid4()
    await n.provision(cid, uuid.uuid4(), POLICY)
    n._scan = lambda: host_state(cid)
    clock.t += 30                                   # younger than grace: DB may lag the commit
    assert (await n.sweep({}, set(), grace=120)).stale_removed == []
    assert n.provisioned == {cid}
    clock.t += 200
    rep = await n.sweep({}, set(), grace=120)
    assert rep.stale_removed == [cid] and n.provisioned == set() and mgr.cells == []


@pytest.mark.asyncio
async def test_protected_cells_are_never_touched():
    cid = uuid.uuid4()
    n, _, links = mk_sweep(lambda: host_state(cid))
    rep = await n.sweep({}, {cid}, grace=0)          # 'creating' / 'destroying' in the DB
    assert not rep.changed and n.provisioned == set() and not FakeProxy.instances


@pytest.mark.asyncio
async def test_live_cell_with_missing_kernel_resources_is_reported_broken():
    clock = Clock()
    n, _, _ = mk_sweep(lambda: host_state(), clock=clock)
    cid = uuid.uuid4()
    await n.provision(cid, uuid.uuid4(), POLICY)
    n._scan = lambda: host_state()                   # veth and netns vanished
    rep = await n.sweep({cid: LIVE}, set())
    assert rep.broken == [cid]


@pytest.mark.asyncio
async def test_adopt_of_incomplete_network_cleans_up_and_reports_broken():
    cid = uuid.uuid4()
    n, mgr, links = mk_sweep(lambda: host_state(cid, with_ns=False))
    rep = await n.sweep({cid: LIVE}, set())
    assert rep.adopted == [] and rep.broken == [cid]
    assert mgr.cells == [] and n.provisioned == set() and not FakeProxy.instances


@pytest.mark.asyncio
async def test_adopt_outside_pool_or_wrong_prefix_is_broken_not_adopted():
    a, b = uuid.uuid4(), uuid.uuid4()
    st = host_state(a, b, addr={a: (ipaddress.IPv4Address("192.168.9.1"), 30),
                                b: (ipaddress.IPv4Address("10.50.0.1"), 24)})
    n, mgr, _ = mk_sweep(lambda: st)
    rep = await n.sweep({a: LIVE, b: LIVE}, set())
    assert sorted(rep.broken) == sorted([a, b]) and rep.adopted == [] and mgr.cells == []


@pytest.mark.asyncio
async def test_two_cells_claiming_one_subnet_second_is_broken():
    a, b = uuid.uuid4(), uuid.uuid4()
    same = (ipaddress.IPv4Address("10.50.0.1"), 30)
    n, mgr, _ = mk_sweep(lambda: host_state(a, b, addr={a: same, b: same}))
    rep = await n.sweep({a: LIVE, b: LIVE}, set())
    assert len(rep.adopted) == 1 and len(rep.broken) == 1 and len(mgr.cells) == 1


@pytest.mark.asyncio
async def test_mass_removal_guard_aborts_without_changes():
    orphans = [ifname_for(uuid.uuid4()) for _ in range(8)]
    n, _, links = mk_sweep(lambda: host_state(orphans=orphans))
    rep = await n.sweep({}, set())                   # e.g. DB returned nothing
    assert rep.aborted and "refusing" in rep.aborted and rep.orphans_removed == []
    assert not links.up and n.provisioned == set()


@pytest.mark.asyncio
async def test_small_cleanups_are_not_blocked_by_the_guard():
    orphans = [ifname_for(uuid.uuid4()) for _ in range(3)]
    live = [uuid.uuid4() for _ in range(3)]
    n, _, _ = mk_sweep(lambda: host_state(*live, orphans=orphans))
    rep = await n.sweep({c: LIVE for c in live}, set())
    assert len(rep.orphans_removed) == 3 and len(rep.adopted) == 3 and rep.aborted is None


@pytest.mark.asyncio
async def test_failed_orphan_removal_is_reported_and_retried_next_sweep():
    orphan = ifname_for(uuid.uuid4())
    links = FakeLinks(fail_teardown=True)
    n, _, _ = mk_sweep(lambda: host_state(orphans=[orphan]), links=links)
    rep = await n.sweep({}, set())
    assert rep.orphans_removed == [] and rep.errors and orphan in rep.errors[0]
    links.fail_teardown = False
    assert (await n.sweep({}, set())).orphans_removed == [orphan]


def test_allocator_reserve_prevents_double_allocation():
    a = NetAllocator("10.9.0.0/28")                  # 4 subnets
    ids = [uuid.uuid4() for _ in range(3)]
    a.reserve(ids[0], ipaddress.ip_network("10.9.0.8/30"))
    got = {str(a.allocate(i)) for i in ids[1:]} | {str(a.allocate(uuid.uuid4()))}
    assert "10.9.0.8/30" not in got and len(got) == 3
    with pytest.raises(Exception, match="exhausted"):
        a.allocate(uuid.uuid4())
    for bad in ("10.9.0.0/29", "10.10.0.0/30", "10.9.0.2/31"):
        with pytest.raises(Exception):
            a.reserve(uuid.uuid4(), ipaddress.ip_network(bad))
    with pytest.raises(Exception, match="already allocated"):
        a.reserve(uuid.uuid4(), ipaddress.ip_network("10.9.0.8/30"))


@pytest.mark.asyncio
async def test_unadopted_in_flight_cells_keep_their_subnet_reserved():
    creating = uuid.uuid4()   # protected: DB says 'creating'; its veth owns 10.50.0.1/30
    n, mgr, _ = mk_sweep(lambda: host_state(creating))
    await n.sweep({}, {creating})
    p = await n.provision(uuid.uuid4(), uuid.uuid4(), POLICY)
    assert str(p.net.host_ip) != "10.50.0.1"          # would have put two ifaces on one /30
    n._scan = lambda: host_state()                    # the in-flight cell's veth is gone
    await n.sweep({}, set())
    q = await n.provision(uuid.uuid4(), uuid.uuid4(), POLICY)
    assert str(q.net.host_ip) == "10.50.0.1"          # and the subnet is reusable again


def test_allocator_external_blocks_both_fresh_and_released_slots():
    a = NetAllocator("10.7.0.0/28")
    c1, c2 = uuid.uuid4(), uuid.uuid4()
    s1 = a.allocate(c1)
    a.release(c1)
    a.set_external([s1])
    assert a.allocate(c2) != s1
    a.set_external([])
    assert a.allocate(uuid.uuid4()) == s1


# ----------------------------------------------------------------- secret refresh
from aijailer.agentsec.egress import SecretBinding  # noqa: E402


class DictSecrets:
    def __init__(self):
        self.by_tenant, self.fail = {}, False

    async def secrets_for(self, tenant_id, cell_id):
        if self.fail:
            raise ConnectionError("db down")
        return list(self.by_tenant.get(tenant_id, []))


def mk_secret_net():
    sec = DictSecrets()
    mgr = NetPolicyManager(runner=FakeNft(), allocator=NetAllocator("10.60.0.0/24"))
    return CellNetwork(mgr, FakeLinks(), secrets=sec, proxy_factory=FakeProxy), sec


def can_inject(proxy, name="gh", host="api.github.com"):
    from aijailer.agentsec.egress import EgressRequest
    proxy.broker._resolver = lambda h: ["140.82.112.5"]
    return proxy.broker.evaluate(EgressRequest(
        "GET", host, 443, "/", {"Authorization": "{{secret:%s}}" % name})).allowed


@pytest.mark.asyncio
async def test_provisioning_uses_the_tenants_secrets():
    n, sec = mk_secret_net()
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    sec.by_tenant[t1] = [SecretBinding("gh", "tok1", ("api.github.com",))]
    await n.provision(uuid.uuid4(), t1, POLICY)
    await n.provision(uuid.uuid4(), t2, POLICY)
    a, b = FakeProxy.instances
    assert can_inject(a) and not can_inject(b)            # tenant isolation at the broker


@pytest.mark.asyncio
async def test_rotation_and_revocation_reach_running_cells():
    n, sec = mk_secret_net()
    t = uuid.uuid4()
    await n.provision(uuid.uuid4(), t, POLICY)
    p = FakeProxy.instances[0]
    assert not can_inject(p)
    sec.by_tenant[t] = [SecretBinding("gh", "tok", ("api.github.com",))]
    assert await n.refresh_secrets(t) == 1 and can_inject(p)      # created -> usable at once
    sec.by_tenant[t] = []
    await n.refresh_secrets(t)
    assert not can_inject(p)                                       # revoked -> unusable at once


@pytest.mark.asyncio
async def test_refresh_is_scoped_to_the_tenant():
    n, sec = mk_secret_net()
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    await n.provision(uuid.uuid4(), t1, POLICY)
    await n.provision(uuid.uuid4(), t2, POLICY)
    sec.by_tenant[t1] = [SecretBinding("gh", "x", ("api.github.com",))]
    sec.by_tenant[t2] = [SecretBinding("gh", "y", ("api.github.com",))]
    assert await n.refresh_secrets(t1) == 1
    a, b = FakeProxy.instances
    assert can_inject(a) and not can_inject(b)


@pytest.mark.asyncio
async def test_store_outage_fails_closed_on_change_but_keeps_state_on_periodic_refresh():
    n, sec = mk_secret_net()
    t = uuid.uuid4()
    sec.by_tenant[t] = [SecretBinding("gh", "tok", ("api.github.com",))]
    await n.provision(uuid.uuid4(), t, POLICY)
    p = FakeProxy.instances[0]
    assert can_inject(p)
    sec.fail = True
    await n.refresh_secrets(None, fail_closed=False)               # periodic: outage tolerated
    assert can_inject(p)
    await n.refresh_secrets(t, fail_closed=True)                   # change-triggered: no stale secret
    assert not can_inject(p)
    sec.fail = False
    await n.refresh_secrets(t)                                     # recovers
    assert can_inject(p)


@pytest.mark.asyncio
async def test_sweep_refreshes_secrets_for_eventual_consistency():
    n, sec = mk_secret_net()
    t = uuid.uuid4()
    cid = uuid.uuid4()
    await n.provision(cid, t, POLICY)
    n._scan = lambda: host_state(cid)
    sec.by_tenant[t] = [SecretBinding("gh", "tok", ("api.github.com",))]
    await n.sweep({cid: LiveCell(t, POLICY, None)}, set())
    assert can_inject(FakeProxy.instances[0])
