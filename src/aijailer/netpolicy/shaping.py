"""Per-cell bandwidth limits with real queueing (tbf), applied with netlink (no `tc` binary).

Both limits are EGRESS shapers, because an egress qdisc queues (TCP sees delay, not loss) while
an ingress policer can only drop:

  download (host -> guest): egress of the host-side veth ``aj<id>`` (root namespace)
  upload   (guest -> host): egress of ``vc0`` inside the cell namespace, i.e. the bridge's
                            port toward the host, which every guest->host frame must leave by

The upload shaper lives in the cell's namespace, outside the guest. Since the cell's only path
off the box is its broker, bounding this link bounds the cell's total network use.
"""

from dataclasses import dataclass

from pyroute2 import IPRoute

from aijailer.netpolicy.link import PEER

MIN_KBIT = 64
MAX_KBIT = 10_000_000          # 10 Gbit/s
BURST_SECONDS = 0.1            # short-spike allowance: 100 ms worth of traffic
MIN_BURST = 32 * 1024          # never below a GSO-sized burst
LATENCY = "50ms"               # queue bound: beyond this the shaper drops (bufferbloat cap)
HANDLE = "1:"


def _check(kbit: int | None, what: str) -> int | None:
    if kbit is None:
        return None
    if isinstance(kbit, bool) or not isinstance(kbit, int):
        raise ValueError(f"{what} must be an integer kbit/s or None")
    if not (MIN_KBIT <= kbit <= MAX_KBIT):
        raise ValueError(f"{what} must be between {MIN_KBIT} and {MAX_KBIT} kbit/s")
    return kbit


@dataclass(frozen=True)
class Bandwidth:
    """None means unlimited in that direction."""

    down_kbit: int | None = None   # host -> guest
    up_kbit: int | None = None     # guest -> host

    def __post_init__(self) -> None:
        _check(self.down_kbit, "down_kbit")
        _check(self.up_kbit, "up_kbit")

    @classmethod
    def symmetric_mbps(cls, mbps: int | None) -> "Bandwidth":
        if mbps is None or mbps <= 0:
            return cls()
        return cls(mbps * 1000, mbps * 1000)


def effective_bandwidth(mbps: int | None, override: dict | None) -> Bandwidth:
    """What a cell must be limited to: its per-direction override if one is set, otherwise the
    symmetric default from ``network_bandwidth_mbps``. The override is stored as
    ``{"down_kbit": int, "up_kbit": int}``."""
    if override:
        return Bandwidth(override.get("down_kbit"), override.get("up_kbit"))
    return Bandwidth.symmetric_mbps(mbps)


def tbf_params(kbit: int) -> dict:
    burst = max(MIN_BURST, int(kbit * 1000 / 8 * BURST_SECONDS))
    return {"rate": f"{kbit}kbit", "burst": burst, "latency": LATENCY}


def _set(ipr: IPRoute, ifname: str, kbit: int | None) -> None:
    idx = ipr.link_lookup(ifname=ifname)
    if not idx:
        raise LookupError(f"interface {ifname} not found")
    if kbit is None:
        if _read(ipr, idx[0]) is not None:
            # pyroute2 insists on the full tbf parameter set even to delete; values are ignored.
            ipr.tc("del", "tbf", index=idx[0], handle=HANDLE, **tbf_params(MIN_KBIT))
        return
    ipr.tc("replace", "tbf", index=idx[0], handle=HANDLE, **tbf_params(kbit))


def _read(ipr: IPRoute, idx: int) -> int | None:
    for q in ipr.get_qdiscs(idx):
        if q.get_attr("TCA_KIND") == "tbf":
            parms = q.get_nested("TCA_OPTIONS", "TCA_TBF_PARMS")
            return round(parms["rate"] * 8 / 1000)  # bytes/s -> kbit/s
    return None


def apply_shaping(host_ifname: str, netns: str, bw: Bandwidth) -> None:
    with IPRoute() as root:
        _set(root, host_ifname, bw.down_kbit)
    with IPRoute(netns=netns) as inner:
        _set(inner, PEER, bw.up_kbit)


def read_shaping(host_ifname: str, netns: str) -> Bandwidth:
    """What the kernel is actually enforcing (not what we last asked for)."""
    with IPRoute() as root:
        down = _read(root, root.link_lookup(ifname=host_ifname)[0])
    with IPRoute(netns=netns) as inner:
        up = _read(inner, inner.link_lookup(ifname=PEER)[0])
    return Bandwidth(down, up)
