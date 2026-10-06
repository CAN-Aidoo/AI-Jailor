"""Read-only discovery of cell network resources that actually exist on this host.

Only names that exactly match what we create (``aj`` + 12 hex digits) are ever reported, so
nothing the operator or another tool owns can be mistaken for a cell resource.
"""

import ipaddress
import re
from dataclasses import dataclass, field

from pyroute2 import IPRoute, netns

_NAME = re.compile(r"^aj[0-9a-f]{12}$")


def is_cell_name(name: str) -> bool:
    return bool(_NAME.match(name))


def prefix_of(name: str) -> str:
    """The 12 hex digits identifying the cell (first 48 bits of its UUID)."""
    return name[2:]


@dataclass
class HostNetState:
    # host-side veth name -> (host_ip, prefixlen) as configured in the kernel (None if unaddressed)
    veths: dict[str, tuple[ipaddress.IPv4Address, int] | None] = field(default_factory=dict)
    netns: set[str] = field(default_factory=set)

    @property
    def names(self) -> set[str]:
        return set(self.veths) | self.netns


def scan_host() -> HostNetState:
    st = HostNetState()
    with IPRoute() as ipr:
        for link in ipr.get_links():
            name = link.get_attr("IFLA_IFNAME")
            if not is_cell_name(name):
                continue
            addr = None
            for a in ipr.get_addr(index=link["index"], family=2):
                addr = (ipaddress.IPv4Address(a.get_attr("IFA_ADDRESS")), a["prefixlen"])
                break
            st.veths[name] = addr
    st.netns = {n for n in netns.listnetns() if is_cell_name(n)}
    return st
