from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

logger = logging.getLogger("allowlist")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Allowlist:
    """IPs and CIDR ranges (IPv4 + IPv6) that never raise an alert."""

    networks: tuple[Network, ...] = ()

    @classmethod
    def parse(cls, entries: list[str], *, source: str = "ALLOWLIST_IPS") -> "Allowlist":
        nets: list[Network] = []
        for raw in entries:
            if not raw.strip():
                continue
            try:
                nets.append(ipaddress.ip_network(raw.strip(), strict=False))
            except ValueError:
                logger.warning("%s: ignoring invalid entry %r", source, raw)
        return cls(tuple(nets))

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        return any(addr.version == net.version and addr in net for net in self.networks)

    def __len__(self) -> int:
        return len(self.networks)
