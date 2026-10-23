"""SSRF protection.

Two modules (TLS certificate and HTTP headers) open a connection to the target the
user typed. Without a guard, someone could point the dashboard at 127.0.0.1, the cloud
metadata service (169.254.169.254) or a host on the server's private network and use
it to probe things it should not reach. Every such connection goes through here first.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket


class BlockedAddress(Exception):
    pass


def is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


async def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve ``host`` and return its addresses, refusing if any of them is not public.

    Refusing on *any* private answer (not just picking a public one) stops tricks where a
    name returns both a public and an internal address.
    """
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise BlockedAddress(f"{host} does not resolve") from exc
        addrs = list(dict.fromkeys(info[4][0] for info in infos))
    blocked = [a for a in addrs if not is_public(a)]
    if blocked:
        raise BlockedAddress(f"{host} resolves to a non-public address ({', '.join(blocked)}); refusing to connect")
    return addrs
