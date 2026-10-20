"""Which IP addresses outbound requests may reach (SECURITY.md §4.6, threat S9).

Only globally routable unicast addresses are allowed. Everything else is refused:
loopback, RFC 1918, link-local (cloud metadata), CGNAT, multicast, reserved,
documentation and benchmarking ranges, and IPv6 forms that embed or translate IPv4
(mapped, 6to4, Teredo, NAT64), unless a connector was explicitly granted a private
range by an administrator.
"""

import ipaddress
from collections.abc import Iterable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# IPv6 ranges that carry or translate IPv4 traffic: refused outright, since the
# embedded address could be internal.
_TRANSLATION_RANGES = tuple(
    ipaddress.ip_network(n) for n in ("2002::/16", "2001::/32", "64:ff9b::/96", "64:ff9b:1::/48")
)


def parse_address(value: str) -> IPAddress:
    address = ipaddress.ip_address(value.split("%", 1)[0])  # drop an IPv6 zone index
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def is_public(address: IPAddress) -> bool:
    if address.is_multicast or not address.is_global:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        return not any(address in network for network in _TRANSLATION_RANGES)
    return True


def is_never_allowed(address: IPAddress) -> bool:
    """Loopback, link-local (cloud metadata), unspecified and multicast: no exception."""
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    )


def is_allowed(address: IPAddress, private_allowed: Iterable[IPNetwork] = ()) -> bool:
    if is_public(address):
        return True
    if is_never_allowed(address):
        return False
    return any(address.version == net.version and address in net for net in private_allowed)
