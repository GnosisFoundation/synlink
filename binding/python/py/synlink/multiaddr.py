"""Re-export of the multiaddr library."""

from typing import Union
from multiaddr import Multiaddr
from multiaddr.protocols import (
    P_DNS,
    P_IP4,
    P_IP6,
    P_P2P,
    P_TCP,
    P_UDP,
    Protocol,
)
from multiaddr.exceptions import (
    StringParseError,
    BinaryParseError,
    ProtocolExistsError,
    ProtocolNotFoundError,
)

__all__ = [
    "Multiaddr",
    "Protocol",
    "is_valid_address",
    "StringParseError",
    "BinaryParseError",
    "ProtocolExistsError",
    "ProtocolNotFoundError",
]

_PROTOCOL_CONFIG = {
    P_IP4: {"transports": [P_TCP, P_UDP], "overlays": [P_P2P]},
    P_IP6: {"transports": [P_TCP, P_UDP], "overlays": [P_P2P]},
    P_DNS: {"transports": [P_TCP], "overlays": [P_P2P]},
}

def _generate_supported_protocols():
    """Generate all valid protocol combinations."""
    protocols = set()

    for network, config in _PROTOCOL_CONFIG.items():
        for transport in config["transports"]:

            base_combo = (network, transport)
            protocols.add(base_combo)

            for overlay in config["overlays"]:
                protocols.add(base_combo + (overlay,))

    return protocols

_SUPPORTED_PROTOCOLS = _generate_supported_protocols()

def is_valid_address(addr: Union[Multiaddr, str, bytes]) -> bool:
    """
    Check if a multiaddr uses only supported protocols.

    synlink network only supports a subset of multiaddr protocols.


    ### Example:
    ```
    "/ip4/127.0.0.1/tcp/8080",
    "/ip6/::1/tcp/8080",
    "/dns/example.com/tcp/443/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
    ```
    """
    address = addr
    if isinstance(addr, (str, bytes)):
        address = Multiaddr(addr)

    protocol_tuple = tuple(protocol.code for protocol in address.protocols())
    return protocol_tuple in _SUPPORTED_PROTOCOLS
