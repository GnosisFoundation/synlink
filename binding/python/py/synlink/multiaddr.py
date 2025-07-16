"""Re-export of the multiaddr library."""

from multiaddr import Multiaddr
from multiaddr.protocols import (
    P_TCP,
    P_IP4,
    P_IP6,
    P_DNS,
    P_UDP,
    P_P2P,
    Protocol
)

__all__ = [
    "Multiaddr", 
    "Protocol",
    "is_valid_address"
]

PROTOCOL_CONFIG = {
    P_IP4: {
        'transports': [P_TCP, P_UDP],
        'overlays': [P_P2P]
    },
    P_IP6: {
        'transports': [P_TCP, P_UDP],
        'overlays': [P_P2P]
    },
    P_DNS: {
        'transports': [P_TCP],
        'overlays': [P_P2P]
    }
}

def _generate_supported_protocols():
    """Generate all valid protocol combinations."""
    protocols = set()
    
    for network, config in PROTOCOL_CONFIG.items():
        for transport in config['transports']:

            base_combo = (network, transport)
            protocols.add(base_combo)
            
            for overlay in config['overlays']:
                protocols.add(base_combo + (overlay,))
    
    return protocols

SUPPORTED_PROTOCOLS = _generate_supported_protocols()

def is_valid_address(addr: Multiaddr) -> bool:
    """
    Check if a multiaddr uses only supported protocols.
    
    synlink network only supports a subset of multiaddr protocols.
    
    
    Example
    ```
    "/ip4/127.0.0.1/tcp/8080",
    "/ip6/::1/tcp/8080",
    "/dns/example.com/tcp/443/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
    ```
    """
    protocol_tuple = tuple(protocol.code for protocol in addr.protocols())
    return protocol_tuple in SUPPORTED_PROTOCOLS



