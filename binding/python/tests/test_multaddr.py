
from typing import Callable, List, Final
from synlink.multiaddr import Multiaddr, is_valid_address

ALL_VALID : Final[Callable[[List[Multiaddr]], bool]] = lambda expected : all(map(lambda x : is_valid_address(x), expected))
ASSERT_ALL_VALID_MESSAGE : Final[str] = "The expected address should be valid synlink address."

def test_valid_synlink_multiaddr_ip():
    """synlink supports ip4/6 addressing."""
    ip4_tcp = Multiaddr("/ip4/0.0.0.0/tcp/0")
    ip6_tcp = Multiaddr("/ip6/::1/tcp/0")
    
    expected = [ip4_tcp, ip6_tcp]

    assert ALL_VALID(expected), ASSERT_ALL_VALID_MESSAGE


def test_valid_synlink_multiaddr_udp():
    """synlink supports tcp/udp packets."""
    ip4_udp = Multiaddr("/ip4/0.0.0.0/udp/0")
    ip6_udp = Multiaddr("/ip6/::1/udp/0")
    
    expected = [ip4_udp, ip6_udp] 

    assert ALL_VALID(expected), ASSERT_ALL_VALID_MESSAGE

def test_valid_synlink_multiaddr_p2p():
    """synlink supports p2p look ups."""
    
    ip4_udp = Multiaddr("/ip4/0.0.0.0/udp/0/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
    ip6_udp = Multiaddr("/ip6/::1/udp/0/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")

    ip4_tcp = Multiaddr("/ip4/0.0.0.0/tcp/0/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
    ip6_tcp = Multiaddr("/ip6/::1/tcp/0/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")

    expected = [ip4_udp, ip6_udp, ip4_tcp, ip6_tcp]

    assert ALL_VALID(expected), ASSERT_ALL_VALID_MESSAGE
    

def test_valid_synlink_multiaddr_p2p_str():
    """synlink supports p2p look ups."""
    
    ip4_udp = "/ip4/0.0.0.0/udp/0/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
    ip6_udp = "/ip6/::1/udp/0/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"

    ip4_tcp = "/ip4/0.0.0.0/tcp/0/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
    ip6_tcp = "/ip6/::1/tcp/0/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"

    expected = [ip4_udp, ip6_udp, ip4_tcp, ip6_tcp]

    assert ALL_VALID(expected), ASSERT_ALL_VALID_MESSAGE
