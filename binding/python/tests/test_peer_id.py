import pytest
import hashlib
import base58

from unittest.mock import Mock
from synlink.peer_id import PeerId


@pytest.fixture
def sample_bytes():
    """Sample bytes data for testing"""
    return b"test_peer_id_data"


@pytest.fixture
def sample_bytearray():
    """Sample bytearray data for testing"""
    return bytearray(b"test_peer_id_data")


@pytest.fixture
def peer_id_from_bytes(sample_bytes):
    """Create a PeerId instance from bytes"""
    return PeerId(sample_bytes)


@pytest.fixture
def mock_public_key():
    """Mock PublicKey for testing"""
    mock_key = Mock()
    mock_key.to_bytes.return_value = b"mock_public_key_bytes"
    return mock_key


def test_peer_id_init_with_bytes(sample_bytes):
    """Test initialization with bytes"""
    peer_id = PeerId(sample_bytes)
    assert peer_id._id == sample_bytes


def test_peer_id_init_with_bytearray(sample_bytearray):
    """Test initialization with bytearray"""
    peer_id = PeerId(sample_bytearray)
    assert peer_id._id == bytes(sample_bytearray)
    assert isinstance(peer_id._id, bytes)


def test_peer_id_init_with_invalid_string():
    """Test initialization with invalid string raises TypeError"""
    with pytest.raises(
        TypeError, match="only supported types; bytes, and bytearray"
    ):
        PeerId("invalid_string")


def test_peer_id_init_with_invalid_int():
    """Test initialization with invalid int raises TypeError"""
    with pytest.raises(TypeError):
        PeerId(123)


def test_peer_id_init_with_invalid_list():
    """Test initialization with invalid list raises TypeError"""
    with pytest.raises(TypeError):
        PeerId([1, 2, 3])


# Property tests
def test_peer_id_xor_id_property(peer_id_from_bytes, sample_bytes):
    """Test xor_id cached property"""
    expected_digest = hashlib.sha256(sample_bytes).digest()
    expected_xor_id = int(expected_digest.hex(), 16)

    assert peer_id_from_bytes.xor_id == expected_xor_id


def test_peer_id_xor_id_is_cached(peer_id_from_bytes):
    """Test that xor_id is cached (accessing twice should return same object)"""
    xor_id1 = peer_id_from_bytes.xor_id
    xor_id2 = peer_id_from_bytes.xor_id
    assert xor_id1 is xor_id2


def test_peer_id_base58_property(peer_id_from_bytes, sample_bytes):
    """Test base58 cached property"""
    expected_base58 = base58.b58encode(sample_bytes).decode()
    assert peer_id_from_bytes.base58 == expected_base58


def test_peer_id_base58_is_cached(peer_id_from_bytes):
    """Test that base58 is cached (accessing twice should return same object)"""
    base58_1 = peer_id_from_bytes.base58
    base58_2 = peer_id_from_bytes.base58
    assert base58_1 is base58_2


def test_peer_id_to_base58(peer_id_from_bytes):
    """Test to_base58 method returns same as base58 property"""
    assert peer_id_from_bytes.to_base58() == peer_id_from_bytes.base58


def test_peer_id_from_base58_classmethod(sample_bytes):
    """Test from_base58 class method"""
    original_peer_id = PeerId(sample_bytes)
    base58_str = original_peer_id.to_base58()

    reconstructed_peer_id = PeerId.from_base58(base58_str)

    assert reconstructed_peer_id._id == sample_bytes
    assert reconstructed_peer_id == original_peer_id


def test_peer_id_from_base58_with_invalid_string():
    """Test from_base58 with invalid base58 string raises exception"""
    with pytest.raises(Exception):  # base58.b58decode raises various exceptions
        PeerId.from_base58("invalid_base58_string_with_0_and_O")


def test_peer_id_from_bytes_classmethod(sample_bytes):
    """Test from_bytes class method"""
    peer_id = PeerId.from_bytes(sample_bytes)
    assert peer_id._id == sample_bytes


def test_peer_id_to_bytes(peer_id_from_bytes, sample_bytes):
    """Test to_bytes method"""
    assert peer_id_from_bytes.to_bytes() == sample_bytes


def test_peer_id_bytes_dunder_method(peer_id_from_bytes, sample_bytes):
    """Test __bytes__ dunder method"""
    assert bytes(peer_id_from_bytes) == sample_bytes


def test_peer_id_hash_dunder_method(sample_bytes):
    """Test __hash__ dunder method"""
    peer_id1 = PeerId(sample_bytes)
    peer_id2 = PeerId(sample_bytes)

    assert hash(peer_id1) == hash(peer_id2)


def test_peer_id_hash_allows_set_usage(sample_bytes):
    """Test that __hash__ allows PeerId to be used in sets"""
    peer_id1 = PeerId(sample_bytes)
    peer_id2 = PeerId(sample_bytes)

    peer_id_set = {peer_id1, peer_id2}
    assert len(peer_id_set) == 1


def test_peer_id_repr_dunder_method(peer_id_from_bytes):
    """Test __repr__ dunder method"""
    repr_str = repr(peer_id_from_bytes)
    expected = (
        f"<synlink.swarm.peer_id.PeerID {peer_id_from_bytes.to_base58()}>"
    )
    assert repr_str == expected


def test_peer_id_str_dunder_method(peer_id_from_bytes):
    """Test __str__ dunder method"""
    assert str(peer_id_from_bytes) == peer_id_from_bytes.to_base58()


def test_peer_id_eq_with_string(peer_id_from_bytes):
    """Test __eq__ with string comparison"""
    base58_str = peer_id_from_bytes.to_base58()
    assert peer_id_from_bytes == base58_str


def test_peer_id_eq_with_different_string(peer_id_from_bytes):
    """Test __eq__ with different string returns False"""
    assert not (peer_id_from_bytes == "different_string")


def test_peer_id_eq_with_bytes(peer_id_from_bytes, sample_bytes):
    """Test __eq__ with bytes comparison"""
    assert peer_id_from_bytes == sample_bytes


def test_peer_id_eq_with_different_bytes(peer_id_from_bytes):
    """Test __eq__ with different bytes returns False"""
    assert not (peer_id_from_bytes == b"different_bytes")


def test_peer_id_eq_with_same_peer_id(sample_bytes):
    """Test __eq__ with same PeerId data returns True"""
    peer_id1 = PeerId(sample_bytes)
    peer_id2 = PeerId(sample_bytes)
    assert peer_id1 == peer_id2


def test_peer_id_eq_with_different_peer_id(sample_bytes):
    """Test __eq__ with different PeerId data returns False"""
    peer_id1 = PeerId(sample_bytes)
    peer_id2 = PeerId(b"different_data")
    assert not (peer_id1 == peer_id2)


def test_peer_id_eq_with_unsupported_int():
    """Test __eq__ with unsupported int type raises ValueError"""
    peer_id = PeerId(b"test_data")
    with pytest.raises(
        ValueError, match="Unsupported type for PeerID comparison"
    ):
        peer_id == 123


def test_peer_id_eq_with_unsupported_list():
    """Test __eq__ with unsupported list type raises ValueError"""
    peer_id = PeerId(b"test_data")
    with pytest.raises(ValueError):
        peer_id == [1, 2, 3]


def test_peer_id_different_input_types_same_data():
    """Test that bytes and bytearray with same data create equal PeerIds"""
    data_bytes = b"same_data"
    data_bytearray = bytearray(b"same_data")

    peer_id1 = PeerId(data_bytes)
    peer_id2 = PeerId(data_bytearray)

    assert peer_id1 == peer_id2
    assert peer_id1.to_base58() == peer_id2.to_base58()
    assert peer_id1.xor_id == peer_id2.xor_id


def test_peer_id_properties_consistency():
    """Test that all string representations are consistent"""
    peer_id = PeerId(b"consistency_test")

    # All these should return the same value
    base58_from_property = peer_id.base58
    base58_from_method = peer_id.to_base58()
    base58_from_str = str(peer_id)

    assert base58_from_property == base58_from_method
    assert base58_from_method == base58_from_str
    assert base58_from_property == base58_from_str
