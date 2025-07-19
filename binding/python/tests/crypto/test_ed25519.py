import pytest
import nacl.utils
from synlink.crypto.ed25519 import (
    PublicKey, 
    PrivateKey, 
    KeyPair,
    create_new_ed25519_key_pair,
    create_new_ed25519_key_pair_from_seed
)
from synlink.crypto.kind import Kind


# Fixtures for reusable test data
@pytest.fixture
def sample_keypair():
    """Fixture providing a sample keypair for tests."""
    return create_new_ed25519_key_pair()


@pytest.fixture
def sample_seed():
    """Fixture providing a sample 32-byte seed."""
    return b"test_seed_32_bytes_long_exactly_"


@pytest.fixture
def test_message():
    """Fixture providing a test message."""
    return b"hello world test message"


# Private Key Tests
def test_private_key_generation():
    """Test that private key generation produces valid keys."""
    key = PrivateKey.generate()
    
    assert isinstance(key, PrivateKey)
    assert key.get_kind() == Kind.ED25519
    assert len(key.to_bytes()) == 32  # ED25519 private key is 32 bytes


def test_private_key_from_seed():
    """Test private key generation from seed."""
    seed = nacl.utils.random(32)
    key = PrivateKey.from_seed(seed)
    
    assert isinstance(key, PrivateKey)
    assert key.get_kind() == Kind.ED25519
    assert len(key.to_bytes()) == 32


def test_private_key_from_seed_deterministic():
    """Test that same seed produces same private key."""
    seed = b"a" * 32  # 32-byte seed
    key1 = PrivateKey.from_seed(seed)
    key2 = PrivateKey.from_seed(seed)
    
    assert key1.to_bytes() == key2.to_bytes()


def test_private_key_from_seed_invalid_length():
    """Test that invalid seed length raises assertion error."""
    with pytest.raises(AssertionError, match="32 bytes long"):
        PrivateKey.from_seed(b"short")


def test_private_key_from_bytes():
    """Test private key creation from arbitrary bytes."""
    data = nacl.utils.random(32)
    key = PrivateKey.from_bytes(data)
    
    assert isinstance(key, PrivateKey)
    assert key.get_kind() == Kind.ED25519
    assert key.to_bytes() == data


def test_private_key_get_public_key():
    """Test that private key can derive its public key."""
    private_key = PrivateKey.generate()
    public_key = private_key.get_public_key()
    
    assert isinstance(public_key, PublicKey)
    assert public_key.get_kind() == Kind.ED25519
    assert len(public_key.to_bytes()) == 32  # ED25519 public key is 32 bytes


def test_private_key_signing():
    """Test that private key can sign data."""
    private_key = PrivateKey.generate()
    message = b"test message to sign"
    
    (_, signature) = private_key.sign(message)
    
    assert isinstance(signature, bytes)
    assert len(signature) == 64  # ED25519 signature is 64 bytes


def test_private_key_bytes_conversion():
    """Test private key bytes conversion."""
    key = PrivateKey.generate()
    key_bytes = key.to_bytes()
    
    assert isinstance(key_bytes, bytes)
    assert len(key_bytes) == 32
    assert bytes(key) == key_bytes


def test_private_key_string_representation():
    """Test private key string representations."""
    key = PrivateKey.generate()
    
    str_repr = str(key)
    repr_repr = repr(key)
    
    assert str_repr == "PrivateKey(ED25519)"
    assert repr_repr == "<synlink.crypto.ed25519.PrivateKey>"


def test_private_key_none_seed_handling():
    """Test that None seed generates random key."""
    key1 = PrivateKey.from_seed(None)
    key2 = PrivateKey.from_seed(None)
    
    # Should be different keys since they're random
    assert key1.to_bytes() != key2.to_bytes()


# Public Key Tests
def test_public_key_from_private():
    """Test public key derivation from private key."""
    private_key = PrivateKey.generate()
    public_key = private_key.get_public_key()
    
    assert isinstance(public_key, PublicKey)
    assert public_key.get_kind() == Kind.ED25519


def test_public_key_from_bytes():
    """Test public key creation from bytes."""
    private_key = PrivateKey.generate()
    public_key = private_key.get_public_key()
    public_bytes = public_key.to_bytes()
    
    reconstructed = PublicKey.from_bytes(public_bytes)
    
    assert isinstance(reconstructed, PublicKey)
    assert reconstructed.to_bytes() == public_bytes


def test_public_key_verification_valid():
    """Test signature verification with valid signature."""
    keypair = create_new_ed25519_key_pair()
    message = b"hello world"
    (_, signature) = keypair.secret.sign(message)
    try:
        assert keypair.public.verify(message, signature)
    except Exception as e:
        raise e


def test_public_key_verification_invalid_signature():
    """Test signature verification with invalid signature."""
    keypair = create_new_ed25519_key_pair()
    message = b"hello world"
    
    # Create invalid signature
    invalid_signature = b"x" * 64
    is_valid = keypair.public.verify(message, invalid_signature)
    
    assert is_valid is False


def test_public_key_verification_wrong_message():
    """Test signature verification with wrong message."""
    keypair = create_new_ed25519_key_pair()
    original_message = b"original message"
    different_message = b"different message"
    
    signature = keypair.secret.sign(original_message)
    is_valid = keypair.public.verify(different_message, signature)
    
    assert is_valid is False


def test_public_key_verification_wrong_key():
    """Test signature verification with wrong public key."""
    keypair = create_new_ed25519_key_pair()
    keypair2 = create_new_ed25519_key_pair()
    public_key2 = keypair2.public
    message = b"test message"
    
    signature = keypair.secret.sign(message)
    is_valid = public_key2.verify(message, signature)
    
    assert is_valid is False


def test_public_key_bytes_conversion():
    """Test public key bytes conversion."""
    private_key = PrivateKey.generate()
    public_key = private_key.get_public_key()
    public_bytes = public_key.to_bytes()
    
    assert isinstance(public_bytes, bytes)
    assert len(public_bytes) == 32
    assert bytes(public_key) == public_bytes


def test_public_key_string_representations():
    """Test public key string representations."""
    private_key = PrivateKey.generate()
    public_key = private_key.get_public_key()
    
    str_repr = str(public_key)
    repr_repr = repr(public_key)
    
    assert str_repr.startswith("PublicKey(")
    assert str_repr.endswith(")")
    assert repr_repr.startswith("<synlink.crypto.ed25519.PublicKey")


# KeyPair Tests
def test_keypair_creation():
    """Test keypair creation and basic properties."""
    keypair = create_new_ed25519_key_pair()
    
    assert isinstance(keypair, KeyPair)
    assert isinstance(keypair.secret, PrivateKey)  # Note: keeping original typo
    assert isinstance(keypair.public, PublicKey)


def test_keypair_from_seed():
    """Test keypair creation from seed."""
    seed = nacl.utils.random(32)
    keypair = create_new_ed25519_key_pair_from_seed(seed)
    
    assert isinstance(keypair, KeyPair)
    assert isinstance(keypair.secret, PrivateKey)
    assert isinstance(keypair.public, PublicKey)


def test_keypair_deterministic_from_seed():
    """Test that same seed produces same keypair."""
    seed = b"\x00" * 32  # 32 bytes
    keypair1 = create_new_ed25519_key_pair_from_seed(seed)
    keypair2 = create_new_ed25519_key_pair_from_seed(seed)
    
    assert keypair1.secret.to_bytes() == keypair2.secret.to_bytes()
    assert keypair1.public.to_bytes() == keypair2.public.to_bytes()


def test_keypair_private_public_match():
    """Test that keypair's private and public keys match."""
    keypair = create_new_ed25519_key_pair()
    derived_public = keypair.secret.get_public_key()
    
    assert keypair.public.to_bytes() == derived_public.to_bytes()


def test_keypair_sign_verify_cycle():
    """Test complete sign/verify cycle with keypair."""
    keypair = create_new_ed25519_key_pair()
    message = b"test message for signing"
    
    (_, signature) = keypair.secret.sign(message)
    is_valid = keypair.public.verify(message, signature)
    
    assert is_valid is True


def test_keypair_bytes_conversion():
    """Test keypair bytes conversion (should return private key bytes)."""
    keypair = create_new_ed25519_key_pair()
    keypair_bytes = bytes(keypair)
    private_bytes = keypair.secret.to_bytes()
    
    assert keypair_bytes == private_bytes


def test_keypair_immutability():
    """Test that keypair is immutable (frozen dataclass)."""
    keypair = create_new_ed25519_key_pair()
    
    with pytest.raises(Exception):  # Should be FrozenInstanceError
        keypair.secret = PrivateKey.generate()


# Serialization Tests
def test_serialization_round_trip_private():
    """Test private key serialization round trip."""
    original = PrivateKey.generate()
    serialized = original.to_bytes()
    deserialized = PrivateKey.from_bytes(serialized)
    
    assert original.to_bytes() == deserialized.to_bytes()


def test_serialization_round_trip_public():
    """Test public key serialization round trip."""
    private_key = PrivateKey.generate()
    original = private_key.get_public_key()
    serialized = original.to_bytes()
    deserialized = PublicKey.from_bytes(serialized)
    
    assert original.to_bytes() == deserialized.to_bytes()


# Cross-compatibility Tests
def test_multiple_signatures_same_key():
    """Test multiple signatures with the same key."""
    keypair = create_new_ed25519_key_pair()
    messages = [b"message1", b"message2", b"message3"]
    
    signatures = [keypair.secret.sign(msg) for msg in messages]
    
    # All signatures should be valid for their respective messages
    for msg, (_, sig) in zip(messages, signatures):
        assert keypair.public.verify(msg, sig) is True
    
    # Cross-verification should fail
    assert keypair.public.verify(messages[0], signatures[1][1]) is False


def test_empty_message_signing():
    """Test signing empty message."""
    private_key = PrivateKey.generate()
    public_key = private_key.get_public_key()
    empty_message = b""
    
    (_, signature) = private_key.sign(empty_message)
    is_valid = public_key.verify(empty_message, signature)
    
    assert is_valid is True


def test_large_message_signing():
    """Test signing large message."""
    keypair = create_new_ed25519_key_pair()
    large_message = b"x" * 10000  # 10KB message
    
    (_, signature) = keypair.secret.sign(large_message)
    is_valid = keypair.public.verify(large_message, signature)
    
    assert is_valid is True


# Parametrized Tests
@pytest.mark.parametrize("message", [
    b"hello world",
    b"",
    b"\x00\x01\x02\xff",
    "unicode message: 你好世界".encode('utf-8'),
    b"x" * 1000,
])
def test_various_message_types(message):
    """Test signing and verification with various message types."""
    private_key = PrivateKey.generate()
    public_key = private_key.get_public_key()
    
    (_, signature) = private_key.sign(message)
    is_valid = public_key.verify(message, signature)
    
    assert is_valid is True


@pytest.mark.parametrize("invalid_seed", [
    b"short",
    b"x" * 31,  # Too short
    b"x" * 33,  # Too long
])
def test_invalid_seed_lengths(invalid_seed):
    """Test various invalid seed lengths."""
    with pytest.raises(AssertionError):
        PrivateKey.from_seed(invalid_seed)


# Fixture Usage Tests
def test_fixture_keypair_usage(sample_keypair):
    """Test using keypair fixture."""
    assert isinstance(sample_keypair, KeyPair)
    assert isinstance(sample_keypair.secret, PrivateKey)
    assert isinstance(sample_keypair.public, PublicKey)


def test_fixture_seed_usage(sample_seed):
    """Test using seed fixture."""
    assert len(sample_seed) == 32
    keypair = create_new_ed25519_key_pair_from_seed(sample_seed)
    assert isinstance(keypair, KeyPair)


def test_deterministic_generation_with_fixture(sample_seed):
    """Test deterministic generation with seed fixture."""
    keypair1 = create_new_ed25519_key_pair_from_seed(sample_seed)
    keypair2 = create_new_ed25519_key_pair_from_seed(sample_seed)
    
    assert keypair1.secret.to_bytes() == keypair2.secret.to_bytes()
    assert keypair1.public.to_bytes() == keypair2.public.to_bytes()
