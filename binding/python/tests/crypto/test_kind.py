import pytest
from synlink.crypto.kind import Kind

def test_kind_from_bytes():
    data = b"\x00"

    kind = Kind.from_bytes(data)
    assert Kind.ED25519 == kind


def test_kind_from_bytes_exception():
    data = b"\x01"

    with pytest.raises(ValueError):
        _ = Kind.from_bytes(data)


def test_kind_from_unbound_bytes_exception():
    with pytest.raises(ValueError):
        _ = Kind.from_bytes([-1])

def test_kind_max_min():
    assert Kind.max() == 0
    assert Kind.min() == 0

def test_kind_to_bytes():
    kind = Kind.ED25519
    assert kind.to_bytes() == b"\x00"