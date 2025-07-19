from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from synlink.crypto.kind import Kind
from synlink.utils import _check_minimum_version


if _check_minimum_version(3, 11):
    from typing import Self
else:
    from typing_extensions import Self

__all__ = ["Key", "PrivateKey", "PublicKey", "KeyPair"]

class Key(ABC):
    """A ``Key`` represents a cryptographic key."""

    _kind: Kind

    @abstractmethod
    def get_kind(self) -> Kind:
        return self._kind

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Returns the byte representation of this key."""
        ...

    @classmethod
    @abstractmethod
    def from_bytes(cls, data : bytes) -> Self:
        """Return instance of the class from bytes."""
        ...

    def __bytes__(self) -> bytes:
        return self.to_bytes()
    
    @abstractmethod
    def __str__(self):...

    @abstractmethod
    def __repr__(self):...

    def __eq__(self, other : "Key") ->bool:
        if isinstance(other, Key):
            return self.to_bytes() == other.to_bytes()
        else:
            raise NotImplemented
    




class PublicKey(Key):
    """Public key for signature verification"""

    _impl: Any
    _kind: Kind

    __slots__ = (
        "_impl",
        "_kind",
    )

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verify that ``signature`` is the cryptographic signature of the hash
        of ``data``.
        """
        ...


class PrivateKey(Key):
    """Private key for signing"""

    _impl: Any
    _kind: Kind

    __slots__ = (
        "_impl",
        "_kind",
    )

    @classmethod
    @abstractmethod
    def generate(cls) -> Self:
        """Generate private key."""
        ...

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """sign datawith private key."""
        ...

    @abstractmethod
    def get_public_key(self) -> PublicKey:
        """obtain refrence of the public key."""
        ...

@runtime_checkable
@dataclass(frozen=True)
class KeyPair(Protocol):
    """Immutable key pair containing public and private keys"""

    public: PublicKey
    seceret: PrivateKey

    def __bytes__(self) -> bytes:
        return bytes(self.seceret)
        
    
    
