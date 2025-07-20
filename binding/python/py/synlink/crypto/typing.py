from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Tuple

from synlink.crypto.kind import Kind
from synlink.utils import _check_minimum_version

if _check_minimum_version(3, 11):
    from typing import Self
else:
    from typing_extensions import Self

__all__ = ["Key", "PrivateKey", "PublicKey", "KeyPair", "Message", "Signiture"]

Message = bytes
Signiture = bytes


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
    def from_bytes(cls, data: bytes) -> Self:
        """Return instance of the class from bytes."""
        ...

    def __bytes__(self) -> bytes:
        return self.to_bytes()


class PublicKey(Key):
    """Public key for signature verification"""

    _impl: Any
    _kind: Kind

    __slots__ = (
        "_impl",
        "_kind",
    )

    def __init__(self, _impl: Any):
        ...

    @abstractmethod
    def try_verify(self, data: bytes, signature: bytes) -> bool:
        """
        Attempts to verify the signature against the signed message.

        Args:
            data: The original message bytes that were signed.
            signature: The raw signature bytes.

        Returns:
            True if the signature is valid.

        Raises:
            SignatureVerificationError: If the signature is forged or corrupt.
            CryptoBaseException: For other unexpected verification errors.
        """
        ...

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Creates a PublicKey object from its raw byte representation.

        Args:
            data: The raw bytes of the public key (VerifyKey).

        Returns:
            A new PublicKey instance.
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

    def __init__(self, _impl: Any):
        ...

    @classmethod
    @abstractmethod
    def generate(cls) -> Self:
        """Generate private key."""
        ...

    @abstractmethod
    def sign(self, data: bytes) -> Tuple[Message, Signiture]:
        """sign datawith private key."""
        ...

    @abstractmethod
    def get_public_key(self) -> PublicKey:
        """obtain refrence of the public key."""
        ...


@dataclass(frozen=True)
class KeyPair:
    """Immutable key pair containing public and private keys"""

    public: PublicKey
    secret: PrivateKey

    def __bytes__(self) -> bytes:
        return bytes(self.secret)
