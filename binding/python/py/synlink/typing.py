from typing import NewType, Protocol, runtime_checkable

from .utils import _check_minimum_version

if _check_minimum_version(3, 11):
    from typing import Self
else:
    from typing_extensions import Self

__all__ = ["TProtocol"]


@runtime_checkable
class Serializable(Protocol):
    """
    Such protocol can be used to check if an object can be translated
    and format into a bit repersentation

    Example:
    ```
    from synlink.crypto import PrivateKey, PublicKey, create_new_key_pair

    keypair : Keypair = create_new_key_pair()
    assert not isinstance(keypair.seceret, Serializable), "seceret key should be able to serializable."
    assert not isinstance(keypair.public, Serializable), "public key should be able to serializable."

    layout : bytes = keypair.to_bytes()
    del keypair
    ```
    """

    def to_bytes(self) -> bytes:
        """serialize the object into bytes."""
        ...

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """deserialize the object from bytes."""
        ...


TProtocol = NewType("TProtocol", str)
