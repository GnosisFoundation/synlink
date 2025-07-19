from dataclasses import dataclass
from typing import Optional, Tuple

import nacl.utils as utils
from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey as ImplPrivateKey

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from synlink.crypto.exception import CryptoException
from synlink.crypto.kind import Kind
from synlink.crypto.typing import PrivateKey as IPrivateKey
from synlink.crypto.typing import PublicKey as IPublicKey
from synlink.utils import _check_minimum_version

# Type hint for python lower then 3.11
if _check_minimum_version(3, 11, 0):
    from typing import Self
else:
    from typing_extensions import Self


__all__ = ["PublicKey", "PrivateKey", "KeyPair", "create_new_ed25519_key_pair",
           "create_new_ed25519_key_pair_from_seed"]


class PublicKey(IPublicKey):
    """
    Represents an ED25519 public key, providing methods for verification
    and various conversions. This class wraps nacl.signing.VerifyKey.
    """
    def __init__(self, impl: VerifyKey):
        """
        Initializes a PublicKey object.

        Args:
            impl: An instance of nacl.signing.VerifyKey.
        """
        super().__init__()
        self._impl: VerifyKey = impl
        self._kind = Kind.ED25519

    def get_kind(self) -> Kind:
        """
        Returns the kind of this cryptographic key.
        """
        return self._kind

    def to_bytes(self) -> bytes:
        """
        Converts the public key to its raw byte representation.
        """
        return bytes(self._impl)

    def __bytes__(self) -> bytes:
        """
        Allows the PublicKey object to be converted to bytes using bytes().
        """
        return self.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """
        Creates a PublicKey object from its raw byte representation.

        Args:
            data: The raw bytes of the public key (VerifyKey).

        Returns:
            A new PublicKey instance.
        """
        return cls(VerifyKey(data))

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verifies the signature against the signed message.

        Args:
            data: The original message bytes that were signed.
            signature: The raw signature bytes.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            # Direct verification using the wrapped VerifyKey
            self._impl.verify(data, signature)
            return True
        except BadSignatureError:
            return False
        except Exception as e:
            # Catch other potential exceptions during verification
            # print(f"An unexpected error occurred during verification: {e}") # For debugging
            return False


    def __str__(self) -> str:
        """
        Returns a human-readable string representation of the public key.
        """
        output = self._impl \
                     .encode(encoder=HexEncoder()) \
                     .decode('utf-8')
        return f"PublicKey({output})"

    def __repr__(self) -> str:
        """
        Returns a detailed string representation for debugging.
        """
        output = self._impl.encode(encoder=HexEncoder()).decode('utf-8')
        # Show a truncated hex representation for brevity in repr
        return f"<synlink.crypto.ed25519.PublicKey {output[:8]}...{output[-8:]}>"


class PrivateKey(IPrivateKey):
    """
    Represents an ED25519 private key, providing methods for signing
    and various conversions. This class wraps nacl.signing.SigningKey.
    """
    def __init__(self, impl: SigningKey):
        """
        Initializes a PrivateKey object.

        Args:
            impl: An instance of nacl.signing.SigningKey.
        """
        super().__init__()
        self._kind = Kind.ED25519
        self._impl: SigningKey = impl

    def get_kind(self) -> Kind:
        """
        Returns the kind of this cryptographic key.
        """
        return self._kind

    @classmethod
    def generate(cls) -> Self:
        """
        Generates a new random ED25519 private key.

        Returns:
            A new PrivateKey instance.
        """
        impl = SigningKey.generate()
        return cls(impl)

    @classmethod
    def from_seed(cls, seed: Optional[bytes] = None) -> Self:
        """
        Generates an ED25519 private key from a 32-byte seed.

        If no seed is provided, a random 32-byte seed will be generated.

        Args:
            seed: An optional 32-byte binary sequence to use as a seed.

        Returns:
            A new PrivateKey instance.

        Raises:
            AssertionError: If the provided seed is not 32 bytes long.
        """
        if seed is None:
            # Ensure random seed is exactly 32 bytes
            seed = utils.random(32)
        assert (
            len(seed) == 32
        ), "PrivateKey seed must be a 32 bytes long binary sequence"
        impl = ImplPrivateKey.from_seed(seed)
        return cls(SigningKey(bytes(impl)))

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """
        Creates an ED25519 private key from its raw byte representation.

        Args:
            data: The raw bytes of the private key (SigningKey).

        Returns:
            A new PrivateKey instance.
        """
        impl = SigningKey(data)
        return cls(impl)

    def get_public_key(self) -> IPublicKey:
        """
        Returns the public key corresponding to this private key.
        """
        if not isinstance(self._impl, SigningKey):
            # Defensive check, though __init__ should ensure correct type.
            raise CryptoException("Invalid private key implementation.")
        # Return a PublicKey wrapping the VerifyKey derived from this SigningKey
        return PublicKey(self._impl.verify_key)

    def sign(self, data: bytes) -> bytes:
        """
        Signs data with the private key and returns the raw signature.

        Args:
            data: The message bytes to sign.

        Returns:
            The raw signature bytes.
        """
        if not isinstance(self._impl, SigningKey):
            raise CryptoException("Invalid private key implementation.")
        # Direct signing using the wrapped SigningKey
        signed_message = self._impl.sign(data)
        return signed_message.message, signed_message.signature # Return only the raw signature bytes

    def to_bytes(self) -> bytes:
        """
        Converts the private key to its raw byte representation.
        """
        return bytes(self._impl)

    def __bytes__(self) -> bytes:
        """
        Allows the PrivateKey object to be converted to bytes using bytes().
        """
        return self.to_bytes()

    def __str__(self) -> str:
        """
        Returns a human-readable string representation of the private key.
        """
        # For security, avoid showing private key material in str.
        return "PrivateKey(ED25519)"

    def __repr__(self) -> str:
        """
        Returns a detailed string representation for debugging.
        """
        # For security, avoid showing private key material in repr.
        return "<synlink.crypto.ed25519.PrivateKey>"


@dataclass(frozen=True, repr=False)
class KeyPair(object):
    """
    Represents an ED25519 key pair, containing both a private and public key.
    """
    secret : PrivateKey
    public  : PublicKey

    def __bytes__(self) -> bytes:
        """
        Returns the raw bytes of the secret (private) key.
        """
        return bytes(self.secret)

    def __repr__(self) -> str:
        """
        Returns a detailed string representation for debugging.
        """
        # Include the public key's repr for better context
        return f"<synlink.crypto.ed25519.KeyPair public={self.public!r}>"


def create_new_ed25519_key_pair() -> KeyPair:
    """
    Creates a new ED25519 key pair with randomly generated keys.

    Returns:
        A new KeyPair instance.
    """
    secret = PrivateKey.generate()
    public = secret.get_public_key()
    return KeyPair(secret, public)


def create_new_ed25519_key_pair_from_seed(seed: Optional[bytes] = None) -> KeyPair:
    """
    Creates a new ED25519 key pair from an optional 32-byte seed.

    If no seed is provided, a random 32-byte seed will be generated.

    Args:
        seed: An optional 32-byte binary sequence to use as a seed.

    Returns:
        A new KeyPair instance.
    """
    secret: PrivateKey = PrivateKey.from_seed(seed)
    public = secret.get_public_key()
    return KeyPair(secret, public)
