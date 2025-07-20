import os

from typing import Union, Optional, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    ed25519 as ED25519,
)

import synlink.crypto.ed25519 as ed25519
from synlink.crypto.typing import KeyPair
from synlink.utils import HOME_DIR

SSH_DEFAULT_DIRECTORY: Final[str] = os.path.join(HOME_DIR, ".ssh")


def load_ssh_private_key(
    file: Union[str, os.PathLike] = SSH_DEFAULT_DIRECTORY,
    password: Optional[Union[str, bytes]] = None,
) -> KeyPair:
    """Load private key from OpenSSL custom encoding, and reconstruct
    key pair.

    Args:
        ssh_dir: Path to SSH directory (default: ~/.ssh)
        key_name: Base name of key files (default: id_rsa)

    Returns:
        KeyPair containing the loaded public and private keys

    Raises:
        FileNotFoundError: If key files don't exist
        ValueError: If keys are malformed or incompatible
        NotImplemented: If other then ed25519
    Example:
        >>> keypair = load_ssh_private_key(key_name="~/.ssh/synlink_ed25519")
    """
    if isinstance(password, str):
        password = password.encode()

    with open(
        file,
        "r+b",
    ) as reader:
        buffer = serialization.load_ssh_private_key(
            reader.read(-1),
            password=password,
        )

        if isinstance(buffer, ED25519.Ed25519PrivateKey):
            secret = ed25519.PrivateKey.from_bytes(buffer.private_bytes_raw())
            public = secret.get_public_key()
            return ed25519.KeyPair(secret=secret, public=public)
        else:
            raise NotImplementedError("key type is not implmented.")
