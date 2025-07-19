
import os
import pathlib

from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    ed25519 as ED25519, 
)

import synlink.crypto.ed25519 as ed25519
from synlink.crypto.typing import PrivateKey, KeyPair



from typing import Optional

HOME_DIR : str = pathlib.Path.home().__str__()
SSH_DEFAULT_DIRECTORY = os.path.join(HOME_DIR, ".ssh")

def load_ssh_private_key(
        ssh_dir: Union[str, os.PathLike] = SSH_DEFAULT_DIRECTORY, 
        key_name: str = "id_ed25519", 
        password : Optional[str] = None,
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
        >>> keypair = load_ssh_keys(key_name="id_ed25519")
    """
    file = os.path.join(ssh_dir, key_name)
    with open(
        file,
        "rb",
    ) as reader:
        buffer = serialization.load_ssh_private_key(
            reader.read(-1),
            password=password,
        )

        if isinstance(buffer, ED25519.Ed25519PrivateKey):
            secret = ed25519.PrivateKey.from_bytes(
                buffer.private_bytes_raw()    
            )
            public = secret.get_public_key()
            return ed25519.KeyPair(secret=secret, public=public)
        else:
            raise NotImplemented
