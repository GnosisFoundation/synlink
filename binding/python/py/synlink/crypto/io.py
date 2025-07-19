
import os
import pathlib
from cryptography.hazmat.primitives import serialization
from synlink.crypto.typing import KeyPair, PrivateKey

from typing import Optional

HOME_DIR : str = pathlib.Path.home().__str__()
SSH_DEFAULT_DIRECTORY = os.path.join(HOME_DIR, ".ssh")

def load_ssh_keys(ssh_dir: str = SSH_DEFAULT_DIRECTORY, key_name: str = "id_ed25519", password : Optional[str] = None) -> KeyPair:
    """Load SSH key pair from filesystem.
    
    Args:
        ssh_dir: Path to SSH directory (default: ~/.ssh)
        key_name: Base name of key files (default: id_rsa)
        
    Returns:
        KeyPair containing the loaded public and private keys
        
    Raises:
        FileNotFoundError: If key files don't exist
        ValueError: If keys are malformed or incompatible
        
    Example:
        >>> keypair = load_ssh_keys(key_name="id_ed25519")
    """
    file = os.path.join(ssh_dir, key_name),
    if not os.path.isfile(file):
        raise FileNotFoundError(f"{file} does not exist.")

    with open(
        file,
        "rb",
    ) as reader:
        buffer = serialization.load_ssh_private_key(
            reader.read(-1),
            password=password,
        )
        

        seceret : PrivateKey = PrivateKey.from_bytes(
            buffer.private_bytes_raw()    
        )

        public = seceret.get_public_key()
        return KeyPair(seceret=seceret, public=public)

