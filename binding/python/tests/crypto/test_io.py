import pytest
import tempfile

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from synlink.crypto.io import load_ssh_private_key



def _create_tempfile(buffer : bytes) -> tempfile._TemporaryFileWrapper:
        """create a test ssh-keygen tempory file."""
        file = tempfile.NamedTemporaryFile()
        try:
            _ = file.write(buffer)
            _ = file.flush()
        except Exception as e:
            file.close()
            raise

        return file


@pytest.fixture
def file_buffer() -> tempfile._TemporaryFileWrapper:
    """Generate a OpenSSH key."""
    # Generate ed25519 private key. 
    private_key = ed25519.Ed25519PrivateKey.generate()
    buffer = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.BestAvailableEncryption(
            b"hello-world"
        )
    )

    return _create_tempfile(buffer)

@pytest.fixture
def invalid_file_buffer() -> tempfile._TemporaryFileWrapper:
    # Generate ed25519 private key. 
    private_key = ed25519.Ed25519PrivateKey.generate()
    buffer = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    return _create_tempfile(buffer)



def test_io_read_ssh_file(file_buffer : tempfile._TemporaryFileWrapper):
    try:
        _ = file_buffer
        _keypair = load_ssh_private_key(
            _.name,
            password="hello-world"
        )
    # finally close the file
    finally:
        _.close()



def test_io_invalid_read_ssh_file(invalid_file_buffer : tempfile._TemporaryFileWrapper):
    _ = invalid_file_buffer
    
    with pytest.raises(Exception): 
        _keypair = load_ssh_private_key(
            _.name,
            password="hello-world"
        )

    _.close()


def test_io_invalid_key_read_ssh_file(file_buffer : tempfile._TemporaryFileWrapper):
    _ = file_buffer
    
    with pytest.raises(Exception): 
        _keypair = load_ssh_private_key(
            _.name,
            password="hello"
        )
        
    _.close()
