import hashlib
from functools import cached_property
from typing import Union

import base58
import multihash
from synlink.crypto.typing import PublicKey
from synlink.utils import _check_minimum_version

if _check_minimum_version(3, 11):
    from typing import Self
else:
    from typing_extensions import Self

class PeerId(object):
    def __init__(self, data: Union[bytes, bytearray]):
        if isinstance(data, (bytearray,)):
            self._id = bytes(data)
        elif isinstance(data, (bytes,)):
            self._id = data
        else:
            raise TypeError("only supported types; bytes, and bytearray(s).")
    @cached_property
    def xor_id(self) -> int:
        return int(sha256_digest(self._id).hex(), 16)
    @cached_property
    def base58(self) -> str:
        return base58.b58encode(self._id).decode()
    def to_base58(self) -> str:
        return self.base58
    @classmethod
    def from_base58(cls, b58_encoded_peer_id_str: str) -> Self:
        peer_id_bytes = base58.b58decode(b58_encoded_peer_id_str)
        pid = cls(peer_id_bytes)
        return pid
    @classmethod
    def from_bytes(cls, data: bytes):
        return cls(data)
    def to_bytes(self) -> bytes:
        return self._id
    @classmethod
    def from_pubkey(cls, key: PublicKey) -> Self:
        serialized_key = key.to_bytes()
        algo = multihash.Func.sha2_256
        mh_digest = multihash.digest(serialized_key, algo)
        return cls(mh_digest.encode())
    def __bytes__(self) -> bytes:
        return self.to_bytes()
    def __hash__(self):
        return hash(self._id)
    def __repr__(self):
        return f"<synlink.swarm.peer_id.PeerID {self.to_base58()}>"
    def __str__(self):
        return self.to_base58()
    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.to_base58() == other
        elif isinstance(other, bytes):
            return self._id == other
        elif isinstance(other, PeerId):
            return self._id == other._id
        else:
            raise ValueError("Unsupported type for PeerID comparison.")

def sha256_digest(data: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf8")
    return hashlib.sha256(data).digest()
