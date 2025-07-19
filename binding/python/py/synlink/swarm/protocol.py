"""
Protocol object that allows use to interface 
with supported protocols on the synlink network.
"""
from synlink.typing import TProtocol
from synlink.utils import _check_minimum_version

if _check_minimum_version(3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class Protocol(object):
    """Network object allows us to see our StreamNetwork struct."""
    _protocol : TProtocol

    def __init__(self, data : TProtocol):
        if not data.startswith('/'):
            raise ValueError("Protocols should start with a /.")
        self._protocol = data

    @classmethod
    def from_bytes(cls, data : bytes) -> Self:
        data = data.decode()
        cls(data)
    
    def to_bytes(self) -> bytes:
        data = self._protocol.encode("utf-8")
        return data

    @classmethod
    def from_str(cls, data : str) -> Self:
        if not data.startswith('/'):
            raise ValueError("Protocols should start with a /.")
        cls(data)

    @property
    def protocol(self):
        self._protocol

    def __repr__(self) -> str:
        return f"<synlin.swarm.protocol {self._protocol!s}>"
    
    def __str__(self) -> str:
        return self._protocol