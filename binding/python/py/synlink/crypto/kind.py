from enum import Enum
from functools import cache


class Kind(Enum):
    ED25519: int = 0

    def to_string(self) -> str:
        """return the name of the crypto kind."""
        return self.name

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(1, byteorder="little")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Kind":
        """return kind from the byte(s)"""
        num = int().from_bytes(data, byteorder="little")
        if num > cls.max():
            raise ValueError(f"bytes shound not exceed {cls.max()}")
        elif num < cls.min():
            raise ValueError(f"bytes shound not be less then {cls.min()}")
        return cls(num)

    @staticmethod
    def max() -> int:
        """return the maximum possible enumeration number."""
        return 0
    
    @staticmethod
    def min() -> int:
        """return the maximum possible enumeration number."""
        return 0
    
    
    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return f"<synlink.crypto.kind kind={self}>"
