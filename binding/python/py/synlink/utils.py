import sys
from typing import Optional

__all__ = ["_check_minimum_version", "_check_exact_version"]


def _check_minimum_version(
    major: int, minor: Optional[int] = 0, micro: Optional[int] = 0
):
    """Check if current Python version meets minimum requirements"""
    current = sys.version_info
    required = (major, minor, micro)
    return current[:3] >= required


def _check_exact_version(
    major: int, minor: Optional[int] = 0, micro: Optional[int] = 0
):
    """Check if current Python version matches exactly"""
    current = sys.version_info

    if major != current.major:
        return False
    if minor is not None and minor != current.minor:
        return False
    if micro is not None and micro != current.micro:
        return False

    return True
