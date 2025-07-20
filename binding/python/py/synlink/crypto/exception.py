from synlink.error import SynlinkBaseException

class CryptoBaseException(SynlinkBaseException):
    """Base exception for all cryptographic errors."""

    pass

class SignatureVerificationError(CryptoBaseException):
    """Raised when signature verification fails."""

    pass
