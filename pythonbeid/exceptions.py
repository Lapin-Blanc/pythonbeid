"""Exception hierarchy of pythonbeid.

Every exception raised by the library derives from :class:`BeidError`, so a
single ``except BeidError`` clause is enough to handle all library failures.
"""

from __future__ import annotations

__all__ = [
    "APDUError",
    "BeidError",
    "CardCommunicationError",
    "CardDataError",
    "NoCardError",
    "NoReaderError",
    "PCSCServiceError",
    "UnsupportedCardError",
]


class BeidError(RuntimeError):
    """Base class of all pythonbeid exceptions."""


class NoReaderError(BeidError):
    """Raised when no usable smart card reader is available."""


class PCSCServiceError(NoReaderError):
    """Raised when the PC/SC service itself cannot be reached.

    Typical causes: ``pcscd`` not running on Linux, or the *Smart Card*
    service stopped on Windows.
    """


class NoCardError(BeidError):
    """Raised when no card is present in the reader (or it was removed)."""


class CardCommunicationError(BeidError):
    """Raised on a failure while talking to the card."""


class APDUError(CardCommunicationError):
    """Raised when the card answers a command with an unexpected status word.

    Attributes:
        sw1: First status byte.
        sw2: Second status byte.
    """

    def __init__(self, sw1: int, sw2: int, message: str = "") -> None:
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(message or f"Unexpected APDU status: SW={sw1:02X}{sw2:02X}")

    @property
    def sw(self) -> int:
        """Both status bytes combined into one integer (e.g. ``0x6A82``)."""
        return (self.sw1 << 8) | self.sw2


class UnsupportedCardError(CardCommunicationError):
    """Raised when the card does not support the requested operation.

    For example, the basic-key chip authentication only exists on applet 1.8
    cards.
    """


class CardDataError(BeidError, ValueError):
    """Raised when data read from the card cannot be decoded."""
