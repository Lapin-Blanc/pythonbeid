"""Custom exceptions for pythonbeid."""


class NoReaderError(RuntimeError):
    """Raised when no smart card reader is detected."""


class NoCardError(RuntimeError):
    """Raised when a reader is present but no card is inserted."""


class CardCommunicationError(RuntimeError):
    """Raised on a general card communication failure."""


class APDUError(CardCommunicationError):
    """Raised when an APDU command returns an unexpected status word.

    Attributes:
        sw1: First status byte (SW1).
        sw2: Second status byte (SW2).
    """

    def __init__(self, sw1: int, sw2: int, message: str = "") -> None:
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(message or f"Unexpected APDU status: SW={sw1:02X}{sw2:02X}")
