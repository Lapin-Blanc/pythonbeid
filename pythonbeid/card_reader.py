"""PC/SC access to Belgian eID cards.

The transport follows what the official middleware (``Fedict/eid-mw``) does:

* files are selected by absolute path, with a fallback that selects the Belpic
  applet when another application left the card in a different state;
* files are read in 252-byte blocks, ``6Cxx`` answers are re-sent with the
  exact length, ``61xx`` answers are collected with GET RESPONSE and ``6B00``
  past the first block marks the end of a file whose size is a multiple of
  the block size;
* every multi-command operation runs inside a PC/SC transaction, so other
  applications (browser, middleware, Windows certificate propagation) cannot
  interleave their own commands;
* the card is left powered when the connection is closed.

No PIN is ever sent: everything this module reads is public card content.
"""

from __future__ import annotations

import base64
import logging
import os
import time
import warnings
from contextlib import contextmanager
from dataclasses import replace
from datetime import date, datetime
from typing import TYPE_CHECKING, Any, NamedTuple, Self

from smartcard.CardConnectionDecorator import CardConnectionDecorator
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import (
    CardConnectionException,
    CardRequestTimeoutException,
    NoCardException,
    SmartcardException,
)
from smartcard.pcsc.PCSCExceptions import BaseSCardException
from smartcard.scard import (
    SCARD_E_NO_SMARTCARD,
    SCARD_LEAVE_CARD,
    SCARD_S_SUCCESS,
    SCARD_W_REMOVED_CARD,
    SCARD_W_RESET_CARD,
    SCardBeginTransaction,
    SCardEndTransaction,
    SCardGetErrorMessage,
)
from smartcard.System import readers as _pcsc_readers

from .exceptions import (
    APDUError,
    BeidError,
    CardCommunicationError,
    CardDataError,
    NoCardError,
    NoReaderError,
    PCSCServiceError,
    UnsupportedCardError,
)
from .models import CardFile, CardInfo, EidData
from .parser import _der_length, _text, parse_address, parse_card_data, parse_identity

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence
    from types import TracebackType

    from .models import Address, Identity, VerificationReport

__all__ = ["CardReader", "list_readers"]

logger = logging.getLogger(__name__)

_BELPIC_AID = bytes.fromhex("A0 00 00 00 30 29 05 70 00 AD 13 10 01 01 FF")
_DEFAULT_CHUNK_SIZE = 252  # eid-mw MAX_APDU_READ_LEN
_MAX_OFFSET = 0x7FFF  # READ BINARY with a 15-bit offset
_MAX_6C_RETRIES = 3
_MAX_GET_RESPONSE = 64
_CHALLENGE_SIZE = 48  # SHA-384 digest size, as eid-viewer does
_WAIT_STEP = 1.0  # seconds between two scans of the readers while waiting

_SW_OK = 0x9000
_SW_EOF_WARNING = 0x6282  # end of file reached before reading Le bytes
_SW_WRONG_OFFSET = 0x6B00
_SW_NOT_FOUND = (0x6A82, 0x6A86)
_SW_MESSAGES = {
    0x6700: "wrong length",
    0x6982: "security status not satisfied",
    0x6986: "command not allowed",
    0x6A82: "file not found",
    0x6A86: "incorrect P1/P2",
    0x6B00: "offset outside the file",
    0x6D00: "instruction not supported",
    0x6E00: "class not supported",
}


# PC/SC codes are signed on Windows and unsigned elsewhere: compare them as
# unsigned 32-bit values on both sides.
_UINT32 = 0xFFFFFFFF
_CARD_ABSENT_CODES = frozenset(
    code & _UINT32 for code in (SCARD_W_REMOVED_CARD, SCARD_E_NO_SMARTCARD)
)
_CARD_RESET_CODE = SCARD_W_RESET_CARD & _UINT32


class _Response(NamedTuple):
    data: bytes
    sw: int


class _CardResetError(Exception):
    """Internal signal: another application reset the card."""


def _repeated_reset() -> CardCommunicationError:
    return CardCommunicationError(
        "The card was reset repeatedly by another application"
    )


def _hresult(exc: BaseException) -> int:
    """PC/SC return code of a pyscard exception, as an unsigned integer."""
    return int(getattr(exc, "hresult", -1)) & _UINT32


def _naive_datetime(day: date) -> datetime:
    """Midnight of *day* as a naive datetime, the 0.x date type."""
    return datetime(day.year, day.month, day.day)  # noqa: DTZ001 - 0.x compatibility


def _list_pcsc_readers() -> list[Any]:
    try:
        return list(_pcsc_readers())
    except (BaseSCardException, SmartcardException) as exc:
        msg = f"PC/SC service unavailable: {exc}"
        raise PCSCServiceError(msg) from exc


def list_readers() -> list[str]:
    """Return the names of the connected PC/SC smart card readers.

    The position of a name in the list is the index accepted by
    :class:`CardReader`.

    Raises:
        PCSCServiceError: If the PC/SC service cannot be reached.
    """
    return [str(reader) for reader in _list_pcsc_readers()]


class _TransactionalConnection(CardConnectionDecorator):  # type: ignore[misc]
    """pyscard connection able to hold PC/SC transactions.

    Unlike pyscard's ``ExclusiveTransmitCardConnection``, failures keep the
    PC/SC return code in ``hresult``, which is needed to detect a card reset.
    """

    def _hcard(self) -> Any:
        component = self.component
        while component is not None:
            if hasattr(component, "hcard"):
                return component.hcard
            component = getattr(component, "component", None)
        return None  # pragma: no cover - pyscard always has a PCSC connection

    def lock(self) -> None:
        """Begin a PC/SC transaction (``SCardBeginTransaction``)."""
        hresult = SCardBeginTransaction(self._hcard())
        if hresult != SCARD_S_SUCCESS:
            msg = f"SCardBeginTransaction failed: {SCardGetErrorMessage(hresult)}"
            raise CardConnectionException(msg, hresult=hresult)

    def unlock(self) -> None:
        """End the PC/SC transaction, leaving the card as it is."""
        hresult = SCardEndTransaction(self._hcard(), SCARD_LEAVE_CARD)
        if hresult != SCARD_S_SUCCESS:
            msg = f"SCardEndTransaction failed: {SCardGetErrorMessage(hresult)}"
            raise CardConnectionException(msg, hresult=hresult)


def _wrap_connection(connection: Any) -> Any:
    """Decorate a pyscard connection so it can hold PC/SC transactions."""
    return _TransactionalConnection(connection)


class CardReader:
    """Connection to a Belgian eID card inserted in a PC/SC reader.

    Args:
        reader: Which reader to use: its index in :func:`list_readers`, its
            name (exact, or a unique case-insensitive substring), or ``None``
            (default) to pick the first reader holding a Belgian eID card.
        timeout: Seconds to wait for a card to be inserted when none is
            present. ``None`` (default) does not wait.
        chunk_size: Number of bytes requested per READ BINARY command
            (1-256). The default (252) is the value of the official
            middleware; lower it only for readers that cannot transfer
            larger blocks.
        reader_index: Deprecated alias of *reader*.

    Raises:
        NoReaderError: If no reader matches.
        PCSCServiceError: If the PC/SC service cannot be reached.
        NoCardError: If no card is present (after *timeout*).
        UnsupportedCardError: If the card is not a Belgian eID card.
        CardCommunicationError: If the connection fails.

    Examples:
        >>> with CardReader() as reader:  # doctest: +SKIP
        ...     eid = reader.read()
        ...     print(eid.identity.last_name)
    """

    def __init__(
        self,
        reader: int | str | None = None,
        *,
        timeout: float | None = None,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
        reader_index: int | None = None,
    ) -> None:
        if reader_index is not None:
            warnings.warn(
                "'reader_index' is deprecated, pass the index as 'reader'",
                DeprecationWarning,
                stacklevel=2,
            )
            if reader is not None:
                msg = "pass either 'reader' or 'reader_index', not both"
                raise TypeError(msg)
            reader = reader_index
        if not 1 <= chunk_size <= 256:
            msg = f"chunk_size must be between 1 and 256, got {chunk_size}"
            raise ValueError(msg)
        self._chunk_size = chunk_size
        self._lock_depth = 0
        self._retry_delay = 0.0
        self._connection: Any = None
        self._card_info: CardInfo | None = None

        available = _list_pcsc_readers()
        if not available:
            msg = "No smart card reader detected"
            raise NoReaderError(msg)
        candidates = self._resolve_readers(available, reader)
        self._open(candidates, explicit=reader is not None, timeout=timeout)

    # ── Reader selection and connection ──────────────────────────────────

    @staticmethod
    def _resolve_readers(available: list[Any], reader: int | str | None) -> list[Any]:
        if reader is None:
            return available
        if isinstance(reader, bool) or not isinstance(reader, int | str):
            msg = f"reader must be an index or a name, got {type(reader).__name__}"
            raise TypeError(msg)
        if isinstance(reader, int):
            if not 0 <= reader < len(available):
                msg = (
                    f"Reader index {reader} out of range "
                    f"({len(available)} reader(s) available)"
                )
                raise NoReaderError(msg)
            return [available[reader]]
        names = [str(item) for item in available]
        if reader in names:
            return [available[names.index(reader)]]
        matches = [
            item for item, name in zip(available, names, strict=True)
            if reader.casefold() in name.casefold()
        ]  # fmt: skip
        if len(matches) == 1:
            return matches
        if not matches:
            msg = f"No reader matches {reader!r} (available: {', '.join(names)})"
        else:
            found = ", ".join(str(item) for item in matches)
            msg = f"Reader name {reader!r} is ambiguous ({found})"
        raise NoReaderError(msg)

    def _open(
        self, candidates: list[Any], *, explicit: bool, timeout: float | None
    ) -> None:
        if self._try_candidates(candidates, explicit=explicit):
            return
        if timeout is None:
            names = ", ".join(f"'{item}'" for item in candidates)
            msg = f"No Belgian eID card in reader {names}"
            raise NoCardError(msg)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                msg = f"No Belgian eID card inserted within {timeout:g} s"
                raise NoCardError(msg)
            self._wait_for_insertion(candidates, min(remaining, _WAIT_STEP))
            if self._try_candidates(candidates, explicit=explicit):
                return

    def _try_candidates(self, candidates: list[Any], *, explicit: bool) -> bool:
        for candidate in candidates:
            try:
                self._connect(candidate)
            except NoCardError:
                continue
            except BeidError:
                if explicit:
                    raise
                logger.debug("Skipping reader '%s'", candidate, exc_info=True)
                continue
            return True
        return False

    def _connect(self, reader: Any) -> None:
        try:
            connection = _wrap_connection(reader.createConnection())
            connection.connect(disposition=SCARD_LEAVE_CARD)
        except NoCardException as exc:
            msg = f"No card in reader '{reader}'"
            raise NoCardError(msg) from exc
        except SmartcardException as exc:
            if _hresult(exc) in _CARD_ABSENT_CODES:
                msg = f"No card in reader '{reader}'"
                raise NoCardError(msg) from exc
            msg = f"Connection error on '{reader}': {exc}"
            raise CardCommunicationError(msg) from exc
        self._connection = connection
        self._reader = reader
        try:
            self._card_info = self._read_card_info()
        except APDUError as exc:
            self.close()
            msg = f"The card in '{reader}' is not a Belgian eID card ({exc})"
            raise UnsupportedCardError(msg) from exc
        except BeidError:
            self.close()
            raise
        if self._card_info.global_os_version == 0x0001:
            # eid-mw waits before re-sending a command answered with 6Cxx
            # on cards with this global OS version.
            self._retry_delay = 0.05
        logger.debug(
            "Connected to applet %s card via '%s'",
            self._card_info.applet_version_string,
            reader,
        )

    @staticmethod
    def _wait_for_insertion(candidates: list[Any], seconds: float) -> None:
        """Block until a card is inserted in one of *candidates*, or *seconds*.

        Readers that already hold a card (e.g. a bank card) do not end the
        wait: only new insertions do, and the caller then retries every
        reader.
        """
        request = CardRequest(timeout=seconds, readers=candidates, newcardonly=True)
        try:
            request.waitforcard()
        except CardRequestTimeoutException:
            return
        except (BaseSCardException, SmartcardException) as exc:
            msg = f"Error while waiting for a card: {exc}"
            raise CardCommunicationError(msg) from exc

    # ── Context manager and properties ───────────────────────────────────

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "open" if self._connection is not None else "closed"
        return f"<CardReader reader='{getattr(self, '_reader', '?')}' {state}>"

    def close(self) -> None:
        """Release the card, leaving it powered for other applications.

        Calling it more than once is harmless.
        """
        connection, self._connection = self._connection, None
        if connection is None:
            return
        try:
            connection.disconnect()
        except (BaseSCardException, SmartcardException) as exc:
            logger.debug("Ignoring error while disconnecting: %s", exc)
        else:
            logger.debug("Disconnected from card")

    @property
    def reader_name(self) -> str:
        """Name of the PC/SC reader in use."""
        return str(self._reader)

    @property
    def atr(self) -> bytes:
        """Answer To Reset of the card."""
        atr: bytes = self._with_reset_retry(
            lambda: bytes(self._call(self._live_connection().getATR))
        )
        return atr

    @property
    def card_info(self) -> CardInfo:
        """Chip information (GET CARD DATA), read when connecting."""
        if self._card_info is None:  # pragma: no cover - set by the constructor
            self._card_info = self._read_card_info()
        return self._card_info

    # ── Low-level transport ──────────────────────────────────────────────

    def _live_connection(self) -> Any:
        if self._connection is None:
            msg = "The connection to the card is closed"
            raise CardCommunicationError(msg)
        return self._connection

    def _call(self, func: Callable[..., Any], *args: Any) -> Any:
        """Run a pyscard call and translate its exceptions."""
        try:
            return func(*args)
        except NoCardException as exc:
            msg = f"Card removed from reader '{self._reader}'"
            raise NoCardError(msg) from exc
        except SmartcardException as exc:
            code = _hresult(exc)
            if code in _CARD_ABSENT_CODES:
                msg = f"Card removed from reader '{self._reader}'"
                raise NoCardError(msg) from exc
            if code == _CARD_RESET_CODE:
                raise _CardResetError from exc
            msg = f"Communication error with the card: {exc}"
            raise CardCommunicationError(msg) from exc

    def _transmit_once(self, apdu: bytes) -> _Response:
        data, sw1, sw2 = self._call(self._live_connection().transmit, list(apdu))
        response = _Response(bytes(data), (sw1 << 8) | sw2)
        logger.debug(
            "APDU %s (%d bytes) -> SW=%04X, %d bytes",
            apdu[:4].hex(" ").upper(),
            len(apdu),
            response.sw,
            len(response.data),
        )
        return response

    def _transmit(self, apdu: bytes) -> _Response:
        """Send one command, handling ``6Cxx`` and ``61xx`` transparently."""
        response = self._transmit_once(apdu)
        for _ in range(_MAX_6C_RETRIES):
            if response.sw >> 8 != 0x6C or len(apdu) != 5:
                break
            if self._retry_delay:
                time.sleep(self._retry_delay)
            apdu = apdu[:4] + bytes([response.sw & 0xFF])
            response = self._transmit_once(apdu)
        data = response.data
        for _ in range(_MAX_GET_RESPONSE):
            if response.sw >> 8 != 0x61:
                break
            response = self._transmit_once(
                bytes([0x00, 0xC0, 0x00, 0x00, response.sw & 0xFF])
            )
            data += response.data
        else:
            msg = "too many chained GET RESPONSE commands"
            raise CardCommunicationError(msg)
        return _Response(data, response.sw)

    @staticmethod
    def _check(response: _Response, action: str) -> bytes:
        if response.sw != _SW_OK:
            sw1, sw2 = response.sw >> 8, response.sw & 0xFF
            reason = _SW_MESSAGES.get(response.sw, "unexpected status")
            msg = f"{action} failed: SW={response.sw:04X} ({reason})"
            raise APDUError(sw1, sw2, msg)
        return response.data

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        """Hold a PC/SC transaction (re-entrant) around several commands."""
        if self._lock_depth == 0:
            try:
                self._call(self._live_connection().lock)
            except _CardResetError:
                self._reconnect()
                try:
                    self._call(self._live_connection().lock)
                except _CardResetError as exc:
                    raise _repeated_reset() from exc
        self._lock_depth += 1
        try:
            yield
        finally:
            self._lock_depth -= 1
            if self._lock_depth == 0 and self._connection is not None:
                try:
                    self._connection.unlock()
                except (BaseSCardException, SmartcardException) as exc:
                    logger.debug("Ignoring error while ending transaction: %s", exc)

    def _reconnect(self) -> None:
        logger.debug("Card was reset by another application, reconnecting")
        connection = self._live_connection()
        try:
            self._call(connection.reconnect, None, None, SCARD_LEAVE_CARD)
            if self._lock_depth:
                self._call(connection.lock)
        except _CardResetError as exc:
            self.close()
            raise _repeated_reset() from exc
        except BeidError:
            # pyscard drops the card handle when reconnecting fails.
            self.close()
            raise

    def _with_reset_retry(self, operation: Callable[[], Any]) -> Any:
        try:
            with self._transaction():
                return operation()
        except _CardResetError:
            self._reconnect()
        try:
            with self._transaction():
                return operation()
        except _CardResetError as exc:
            raise _repeated_reset() from exc

    def _select(self, path: bytes) -> None:
        command = bytes([0x00, 0xA4, 0x08, 0x0C, len(path)]) + path
        response = self._transmit(command)
        if response.sw in _SW_NOT_FOUND or response.sw >> 8 in (0x6D, 0x6E):
            # Another application may have selected a different applet.
            self._transmit(
                bytes([0x00, 0xA4, 0x04, 0x0C, len(_BELPIC_AID)]) + _BELPIC_AID
            )
            response = self._transmit(command)
        self._check(response, f"SELECT {path.hex().upper()}")

    def _read_selected(self) -> bytes:
        content = bytearray()
        le = self._chunk_size & 0xFF  # 256 is encoded as 0x00
        while True:
            offset = len(content)
            if offset > _MAX_OFFSET:
                msg = "file larger than the READ BINARY offset range"
                raise CardDataError(msg)
            response = self._transmit(
                bytes([0x00, 0xB0, offset >> 8, offset & 0xFF, le])
            )
            if response.sw == _SW_WRONG_OFFSET and offset > 0:
                break  # the file size is a multiple of the block size
            if response.sw == _SW_EOF_WARNING:
                content += response.data
                break
            content += self._check(response, f"READ BINARY at offset {offset}")
            if len(response.data) < self._chunk_size:
                break
        return bytes(content)

    def _read_card_info(self) -> CardInfo:
        def operation() -> CardInfo:
            data = self._check(
                self._transmit(bytes([0x80, 0xE4, 0x00, 0x00, 0x1C])), "GET CARD DATA"
            )
            extended = None
            if len(data) > 21 and data[21] >= 0x18:
                extended = self._check(
                    self._transmit(bytes([0x80, 0xE4, 0x00, 0x01, 0x1F])),
                    "GET CARD DATA (extended)",
                )
            return parse_card_data(data, extended)

        result: CardInfo = self._with_reset_retry(operation)
        return result

    # ── Public API ───────────────────────────────────────────────────────

    def read_file(self, file: CardFile | bytes | Sequence[int]) -> bytes:
        """Read the complete raw content of a file.

        Args:
            file: A :class:`CardFile`, or an absolute path such as
                ``bytes.fromhex("3F00DF014031")``.

        Returns:
            The file content, including any zero padding.

        Raises:
            APDUError: If the file does not exist or cannot be read.
            NoCardError: If the card was removed.
            CardCommunicationError: On any other transport failure.
        """
        path = file.path if isinstance(file, CardFile) else bytes(file)

        def operation() -> bytes:
            self._select(path)
            return self._read_selected()

        content: bytes = self._with_reset_retry(operation)
        logger.debug("Read %d bytes from %s", len(content), path.hex().upper())
        return content

    def read_certificate(self, file: CardFile) -> bytes:
        """Read a certificate file and return the DER certificate it holds.

        Certificate files are larger than their content and padded with zero
        bytes; the padding is removed.

        Raises:
            ValueError: If *file* is not a certificate file.
        """
        if not file.is_certificate:
            msg = f"{file.name} is not a certificate file"
            raise ValueError(msg)
        content = self.read_file(file)
        return content[: _der_length(content)]

    def read_card_info(self) -> CardInfo:
        """Read the chip information (GET CARD DATA) again."""
        self._card_info = self._read_card_info()
        return self._card_info

    def read_identity(self) -> Identity:
        """Read and decode the identity file."""
        return parse_identity(self.read_file(CardFile.IDENTITY))

    def read_address(self) -> Address:
        """Read and decode the address file."""
        return parse_address(self.read_file(CardFile.ADDRESS))

    def read_photo(self) -> bytes:
        """Read the photo of the card holder (JPEG)."""
        return self.read_file(CardFile.PHOTO)

    def read(self, *, photo: bool = True, integrity: bool = True) -> EidData:
        """Read the card content in a single PC/SC transaction.

        Args:
            photo: Read the photo.
            integrity: Also read the files needed by
                :func:`pythonbeid.verify_eid`: the signatures, the RRN
                certificate and, when the identity file references one, the
                basic public key (applet 1.8).

        Returns:
            The decoded content, with the raw files in :attr:`EidData.files`.
        """
        with self._transaction():
            files = {CardFile.IDENTITY: self.read_file(CardFile.IDENTITY)}
            identity = parse_identity(files[CardFile.IDENTITY])
            wanted = [CardFile.ADDRESS]
            if photo:
                wanted.append(CardFile.PHOTO)
            if integrity:
                wanted += [
                    CardFile.IDENTITY_SIGNATURE,
                    CardFile.ADDRESS_SIGNATURE,
                    CardFile.RRN_CERTIFICATE,
                ]
                if identity.basic_key_hash is not None:
                    wanted.append(CardFile.BASIC_PUBLIC_KEY)
            files.update((file, self.read_file(file)) for file in wanted)
        return EidData(
            identity=identity,
            address=parse_address(files[CardFile.ADDRESS]),
            card=self.card_info,
            photo=files.get(CardFile.PHOTO),
            files=files,
        )

    def challenge(self, nonce: bytes) -> bytes:
        """Have the chip sign *nonce* with its basic private key.

        This INTERNAL AUTHENTICATE command only exists on applet 1.8 cards
        and needs no PIN. Prefer :meth:`authenticate_chip`, which also checks
        the key and the answer.

        Args:
            nonce: Data to sign (the official viewer uses 48 random bytes).

        Returns:
            The raw ECDSA signature (``r || s``).

        Raises:
            APDUError: If the card refuses the command (applet 1.7 cards).
        """
        if not 1 <= len(nonce) <= 253:
            msg = "nonce must be between 1 and 253 bytes"
            raise ValueError(msg)
        command = (
            bytes([0x00, 0x88, 0x02, 0x81, len(nonce) + 2, 0x94, len(nonce)]) + nonce
        )
        response = self._with_reset_retry(lambda: self._transmit(command))
        return self._check(response, "INTERNAL AUTHENTICATE")

    def authenticate_chip(self, identity: Identity | None = None) -> bool:
        """Prove that the chip is the genuine one (applet 1.8 cards).

        The basic public key file is checked against its digest in the
        identity file, then the chip must sign a random challenge with the
        matching private key, which a copy of the card data cannot do.

        Args:
            identity: The identity whose signed basic key digest is the
                reference, typically one checked by :func:`verify_eid`
                (:meth:`verify` does both). Read from the card when omitted;
                it then proves the chip matches its own identity file, whose
                signature must be checked separately.

        Returns:
            Whether the key matches its digest and the chip signature is
            valid.

        Raises:
            UnsupportedCardError: If the identity file references no basic
                key (applet 1.7 cards).
            ImportError: If the ``cryptography`` package is not installed.
        """
        from .integrity import (  # noqa: PLC0415 - optional dependency
            basic_key_matches,
            verify_chip_signature,
        )

        with self._transaction():
            if identity is None:
                identity = self.read_identity()
            if identity.basic_key_hash is None:
                msg = "This card has no basic key (applet 1.8 or later required)"
                raise UnsupportedCardError(msg)
            key_file = self.read_file(CardFile.BASIC_PUBLIC_KEY)
            if not basic_key_matches(key_file, identity.basic_key_hash):
                logger.warning("The basic public key does not match its digest")
                return False
            nonce = os.urandom(_CHALLENGE_SIZE)
            signature = self.challenge(nonce)
        try:
            return verify_chip_signature(key_file, nonce, signature)
        except CardDataError:
            return False

    def verify(
        self,
        eid: EidData | None = None,
        *,
        authenticate_chip: bool = True,
        trusted_roots: Sequence[bytes] | None = None,
    ) -> VerificationReport:
        """Check the integrity and authenticity of the card content.

        Args:
            eid: Data previously returned by :meth:`read` (with
                ``integrity=True``); read from the card when omitted.
            authenticate_chip: When the signed identity file references a
                basic key (applet 1.8), also run the chip challenge
                (:meth:`authenticate_chip`).
            trusted_roots: Root certificates (DER or PEM) to trust instead of
                the bundled Belgian roots.

        Returns:
            The outcome of every check.

        Raises:
            ImportError: If the ``cryptography`` package is not installed.
            NoCardError: If the card is removed during the checks.
        """
        from .integrity import verify_eid  # noqa: PLC0415 - optional dependency

        if eid is None:
            eid = self.read(photo=True, integrity=True)
        report = verify_eid(eid, trusted_roots=trusted_roots)
        try:
            signed = parse_identity(eid.files[CardFile.IDENTITY])
        except CardDataError:
            return report  # already reported as failed
        if not authenticate_chip or signed.basic_key_hash is None:
            return report
        try:
            authenticated = self.authenticate_chip(signed)
        except (UnsupportedCardError, APDUError) as exc:
            logger.warning("Chip challenge refused: %s", exc)
            authenticated = False
        errors = report.errors
        if not authenticated:
            errors = (*errors, "chip challenge failed: the chip is not genuine")
        return replace(report, chip_authenticated=authenticated, errors=errors)

    # ── Deprecated 0.x API ───────────────────────────────────────────────

    def read_informations(
        self, photo: bool = False  # noqa: FBT001, FBT002 - 0.x signature
    ) -> dict[str, Any]:
        """Return the card content as a 0.x-style dictionary.

        .. deprecated:: 1.0
            Use :meth:`read`, which returns typed data. This method keeps the
            0.x keys and types: naive ``datetime`` dates, ``suffix`` for the
            initial of the third given name, raw ``sex`` letter, photo as a
            base-64 string. ``birth_date`` is ``None`` for incomplete dates.

        Args:
            photo: Include the photo, as a base-64 encoded string.
        """
        warnings.warn(
            "read_informations() is deprecated, use read() instead",
            DeprecationWarning,
            stacklevel=2,
        )
        eid = self.read(photo=photo, integrity=False)
        identity, address = eid.identity, eid.address
        birth = identity.birth_date
        informations: dict[str, Any] = {
            "card_number": identity.card_number,
            "validity_start": _naive_datetime(identity.validity_start),
            "validity_end": _naive_datetime(identity.validity_end),
            "issuing_municipality": identity.issuing_municipality,
            "national_number": identity.national_number,
            "last_name": identity.last_name,
            "first_names": identity.first_names,
            "suffix": identity.third_given_name_initial,
            "nationality": identity.nationality,
            "birth_place": identity.birth_place,
            "birth_date": (
                _naive_datetime(birth.to_date())
                if birth is not None and birth.is_complete
                else None
            ),
            "sex": _text(identity.raw.get(0x0D)),
            "address": address.street,
            "postal_code": address.postal_code,
            "city": address.municipality,
        }
        if eid.photo is not None:
            informations["photo"] = base64.b64encode(eid.photo).decode("ascii")
        for key, value in informations.items():
            setattr(self, key, value)
        return informations
