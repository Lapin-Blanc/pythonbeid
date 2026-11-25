"""Simulated Belgian eID card speaking ISO 7816-4, for hardware-free tests.

The behaviour mirrors what a real applet 1.7 card does (observed with an ACS
ACR38U reader): ``6Cxx`` when Le exceeds the remaining bytes, ``6B00`` when
the offset is past the end of the file, ``61xx`` for case 4 commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)
from smartcard import scard
from smartcard.Exceptions import CardConnectionException, NoCardException

if TYPE_CHECKING:
    from collections.abc import Callable

BELPIC_AID = bytes.fromhex("A0 00 00 00 30 29 05 70 00 AD 13 10 01 01 FF")
ATR_17 = bytes.fromhex("3B9813400AA503010101AD1311")


def card_data(applet: int = 0x17, global_os: int = 0x0003) -> bytes:
    """Build a GET CARD DATA answer (28 bytes)."""
    serial = bytes(range(0x10, 0x20))
    return (
        serial
        + bytes(
            [
                0xF3,
                0x36,
                0x01,
                0x25,
                0x01,
                applet,
                global_os >> 8,
                global_os & 0xFF,
                0x00,
            ]
        )
        + bytes(
            [0x21 if applet < 0x18 else 0x00, 0x01 if applet < 0x18 else 0x02, 0x0F]
        )
    )


@dataclass
class FakeCard:
    """A card with a file system and configurable quirks."""

    files: dict[bytes, bytes]
    applet: int = 0x17
    global_os: int = 0x0003
    atr: bytes = ATR_17
    basic_key: ec.EllipticCurvePrivateKey | None = None
    pin_attempts: int = 3
    get_response_mode: bool = False  # answer READ BINARY with 61xx
    eof_warning: bool = False  # answer short reads with 6282 instead of 6Cxx
    require_applet_select: bool = False  # path SELECT fails until AID SELECT
    is_beid: bool = True
    connect_error: BaseException | None = None
    transmit_errors: list[BaseException] = field(default_factory=list)
    on_transmit: Callable[[list[int]], None] | None = None

    log: list[bytes] = field(default_factory=list)
    connect_kwargs: dict[str, Any] = field(default_factory=dict)
    disconnect_calls: int = 0
    disconnect_error: BaseException | None = None
    reconnect_calls: int = 0
    lock_calls: int = 0
    unlock_calls: int = 0
    unlock_error: BaseException | None = None
    _current: bytes | None = None
    _applet_selected: bool = False
    _pending: bytes = b""

    # ── pyscard connection interface ─────────────────────────────────────

    def connect(
        self, protocol: Any = None, mode: Any = None, disposition: Any = None
    ) -> None:
        self.connect_kwargs = {
            "protocol": protocol,
            "mode": mode,
            "disposition": disposition,
        }
        if self.connect_error is not None:
            raise self.connect_error

    def disconnect(self) -> None:
        self.disconnect_calls += 1
        if self.disconnect_error is not None:
            raise self.disconnect_error

    def reconnect(
        self, protocol: Any = None, mode: Any = None, disposition: Any = None
    ) -> None:
        self.reconnect_calls += 1
        self._current = None

    def getATR(self) -> list[int]:  # noqa: N802 - pyscard API
        return list(self.atr)

    def lock(self) -> None:
        self.lock_calls += 1

    def unlock(self) -> None:
        self.unlock_calls += 1
        if self.unlock_error is not None:
            raise self.unlock_error

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        if self.on_transmit is not None:
            self.on_transmit(apdu)
        if self.transmit_errors:
            raise self.transmit_errors.pop(0)
        self.log.append(bytes(apdu))
        data, sw = self._process(bytes(apdu))
        return list(data), sw >> 8, sw & 0xFF

    # ── Command processing ───────────────────────────────────────────────

    def _process(self, apdu: bytes) -> tuple[bytes, int]:
        cla, ins, p1, p2 = apdu[:4]
        if not self.is_beid:
            return b"", 0x6E00
        if (cla, ins) == (0x00, 0xA4):
            return self._select(p1, apdu[5 : 5 + apdu[4]])
        if (cla, ins) == (0x00, 0xB0):
            return self._read_binary((p1 << 8) | p2, apdu[4] or 256)
        if (cla, ins) == (0x80, 0xE4):
            return self._card_data(p2, apdu[4])
        if (cla, ins) == (0x00, 0xC0):
            return self._get_response(apdu[4])
        if (cla, ins) == (0x00, 0x88):
            return self._internal_authenticate(apdu)
        return b"", 0x6D00

    def _select(self, p1: int, data: bytes) -> tuple[bytes, int]:
        if p1 == 0x04:
            if data == BELPIC_AID:
                self._applet_selected = True
                return b"", 0x9000
            return b"", 0x6A82
        if self.require_applet_select and not self._applet_selected:
            return b"", 0x6A82
        if data not in self.files:
            return b"", 0x6A82
        self._current = self.files[data]
        return b"", 0x9000

    def _read_binary(self, offset: int, le: int) -> tuple[bytes, int]:
        if self._current is None:
            return b"", 0x6986
        if offset >= len(self._current):
            return b"", 0x6B00
        remaining = len(self._current) - offset
        if self.get_response_mode:
            self._pending = self._current[offset : offset + min(le, remaining)]
            return b"", 0x6100 | len(self._pending) & 0xFF
        if le > remaining:
            if self.eof_warning:
                return self._current[offset:], 0x6282
            return b"", 0x6C00 | remaining
        return self._current[offset : offset + le], 0x9000

    def _card_data(self, p2: int, le: int) -> tuple[bytes, int]:
        base = card_data(self.applet, self.global_os)
        if p2 == 0x00:
            return (base, 0x9000) if le == len(base) else (b"", 0x6C00 | len(base))
        if p2 == 0x01 and self.applet >= 0x18:
            return base + bytes([self.pin_attempts, 0xFF, 0xFF]), 0x9000
        return b"", 0x6B00

    def _get_response(self, le: int) -> tuple[bytes, int]:
        if not self._pending:
            return b"", 0x6985
        chunk, self._pending = self._pending[:le], self._pending[le:]
        return chunk, (
            0x9000 if not self._pending else 0x6100 | len(self._pending) & 0xFF
        )

    def _internal_authenticate(self, apdu: bytes) -> tuple[bytes, int]:
        if self.basic_key is None:
            return b"", 0x6D00
        body = apdu[5 : 5 + apdu[4]]
        if apdu[2:4] != b"\x02\x81" or body[0] != 0x94:
            return b"", 0x6A86
        nonce = body[2 : 2 + body[1]]
        der = self.basic_key.sign(nonce, ec.ECDSA(Prehashed(hashes.SHA384())))
        r, s = decode_dss_signature(der)
        self._pending = r.to_bytes(48, "big") + s.to_bytes(48, "big")
        return b"", 0x6100 | len(self._pending)


class FakeReader:
    """Stand-in for a pyscard reader object."""

    def __init__(self, name: str, card: FakeCard | None) -> None:
        self.name = name
        self.card = card

    def createConnection(self) -> FakeCard:  # noqa: N802 - pyscard API
        if self.card is None:
            empty = FakeCard(files={})
            empty.connect_error = NoCardException("No card", 0)
            return empty
        return self.card

    def __str__(self) -> str:
        return self.name


def reset_error() -> CardConnectionException:
    """Exception raised by pyscard when another application reset the card."""
    return CardConnectionException("Card reset", hresult=scard.SCARD_W_RESET_CARD)


def removed_error() -> CardConnectionException:
    """Exception raised by pyscard when the card was removed."""
    return CardConnectionException("Card removed", hresult=scard.SCARD_W_REMOVED_CARD)
