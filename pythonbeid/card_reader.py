"""Belgian eID card reader.

Reads personal data, address and optionally the photo from a Belgian
electronic identity card via a PC/SC-compatible smart card reader.

Dependencies: pyscard (python-smartcard)

Usage::

    from pythonbeid import CardReader

    with CardReader() as cr:
        info = cr.read_informations(photo=False)
        print(info["last_name"])
"""
import base64
import logging
from datetime import datetime
from typing import Any

from smartcard.Exceptions import CardConnectionException, NoCardException
from smartcard.System import readers

from .exceptions import APDUError, CardCommunicationError, NoCardError, NoReaderError
from .parser import parse_french_date, parse_tlv

logger = logging.getLogger(__name__)

# ── File identifiers (path on the card) ──────────────────────────────────────
_FILE_ID = [0x3F, 0x00, 0xDF, 0x01, 0x40, 0x31]      # personal identity data
_FILE_ADDRESS = [0x3F, 0x00, 0xDF, 0x01, 0x40, 0x33]  # address data
_FILE_PHOTO = [0x3F, 0x00, 0xDF, 0x01, 0x40, 0x35]    # photo data

# ISO 7816-4: Le=0x00 in a short APDU means "expect up to 256 bytes".
_LE_MAX = 0x00

# ── Status words that are handled in-band ──────────────────────────────────
_SW_OK = 0x90           # Normal completion
_SW_MORE_DATA = 0x61    # More data available (GET RESPONSE with SW2 bytes)
_SW_WRONG_LE = 0x6C     # Wrong Le: use SW2 as exact length


class CardReader:
    """Read information from a Belgian eID card.

    Args:
        reader_index: Index of the PC/SC reader to use when multiple readers
            are connected. Defaults to 0 (first available reader).

    Examples:
        Using as a context manager (recommended)::

            with CardReader() as cr:
                data = cr.read_informations()

        Or manually::

            cr = CardReader()
            try:
                data = cr.read_informations()
            finally:
                cr.close()
    """

    def __init__(self, reader_index: int = 0) -> None:
        available = readers()
        if not available:
            raise NoReaderError("No smart card reader detected")
        if reader_index >= len(available):
            raise NoReaderError(
                f"Reader index {reader_index} out of range "
                f"({len(available)} reader(s) available)"
            )
        reader = available[reader_index]
        logger.debug("Using reader: %s", reader)
        try:
            self._cnx = reader.createConnection()
            self._cnx.connect()
        except NoCardException:
            raise NoCardError(f"No card in reader '{reader}'")
        except CardConnectionException as exc:
            raise CardCommunicationError(f"Connection error on '{reader}': {exc}") from exc
        logger.debug("Connected to card via '%s'", reader)

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "CardReader":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        """Disconnect from the card and release the reader."""
        try:
            self._cnx.disconnect()
            logger.debug("Disconnected from card")
        except Exception:
            pass  # Ignore errors on cleanup

    # ── Low-level APDU transport ──────────────────────────────────────────

    def _send_apdu(self, apdu: list[int]) -> tuple[list[int], int, int]:
        """Transmit one APDU and return ``(data, SW1, SW2)``.

        Raises:
            APDUError: If the card returns an unexpected status word
                (i.e. not 0x90, 0x61, or 0x6C).
        """
        response, sw1, sw2 = self._cnx.transmit(apdu)
        logger.debug("APDU %s → SW=%02X%02X  data(%d)=%s",
                     [f"{b:02X}" for b in apdu], sw1, sw2, len(response),
                     [f"{b:02X}" for b in response[:8]])
        if sw1 not in (_SW_OK, _SW_MORE_DATA, _SW_WRONG_LE):
            raise APDUError(sw1, sw2,
                            f"Unexpected status SW={sw1:02X}{sw2:02X} "
                            f"for APDU {[hex(b) for b in apdu[:4]]}")
        return response, sw1, sw2

    # ── File access helpers ───────────────────────────────────────────────

    def _select_file(self, file_id: list[int]) -> None:
        """Send a SELECT command for *file_id* (no response expected)."""
        cmd = [0x00, 0xA4, 0x08, 0x0C, len(file_id)] + file_id
        _, sw1, sw2 = self._send_apdu(cmd)
        if sw1 != _SW_OK:
            raise APDUError(sw1, sw2, f"SELECT failed for file {[hex(b) for b in file_id]}")
        logger.debug("Selected file %s", [f"{b:02X}" for b in file_id])

    def _read_binary(self, p1: int, p2: int, le: int) -> tuple[list[int], int, int]:
        """Send a READ BINARY command and handle Le mismatch (0x6C)."""
        cmd = [0x00, 0xB0, p1, p2, le]
        data, sw1, sw2 = self._send_apdu(cmd)
        if sw1 == _SW_WRONG_LE:
            # Card tells us the exact length: re-issue with SW2 as Le.
            logger.debug("RE-READ BINARY with Le=%d (was %d)", sw2, le)
            cmd[-1] = sw2
            data, sw1, sw2 = self._send_apdu(cmd)
        return data, sw1, sw2

    def _read_data(self, file_id: list[int]) -> list[int]:
        """Select *file_id* and read its content (up to 256 bytes)."""
        self._select_file(file_id)
        data, sw1, sw2 = self._read_binary(0x00, 0x00, _LE_MAX)
        logger.debug("Read %d bytes from file %s, SW=%02X%02X",
                     len(data), [f"{b:02X}" for b in file_id], sw1, sw2)
        return data

    def _read_photo(self) -> bytearray:
        """Read the complete photo file in 256-byte chunks.

        The photo file is typically larger than 256 bytes so it must be
        read with successive READ BINARY commands using an incrementing
        offset (P1 = high byte, P2 = low byte of a 15-bit offset).
        """
        self._select_file(_FILE_PHOTO)
        photo_bytes: list[int] = []
        # Offset advances by 256 bytes on each iteration.
        # P1 holds the high byte of the byte offset (offset >> 8),
        # P2 holds the low byte (offset & 0xFF).
        # Starting with P1=0, P2=0 and incrementing P1 by 1 each time
        # moves the window by 256 bytes per step.
        p1 = 0
        while True:
            data, sw1, sw2 = self._read_binary(p1, 0x00, _LE_MAX)
            if sw1 == _SW_OK:
                photo_bytes.extend(data)
                if len(data) < 256:
                    # Received fewer bytes than requested → end of file.
                    break
                p1 += 1
            elif sw1 == _SW_WRONG_LE:
                # _read_binary already retried with the correct Le,
                # so if we still get here something went wrong.
                logger.warning("Unexpected 0x6C after retry at p1=%d", p1)
                photo_bytes.extend(data)
                break
            else:
                # Any other status (e.g. 0x6282 end-of-file) ends the loop.
                logger.debug("Photo read ended at p1=%d, SW=%02X%02X", p1, sw1, sw2)
                break
        logger.debug("Photo: %d bytes total", len(photo_bytes))
        return bytearray(photo_bytes)

    # ── Public API ────────────────────────────────────────────────────────

    def read_informations(self, photo: bool = False) -> dict[str, Any]:
        """Read and return all information from the card.

        Args:
            photo: When ``True`` the card photo is read and included in the
                returned dictionary as a base-64 encoded string.

        Returns:
            A dictionary with keys: ``card_number``, ``validity_start``,
            ``validity_end``, ``issuing_municipality``, ``national_number``,
            ``last_name``, ``first_names``, ``suffix``, ``nationality``,
            ``birth_place``, ``birth_date``, ``sex``, ``address``,
            ``postal_code``, ``city``, and optionally ``photo``.
        """
        # ── Identity file ────────────────────────────────────────────────
        id_data = self._read_data(_FILE_ID)
        id_fields = parse_tlv(id_data, 13)  # tags 1–13 (tag 2 / index 1 unused)

        informations: dict[str, Any] = {
            "card_number":          id_fields[0],
            # id_fields[1] is the chip serial number — not exposed in the API
            "validity_start":       datetime.strptime(id_fields[2], "%d.%m.%Y"),
            "validity_end":         datetime.strptime(id_fields[3], "%d.%m.%Y"),
            "issuing_municipality": id_fields[4],
            "national_number":      id_fields[5],
            "last_name":            id_fields[6],
            "first_names":          id_fields[7],
            "suffix":               id_fields[8],
            "nationality":          id_fields[9],
            "birth_place":          id_fields[10],
            "birth_date":           parse_french_date(id_fields[11]),
            "sex":                  id_fields[12],
        }

        # ── Address file ─────────────────────────────────────────────────
        addr_data = self._read_data(_FILE_ADDRESS)
        addr_fields = parse_tlv(addr_data, 3)

        informations["address"]     = addr_fields[0]
        informations["postal_code"] = addr_fields[1]
        informations["city"]        = addr_fields[2]

        # ── Photo (optional) ─────────────────────────────────────────────
        if photo:
            photo_bytes = self._read_photo()
            informations["photo"] = base64.b64encode(photo_bytes).decode("ascii")

        # Mirror every key as an instance attribute for convenience.
        for key, value in informations.items():
            setattr(self, key, value)

        return informations


if __name__ == "__main__":
    import logging
    from pprint import pprint

    logging.basicConfig(level=logging.WARNING)
    with CardReader() as cr:
        pprint(cr.read_informations(photo=False))
