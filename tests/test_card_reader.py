"""Tests for CardReader.

Hardware-independent tests use unittest.mock to stub _send_apdu.
Integration tests (require a real card) are skipped automatically when
no reader is available.
"""
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, call

from pythonbeid.exceptions import APDUError, NoReaderError, NoCardError
from pythonbeid.parser import parse_tlv


# ── Helpers ───────────────────────────────────────────────────────────────

def _tlv(*fields: str) -> list[int]:
    buf: list[int] = []
    for i, text in enumerate(fields, start=1):
        raw = text.encode("utf-8")
        buf += [i, len(raw)] + list(raw)
    return buf


def _make_reader(apdu_side_effect=None, apdu_return_value=None):
    """Return a CardReader whose _send_apdu is fully mocked."""
    from pythonbeid.card_reader import CardReader

    mock_cnx = MagicMock()
    mock_reader = MagicMock()
    mock_reader.createConnection.return_value = mock_cnx

    with patch("pythonbeid.card_reader.readers", return_value=[mock_reader]):
        cr = CardReader()

    if apdu_side_effect is not None:
        cr._send_apdu = MagicMock(side_effect=apdu_side_effect)
    elif apdu_return_value is not None:
        cr._send_apdu = MagicMock(return_value=apdu_return_value)
    return cr


# ── CardReader construction ───────────────────────────────────────────────

class TestCardReaderInit:
    def test_no_readers_raises(self):
        from pythonbeid.card_reader import CardReader
        with patch("pythonbeid.card_reader.readers", return_value=[]):
            with pytest.raises(NoReaderError):
                CardReader()

    def test_reader_index_out_of_range(self):
        from pythonbeid.card_reader import CardReader
        mock_reader = MagicMock()
        mock_cnx = MagicMock()
        mock_reader.createConnection.return_value = mock_cnx
        with patch("pythonbeid.card_reader.readers", return_value=[mock_reader]):
            with pytest.raises(NoReaderError):
                CardReader(reader_index=5)

    def test_no_card_raises(self):
        from pythonbeid.card_reader import CardReader
        from smartcard.Exceptions import NoCardException
        mock_reader = MagicMock()
        mock_cnx = MagicMock()
        # NoCardException requires (message, hresult) on Windows/pyscard.
        mock_cnx.connect.side_effect = NoCardException("No card", 0)
        mock_reader.createConnection.return_value = mock_cnx
        with patch("pythonbeid.card_reader.readers", return_value=[mock_reader]):
            with pytest.raises(NoCardError):
                CardReader()

    def test_context_manager(self):
        from pythonbeid.card_reader import CardReader
        mock_cnx = MagicMock()
        mock_reader = MagicMock()
        mock_reader.createConnection.return_value = mock_cnx
        with patch("pythonbeid.card_reader.readers", return_value=[mock_reader]):
            with CardReader() as cr:
                assert cr is not None
        mock_cnx.disconnect.assert_called_once()


# ── list_readers ──────────────────────────────────────────────────────────

class TestListReaders:
    def test_returns_reader_names(self):
        from pythonbeid.card_reader import list_readers
        mock_reader = MagicMock()
        mock_reader.__str__ = lambda self: "ACS ACR38U 0"
        with patch("pythonbeid.card_reader.readers", return_value=[mock_reader]):
            assert list_readers() == ["ACS ACR38U 0"]

    def test_empty_when_no_reader(self):
        from pythonbeid.card_reader import list_readers
        with patch("pythonbeid.card_reader.readers", return_value=[]):
            assert list_readers() == []

    def test_exported_at_package_level(self):
        import pythonbeid
        assert callable(pythonbeid.list_readers)


# ── _send_apdu error handling ────────────────────────────────────────────

class TestSendApdu:
    def test_ok_status_passes_through(self):
        cr = _make_reader()
        cr._cnx.transmit = MagicMock(return_value=([0x01, 0x02], 0x90, 0x00))
        data, sw1, sw2 = cr._send_apdu([0x00, 0xB0, 0x00, 0x00, 0x00])
        assert sw1 == 0x90

    def test_unexpected_status_raises_apdu_error(self):
        cr = _make_reader()
        cr._cnx.transmit = MagicMock(return_value=([], 0x69, 0x82))
        with pytest.raises(APDUError) as exc_info:
            cr._send_apdu([0x00, 0xB0, 0x00, 0x00, 0x00])
        assert exc_info.value.sw1 == 0x69
        assert exc_info.value.sw2 == 0x82


# ── _read_data (Le mismatch handling) ────────────────────────────────────

class TestReadData:
    def test_read_data_le_mismatch_retried(self):
        """0x6C on READ BINARY must trigger a retry with Le=SW2."""
        from pythonbeid.card_reader import _FILE_ID

        id_payload = _tlv("CARD001", "CHIP001", "01.01.2020", "01.01.2030",
                          "Brussels", "90010100115", "Smith", "John", "",
                          "BEL", "Brussels", "01 JANV 1990", "M")

        calls = iter([
            ([], 0x90, 0x00),       # SELECT → OK
            ([], 0x6C, 0x80),       # READ BINARY → wrong Le (expect 128)
            (id_payload, 0x90, 0x00),  # READ BINARY retry with Le=0x80 → OK
        ])

        cr = _make_reader(apdu_side_effect=lambda apdu: next(calls))
        data = cr._read_data(_FILE_ID)
        assert data == id_payload


# ── read_informations (full flow with mocked APDU) ────────────────────────

class TestReadInformations:
    def _build_responses(self, with_photo: bool = False):
        id_payload = _tlv(
            "CARD001",          # card_number
            "CHIP001",          # chip serial (index 1, ignored)
            "15.03.2020",       # validity_start
            "15.03.2030",       # validity_end
            "Brussels",         # issuing_municipality
            "90010100115",      # national_number
            "Smith",            # last_name
            "John",             # first_names
            "",                 # suffix
            "BEL",              # nationality
            "Brussels",         # birth_place
            "01 JANV 1990",     # birth_date
            "M",                # sex
        )
        addr_payload = _tlv("Rue de la Loi 1", "1000", "Brussels")

        # Build APDU call sequence:
        # SELECT ID → OK, READ BINARY ID → OK,
        # SELECT ADDR → OK, READ BINARY ADDR → OK
        responses = [
            ([], 0x90, 0x00),           # SELECT ID
            (id_payload, 0x90, 0x00),   # READ BINARY ID
            ([], 0x90, 0x00),           # SELECT ADDRESS
            (addr_payload, 0x90, 0x00), # READ BINARY ADDRESS
        ]

        if with_photo:
            photo_chunk = list(b"\xFF\xD8" + b"\x00" * 254)  # 256 bytes
            responses += [
                ([], 0x90, 0x00),               # SELECT PHOTO
                (photo_chunk, 0x90, 0x00),       # chunk 0 (full)
                (list(b"\xFF\xD9"), 0x90, 0x00), # chunk 1 (partial → EOF)
            ]

        return iter(responses)

    def test_identity_fields(self):
        responses = self._build_responses()
        cr = _make_reader(apdu_side_effect=lambda apdu: next(responses))
        info = cr.read_informations()
        assert info["card_number"] == "CARD001"
        assert info["last_name"] == "Smith"
        assert info["first_names"] == "John"
        assert info["birth_date"] == datetime(1990, 1, 1)
        assert info["nationality"] == "BEL"

    def test_address_fields(self):
        responses = self._build_responses()
        cr = _make_reader(apdu_side_effect=lambda apdu: next(responses))
        info = cr.read_informations()
        assert info["address"] == "Rue de la Loi 1"
        assert info["postal_code"] == "1000"
        assert info["city"] == "Brussels"

    def test_validity_dates_are_datetime(self):
        responses = self._build_responses()
        cr = _make_reader(apdu_side_effect=lambda apdu: next(responses))
        info = cr.read_informations()
        assert isinstance(info["validity_start"], datetime)
        assert isinstance(info["validity_end"], datetime)

    def test_attributes_set_on_instance(self):
        responses = self._build_responses()
        cr = _make_reader(apdu_side_effect=lambda apdu: next(responses))
        info = cr.read_informations()
        assert cr.last_name == info["last_name"]
        assert cr.birth_date == info["birth_date"]

    def test_photo_included_when_requested(self):
        responses = self._build_responses(with_photo=True)
        cr = _make_reader(apdu_side_effect=lambda apdu: next(responses))
        info = cr.read_informations(photo=True)
        assert "photo" in info
        assert isinstance(info["photo"], str)  # base64 string

    def test_photo_absent_by_default(self):
        responses = self._build_responses()
        cr = _make_reader(apdu_side_effect=lambda apdu: next(responses))
        info = cr.read_informations()
        assert "photo" not in info


# ── Integration test (real hardware) ─────────────────────────────────────

def _hardware_available() -> bool:
    try:
        from smartcard.System import readers as _readers
        from smartcard.Exceptions import NoCardException
        available = _readers()
        if not available:
            return False
        cnx = available[0].createConnection()
        cnx.connect()
        cnx.disconnect()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _hardware_available(), reason="No card reader / card available")
class TestIntegration:
    def test_read_informations_returns_dict(self):
        from pythonbeid import CardReader
        with CardReader() as cr:
            info = cr.read_informations()
        assert isinstance(info, dict)
        assert "card_number" in info
        assert "last_name" in info
        assert "birth_date" in info
        assert isinstance(info["birth_date"], datetime)
