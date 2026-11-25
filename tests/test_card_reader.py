"""Tests of the PC/SC transport, against a simulated card."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import datetime
from typing import Any

import pytest
from smartcard import scard
from smartcard.Exceptions import (
    CardConnectionException,
    CardRequestTimeoutException,
    NoCardException,
)
from smartcard.pcsc.PCSCExceptions import EstablishContextException
from smartcard.scard import SCARD_LEAVE_CARD

from pythonbeid import (
    APDUError,
    CardCommunicationError,
    CardDataError,
    CardFile,
    CardInUseError,
    CardReader,
    NoCardError,
    NoReaderError,
    PCSCServiceError,
    UnsupportedCardError,
    list_readers,
)
from pythonbeid import card_reader as card_reader_module

from .builders import PHOTO, Pki, identity_file, signed_files
from .conftest import card_from
from .fake_card import FakeCard, removed_error, reset_error

Install = "Callable[..., list[FakeReader]]"


def _reads(card: FakeCard) -> list[bytes]:
    return [apdu for apdu in card.log if apdu[1] == 0xB0]


# ── Reader listing and selection ──────────────────────────────────────────


class TestListReaders:
    def test_names(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(("ACS ACR38U 0", card17), ("Other 1", None))
        assert list_readers() == ["ACS ACR38U 0", "Other 1"]

    def test_empty(self, install_readers: Any) -> None:
        install_readers()
        assert list_readers() == []

    def test_service_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fail() -> list[Any]:
            raise EstablishContextException(scard.SCARD_E_NO_SERVICE)

        monkeypatch.setattr(card_reader_module, "_pcsc_readers", fail)
        with pytest.raises(PCSCServiceError, match="PC/SC service unavailable"):
            list_readers()
        with pytest.raises(NoReaderError):
            CardReader()


class TestReaderSelection:
    def test_no_reader(self, install_readers: Any) -> None:
        install_readers()
        with pytest.raises(NoReaderError, match="No smart card reader"):
            CardReader()

    def test_auto_skips_empty_and_foreign_cards(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        bank_card = FakeCard(files={}, is_beid=False)
        install_readers(("Empty", None), ("Bank", bank_card), ("Belgian", card17))
        with CardReader() as reader:
            assert reader.reader_name == "Belgian"
        assert bank_card.disconnect_calls == 1

    def test_auto_without_card(self, install_readers: Any) -> None:
        install_readers(("Empty 0", None), ("Empty 1", None))
        with pytest.raises(NoCardError, match="'Empty 0', 'Empty 1'"):
            CardReader()

    def test_index(
        self, install_readers: Any, card17: FakeCard, card18: FakeCard
    ) -> None:
        install_readers(card17, card18)
        with CardReader(1) as reader:
            assert reader.card_info.applet_version == 0x18

    @pytest.mark.parametrize("index", [2, -1])
    def test_index_out_of_range(
        self, install_readers: Any, card17: FakeCard, index: int
    ) -> None:
        install_readers(card17, card17)
        with pytest.raises(NoReaderError, match="out of range"):
            CardReader(index)

    def test_exact_name(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(("ACS ACR38U 0", None), ("ACS ACR38U 1", card17))
        with CardReader("ACS ACR38U 1") as reader:
            assert reader.reader_name == "ACS ACR38U 1"

    def test_name_substring(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(
            ("Alcor Micro USB Smart Card Reader 0", None), ("ACS ACR38U 0", card17)
        )
        with CardReader("acr38") as reader:
            assert reader.reader_name == "ACS ACR38U 0"

    def test_ambiguous_name(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(("ACS ACR38U 0", card17), ("ACS ACR38U 1", card17))
        with pytest.raises(NoReaderError, match="ambiguous"):
            CardReader("ACR38U")

    def test_unknown_name(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(("ACS ACR38U 0", card17))
        with pytest.raises(NoReaderError, match="No reader matches 'Gemalto'"):
            CardReader("Gemalto")

    @pytest.mark.parametrize("value", [True, 1.5, b"name"])
    def test_invalid_reader_type(
        self, install_readers: Any, card17: FakeCard, value: Any
    ) -> None:
        install_readers(card17)
        with pytest.raises(TypeError, match="index or a name"):
            CardReader(value)

    def test_explicit_reader_without_card(self, install_readers: Any) -> None:
        install_readers(("Empty", None))
        with pytest.raises(NoCardError):
            CardReader(0)

    def test_explicit_foreign_card(self, install_readers: Any) -> None:
        install_readers(FakeCard(files={}, is_beid=False))
        with pytest.raises(UnsupportedCardError, match="not a Belgian eID card"):
            CardReader(0)

    def test_deprecated_reader_index(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(None, card17)
        with pytest.deprecated_call(), CardReader(reader_index=1) as reader:
            assert reader.reader_name == "Fake Reader 1"

    def test_reader_and_reader_index(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with pytest.deprecated_call(), pytest.raises(TypeError, match="not both"):
            CardReader(0, reader_index=0)

    @pytest.mark.parametrize("size", [0, 257])
    def test_invalid_chunk_size(
        self, install_readers: Any, card17: FakeCard, size: int
    ) -> None:
        install_readers(card17)
        with pytest.raises(ValueError, match="chunk_size"):
            CardReader(chunk_size=size)


class TestWaitForCard:
    @staticmethod
    def _request(on_wait: Any, seen: dict[str, Any] | None = None) -> type:
        class Request:
            def __init__(self, **kwargs: Any) -> None:
                if seen is not None:
                    seen.update(kwargs)

            def waitforcard(self) -> None:
                on_wait()

        return Request

    @staticmethod
    def _timeout() -> None:
        raise CardRequestTimeoutException

    @staticmethod
    def _clock(monkeypatch: pytest.MonkeyPatch, *values: float) -> None:
        ticks = iter(values)
        last = [values[-1]]

        def monotonic() -> float:
            last[0] = next(ticks, last[0])
            return last[0]

        monkeypatch.setattr("pythonbeid.card_reader.time.monotonic", monotonic)

    def test_waits_for_insertion(
        self, install_readers: Any, card17: FakeCard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        readers = install_readers(("Slot", None))
        seen: dict[str, Any] = {}

        def insert() -> None:
            readers[0].card = card17

        monkeypatch.setattr(
            card_reader_module, "CardRequest", self._request(insert, seen)
        )
        with CardReader(timeout=5) as reader:
            assert reader.reader_name == "Slot"
        assert seen["timeout"] == 1.0  # the readers are rescanned every second
        assert seen["newcardonly"] is True

    def test_other_card_does_not_end_the_wait(
        self, install_readers: Any, card17: FakeCard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bank card in reader 0 must not hide the eID inserted in reader 1."""
        bank = FakeCard(files={}, is_beid=False)
        readers = install_readers(("Bank", bank), ("Slot", None))
        calls = {"count": 0}

        def insert_later() -> None:
            calls["count"] += 1
            if calls["count"] == 2:
                readers[1].card = card17
            else:
                raise CardRequestTimeoutException

        monkeypatch.setattr(
            card_reader_module, "CardRequest", self._request(insert_later)
        )
        with CardReader(timeout=30) as reader:
            assert reader.reader_name == "Slot"
        assert calls["count"] == 2

    def test_infinite_timeout(
        self, install_readers: Any, card17: FakeCard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        readers = install_readers(("Slot", None))
        seen: dict[str, Any] = {}

        def insert() -> None:
            readers[0].card = card17

        monkeypatch.setattr(
            card_reader_module, "CardRequest", self._request(insert, seen)
        )
        CardReader(timeout=float("inf")).close()
        assert seen["timeout"] == 1.0

    def test_timeout_expires(
        self, install_readers: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install_readers(("Slot", None))
        self._clock(monkeypatch, 100.0, 100.0, 100.3, 100.6)
        seen: dict[str, Any] = {}
        monkeypatch.setattr(
            card_reader_module, "CardRequest", self._request(self._timeout, seen)
        )
        with pytest.raises(NoCardError, match=r"within 0\.5 s"):
            CardReader(timeout=0.5)
        assert seen["timeout"] == pytest.approx(0.2)

    def test_explicit_reader_rejects_foreign_card(
        self, install_readers: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        readers = install_readers(("Slot", None))

        def insert() -> None:
            readers[0].card = FakeCard(files={}, is_beid=False)

        monkeypatch.setattr(card_reader_module, "CardRequest", self._request(insert))
        with pytest.raises(UnsupportedCardError):
            CardReader("Slot", timeout=5)

    def test_wait_error(
        self, install_readers: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install_readers(("Slot", None))

        def fail() -> None:
            raise CardConnectionException("boom")

        monkeypatch.setattr(card_reader_module, "CardRequest", self._request(fail))
        with pytest.raises(CardCommunicationError, match="waiting for a card"):
            CardReader(timeout=1)


# ── Connection lifecycle ──────────────────────────────────────────────────


class TestConnection:
    def test_leaves_card_powered(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        CardReader().close()
        assert card17.connect_kwargs["disposition"] == SCARD_LEAVE_CARD

    def test_close_is_idempotent(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        reader = CardReader()
        reader.close()
        reader.close()
        assert card17.disconnect_calls == 1
        assert repr(reader) == "<CardReader reader='Fake Reader 0' closed>"

    def test_close_ignores_errors(self, install_readers: Any, card17: FakeCard) -> None:
        card17.disconnect_error = CardConnectionException("gone")
        install_readers(card17)
        CardReader().close()

    def test_use_after_close(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        reader = CardReader()
        reader.close()
        with pytest.raises(CardCommunicationError, match="closed"):
            reader.read_identity()

    def test_context_manager_and_repr(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            assert repr(reader) == "<CardReader reader='Fake Reader 0' open>"
        assert card17.disconnect_calls == 1

    def test_atr(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            assert reader.atr == card17.atr

    @pytest.mark.parametrize(
        "error",
        [
            NoCardException("No card", 0),
            CardConnectionException("x", hresult=scard.SCARD_E_NO_SMARTCARD),
        ],
    )
    def test_connect_no_card(
        self, install_readers: Any, card17: FakeCard, error: Exception
    ) -> None:
        card17.connect_error = error
        install_readers(card17)
        with pytest.raises(NoCardError):
            CardReader(0)

    def test_connect_failure(self, install_readers: Any, card17: FakeCard) -> None:
        card17.connect_error = CardConnectionException("protocol mismatch")
        install_readers(card17)
        with pytest.raises(CardCommunicationError, match="Connection error"):
            CardReader(0)

    def test_card_removed_during_card_data(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        card17.transmit_errors = [removed_error()]
        install_readers(card17)
        with pytest.raises(NoCardError, match="No Belgian eID card in reader"):
            CardReader(0)
        assert card17.disconnect_calls == 1


# ── APDU handling ─────────────────────────────────────────────────────────


class TestReadFile:
    def test_file_multiple_of_chunk(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        """A file of exactly 2 blocks ends with 6B00, which is not an error."""
        content = bytes(range(252)) * 2
        card17.files[CardFile.PHOTO.path] = content
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_photo() == content
        offsets = [(apdu[2] << 8) | apdu[3] for apdu in _reads(card17)]
        assert offsets == [0, 252, 504]

    def test_short_last_block_uses_6c(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_photo() == PHOTO
        assert any(apdu[4] == len(PHOTO) % 252 for apdu in _reads(card17))

    def test_6c_retry_delay_on_global_os_1(
        self, install_readers: Any, card18: FakeCard, no_sleep: list[float]
    ) -> None:
        install_readers(card18)
        with CardReader() as reader:
            reader.read_identity()
        assert no_sleep
        assert set(no_sleep) == {0.05}

    def test_no_delay_on_global_os_3(
        self, install_readers: Any, card17: FakeCard, no_sleep: list[float]
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            reader.read_identity()
        assert no_sleep == []

    def test_get_response(self, install_readers: Any, card17: FakeCard) -> None:
        card17.get_response_mode = True
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_photo() == PHOTO
        assert any(apdu[1] == 0xC0 for apdu in card17.log)

    def test_eof_warning(self, install_readers: Any, card17: FakeCard) -> None:
        card17.eof_warning = True
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_photo() == PHOTO

    def test_chunk_size_256_sends_le_zero(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader(chunk_size=256) as reader:
            assert reader.read_photo() == PHOTO
        assert _reads(card17)[0][4] == 0x00

    def test_small_chunk_size(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader(chunk_size=64) as reader:
            assert reader.read_photo() == PHOTO

    def test_path_as_bytes_or_list(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_file(bytes.fromhex("3F00DF014035")) == PHOTO
            assert reader.read_file([0x3F, 0x00, 0xDF, 0x01, 0x40, 0x35]) == PHOTO

    def test_missing_file(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with (
            CardReader() as reader,
            pytest.raises(APDUError, match="file not found") as info,
        ):
            reader.read_file(CardFile.BASIC_PUBLIC_KEY)
        assert info.value.sw == 0x6A82

    def test_applet_reselection(self, install_readers: Any, card17: FakeCard) -> None:
        card17.require_applet_select = True
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_identity().last_name == "Specimen"
        assert any(apdu[:3] == b"\x00\xa4\x04" for apdu in card17.log)

    def test_unexpected_status(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            card17.is_beid = False
            with pytest.raises(APDUError, match="SW=6E00 \\(class not supported\\)"):
                reader.read_identity()

    def test_unknown_status_message(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            card17.files[CardFile.PHOTO.path] = b""  # 6B00 at offset 0 is an error
            with pytest.raises(APDUError, match="offset outside the file"):
                reader.read_photo()

    def test_offset_limit(self, install_readers: Any, card17: FakeCard) -> None:
        card17.files[CardFile.PHOTO.path] = bytes(0x8100)
        install_readers(card17)
        with (
            CardReader(chunk_size=256) as reader,
            pytest.raises(CardDataError, match="offset range"),
        ):
            reader.read_photo()

    def test_endless_get_response(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            card17.transmit = lambda apdu: ([], 0x61, 0x10)  # type: ignore[method-assign]
            with pytest.raises(CardCommunicationError, match="GET RESPONSE"):
                reader.read_identity()

    def test_persistent_6c(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            original = card17.transmit
            card17.transmit = lambda apdu: (  # type: ignore[method-assign]
                ([], 0x6C, 0x10) if apdu[1] == 0xB0 else original(apdu)
            )
            with pytest.raises(APDUError, match="SW=6C10"):
                reader.read_identity()

    def test_read_certificate_trims_padding(
        self, install_readers: Any, card17: FakeCard, rsa_pki: Pki
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            certificate = reader.read_certificate(CardFile.RRN_CERTIFICATE)
        assert rsa_pki.rrn_file.startswith(certificate)
        assert len(certificate) == len(rsa_pki.rrn_file) - 64

    def test_read_certificate_rejects_other_files(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with (
            CardReader() as reader,
            pytest.raises(ValueError, match="not a certificate"),
        ):
            reader.read_certificate(CardFile.PHOTO)

    def test_read_card_info_again(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            first = reader.card_info
            assert reader.read_card_info() == first


class TestTransactions:
    def test_each_file_in_a_transaction(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            before = card17.lock_calls
            reader.read_identity()
            reader.read_address()
        assert card17.lock_calls - before == 2
        assert card17.lock_calls == card17.unlock_calls

    def test_read_uses_a_single_transaction(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            before = card17.lock_calls
            reader.read()
        assert card17.lock_calls - before == 1
        assert card17.lock_calls == card17.unlock_calls

    def test_unlock_errors_are_ignored(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        card17.unlock_error = CardConnectionException("removed")
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_identity().last_name == "Specimen"

    def test_lock_failure(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            card17.lock = lambda: (_ for _ in ()).throw(CardConnectionException("busy"))  # type: ignore[method-assign]
            with pytest.raises(CardCommunicationError, match="busy"):
                reader.read_identity()

    def test_reset_is_recovered(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            card17.transmit_errors = [reset_error()]
            assert reader.read_photo() == PHOTO
        assert card17.reconnect_calls == 1

    def test_reset_inside_read_relocks(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            before = card17.lock_calls
            card17.transmit_errors = [reset_error()]
            eid = reader.read()
        assert eid.photo == PHOTO
        assert card17.reconnect_calls == 1
        assert card17.lock_calls - before == 2

    def test_reset_when_locking(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            calls = {"count": 0}
            original = card17.lock

            def lock() -> None:
                calls["count"] += 1
                if calls["count"] == 1:
                    raise reset_error()
                original()

            card17.lock = lock  # type: ignore[method-assign]
            assert reader.read_identity().last_name == "Specimen"
        assert card17.reconnect_calls == 1

    def test_repeated_reset(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            card17.transmit_errors = [reset_error(), reset_error()]
            with pytest.raises(CardCommunicationError, match="reset repeatedly"):
                reader.read_identity()

    def test_card_removed(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            card17.transmit_errors = [NoCardException("gone", 0)]
            with pytest.raises(NoCardError, match="removed"):
                reader.read_identity()
            card17.transmit_errors = [removed_error()]
            with pytest.raises(NoCardError, match="removed"):
                reader.read_identity()

    def test_other_transport_error(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            card17.transmit_errors = [
                CardConnectionException("timeout", hresult=scard.SCARD_E_TIMEOUT)
            ]
            with pytest.raises(CardCommunicationError, match="Communication error"):
                reader.read_identity()


# ── High-level reads ──────────────────────────────────────────────────────


class TestRead:
    def test_read_everything(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            eid = reader.read()
        assert eid.identity.last_name == "Specimen"
        assert eid.address.street == "Rue de la Loi 16"
        assert eid.photo == PHOTO
        assert eid.card is not None
        assert eid.card.applet_version_string == "1.7"
        assert set(eid.files) == {
            CardFile.IDENTITY,
            CardFile.ADDRESS,
            CardFile.PHOTO,
            CardFile.IDENTITY_SIGNATURE,
            CardFile.ADDRESS_SIGNATURE,
            CardFile.RRN_CERTIFICATE,
        }

    def test_read_minimal(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader:
            eid = reader.read(photo=False, integrity=False)
        assert eid.photo is None
        assert set(eid.files) == {CardFile.IDENTITY, CardFile.ADDRESS}

    def test_read_applet_18_includes_basic_key(
        self, install_readers: Any, card18: FakeCard
    ) -> None:
        install_readers(card18)
        with CardReader() as reader:
            eid = reader.read()
        assert CardFile.BASIC_PUBLIC_KEY in eid.files
        assert eid.card is not None
        assert eid.card.pin_attempts_left == 3

    def test_read_identity_and_address(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_identity().national_number_valid
            assert reader.read_address().postal_code == "1000"


class TestChip:
    def test_authenticate_genuine_chip(
        self, install_readers: Any, card18: FakeCard
    ) -> None:
        install_readers(card18)
        with CardReader() as reader:
            assert reader.authenticate_chip() is True

    def test_challenge_answer(self, install_readers: Any, card18: FakeCard) -> None:
        install_readers(card18)
        with CardReader() as reader:
            assert len(reader.challenge(bytes(48))) == 96
        command = next(apdu for apdu in card18.log if apdu[1] == 0x88)
        assert command[:7] == bytes([0x00, 0x88, 0x02, 0x81, 50, 0x94, 48])

    def test_cloned_chip(
        self, install_readers: Any, ec_pki: Pki, basic_key: Any
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        impostor = card_from(
            signed_files(ec_pki, basic_key=basic_key),
            applet=0x18,
            basic_key=ec.generate_private_key(ec.SECP384R1()),
        )
        install_readers(impostor)
        with CardReader() as reader:
            assert reader.authenticate_chip() is False

    def test_applet_17_has_no_basic_key(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            with pytest.raises(UnsupportedCardError, match="no basic key"):
                reader.authenticate_chip()
            with pytest.raises(APDUError):
                reader.challenge(bytes(48))

    def test_unverified_key_is_rejected(
        self, install_readers: Any, ec_pki: Pki, basic_key: Any
    ) -> None:
        """An impostor serving its own key pair must not pass."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        impostor_key = ec.generate_private_key(ec.SECP384R1())
        files = signed_files(ec_pki, basic_key=basic_key)
        files[CardFile.BASIC_PUBLIC_KEY] = impostor_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        install_readers(card_from(files, applet=0x18, basic_key=impostor_key))
        with CardReader() as reader:
            assert reader.authenticate_chip() is False

    def test_reference_identity(self, install_readers: Any, card18: FakeCard) -> None:
        install_readers(card18)
        with CardReader() as reader:
            identity = reader.read_identity()
            assert reader.authenticate_chip(identity) is True
            assert (
                reader.authenticate_chip(replace(identity, basic_key_hash=bytes(48)))
                is False
            )

    def test_garbage_key_file(
        self, install_readers: Any, ec_pki: Pki, basic_key: Any
    ) -> None:
        files = signed_files(ec_pki, basic_key=basic_key)
        files[CardFile.BASIC_PUBLIC_KEY] = b"\x30\x03abc"
        identity = identity_file(tag_1A=hashlib.sha384(b"\x30\x03abc").digest())
        files[CardFile.IDENTITY] = identity
        install_readers(card_from(files, applet=0x18, basic_key=basic_key))
        with CardReader() as reader:
            assert reader.authenticate_chip() is False

    @pytest.mark.parametrize("size", [0, 254])
    def test_nonce_size(
        self, install_readers: Any, card18: FakeCard, size: int
    ) -> None:
        install_readers(card18)
        with CardReader() as reader, pytest.raises(ValueError, match="nonce"):
            reader.challenge(bytes(size))


class TestVerify:
    def test_verify_applet_17(
        self, install_readers: Any, card17: FakeCard, rsa_pki: Pki
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            report = reader.verify(trusted_roots=[rsa_pki.root_pem])
        assert report.is_valid
        assert report.chip_authenticated is None

    def test_verify_applet_18_with_chip(
        self, install_readers: Any, card18: FakeCard, ec_pki: Pki
    ) -> None:
        install_readers(card18)
        with CardReader() as reader:
            report = reader.verify(trusted_roots=[ec_pki.root_pem])
        assert report.is_valid
        assert report.basic_key_valid is True
        assert report.chip_authenticated is True

    def test_verify_without_chip(
        self, install_readers: Any, card18: FakeCard, ec_pki: Pki
    ) -> None:
        install_readers(card18)
        with CardReader() as reader:
            report = reader.verify(
                authenticate_chip=False, trusted_roots=[ec_pki.root_pem]
            )
        assert report.chip_authenticated is None

    def test_verify_reuses_data(
        self, install_readers: Any, card17: FakeCard, rsa_pki: Pki
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            eid = reader.read()
            count = len(card17.log)
            assert reader.verify(eid, trusted_roots=[rsa_pki.root_pem]).is_valid
        assert len(card17.log) == count

    def test_verify_cloned_chip(
        self, install_readers: Any, ec_pki: Pki, basic_key: Any
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        impostor = card_from(
            signed_files(ec_pki, basic_key=basic_key),
            applet=0x18,
            basic_key=ec.generate_private_key(ec.SECP384R1()),
        )
        install_readers(impostor)
        with CardReader() as reader:
            report = reader.verify(trusted_roots=[ec_pki.root_pem])
        assert not report.is_valid
        assert report.chip_authenticated is False
        assert "chip challenge failed" in report.errors[-1]


class TestLegacyApi:
    def test_read_informations(self, install_readers: Any, card17: FakeCard) -> None:
        install_readers(card17)
        with CardReader() as reader, pytest.deprecated_call():
            info = reader.read_informations()
        assert set(info) == {
            "card_number", "validity_start", "validity_end", "issuing_municipality",
            "national_number", "last_name", "first_names", "suffix", "nationality",
            "birth_place", "birth_date", "sex", "address", "postal_code", "city",
        }  # fmt: skip
        assert info["birth_date"] == datetime(1985, 3, 24)  # noqa: DTZ001
        assert isinstance(info["validity_start"], datetime)
        assert info["suffix"] == "B"
        assert info["sex"] == "F"
        assert info["city"] == "Bruxelles"
        assert reader.last_name == "Specimen"  # type: ignore[attr-defined]

    def test_read_informations_photo(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader, pytest.deprecated_call():
            info = reader.read_informations(True)
        assert base64.b64decode(info["photo"]) == PHOTO

    def test_incomplete_birth_date(self, install_readers: Any, rsa_pki: Pki) -> None:
        card = card_from(signed_files(rsa_pki, identity=identity_file(tag_0C="1984")))
        install_readers(card)
        with CardReader() as reader, pytest.deprecated_call():
            assert reader.read_informations()["birth_date"] is None


class TestTransactionalConnection:
    """The real decorator, with the PC/SC functions replaced."""

    class _Component:
        hcard = 1234

        def __init__(self) -> None:
            self.component = None

    @pytest.fixture
    def scard_calls(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        calls: dict[str, Any] = {
            "begin": [],
            "end": [],
            "result": scard.SCARD_S_SUCCESS,
        }

        def begin(hcard: int) -> int:
            calls["begin"].append(hcard)
            return int(calls["result"])

        def end(hcard: int, disposition: int) -> int:
            calls["end"].append((hcard, disposition))
            return int(calls["result"])

        monkeypatch.setattr(card_reader_module, "SCardBeginTransaction", begin)
        monkeypatch.setattr(card_reader_module, "SCardEndTransaction", end)
        return calls

    def test_finds_nested_handle(self, scard_calls: dict[str, Any]) -> None:
        inner = self._Component()
        middle = type("Middle", (), {"component": inner})()
        connection = card_reader_module._wrap_connection(middle)
        connection.lock()
        connection.unlock()
        assert scard_calls["begin"] == [1234]
        assert scard_calls["end"] == [(1234, SCARD_LEAVE_CARD)]

    @pytest.mark.parametrize("method", ["lock", "unlock"])
    def test_failure_keeps_hresult(
        self, scard_calls: dict[str, Any], method: str
    ) -> None:
        scard_calls["result"] = scard.SCARD_W_RESET_CARD
        connection = card_reader_module._wrap_connection(self._Component())
        with pytest.raises(CardConnectionException) as info:
            getattr(connection, method)()
        assert info.value.hresult == scard.SCARD_W_RESET_CARD


class TestReviewFindings:
    """Regression tests for issues found by an independent review."""

    def test_downgraded_card_data_still_challenged(
        self, install_readers: Any, ec_pki: Pki, basic_key: Any
    ) -> None:
        """A clone claiming applet 1.7 must not skip the chip challenge."""
        clone = card_from(signed_files(ec_pki, basic_key=basic_key), applet=0x17)
        install_readers(clone)
        with CardReader() as reader:
            eid = reader.read()
            assert CardFile.BASIC_PUBLIC_KEY in eid.files
            report = reader.verify(eid, trusted_roots=[ec_pki.root_pem])
        assert report.basic_key_valid is True
        assert report.chip_authenticated is False
        assert not report.is_valid

    def test_missing_key_file_fails_closed(
        self, install_readers: Any, card18: FakeCard, ec_pki: Pki
    ) -> None:
        install_readers(card18)
        with CardReader() as reader:
            eid = reader.read()
            files = dict(eid.files)
            del files[CardFile.BASIC_PUBLIC_KEY]
            report = reader.verify(
                replace(eid, files=files), trusted_roots=[ec_pki.root_pem]
            )
        assert report.basic_key_valid is False
        assert not report.is_valid

    def test_repeated_reset_when_locking(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:

            def lock() -> None:
                raise reset_error()

            card17.lock = lock  # type: ignore[method-assign]
            with pytest.raises(CardCommunicationError, match="reset repeatedly"):
                reader.read()

    def test_reset_while_relocking(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:
            original = card17.lock
            calls = {"count": 0}

            def lock() -> None:
                calls["count"] += 1
                if calls["count"] > 1:
                    raise reset_error()
                original()

            card17.lock = lock  # type: ignore[method-assign]
            card17.transmit_errors = [reset_error()]
            with pytest.raises(CardCommunicationError, match="reset repeatedly"):
                reader.read()
            assert repr(reader).endswith("closed>")

    def test_failed_reconnect_closes_the_connection(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        install_readers(card17)
        with CardReader() as reader:

            def reconnect(*_: Any) -> None:
                raise NoCardException("gone", 0)

            card17.reconnect = reconnect  # type: ignore[method-assign,assignment]
            card17.transmit_errors = [reset_error()]
            with pytest.raises(NoCardError):
                reader.read_identity()
            with pytest.raises(CardCommunicationError, match="closed"):
                reader.read_identity()

    def test_create_connection_failure(self, install_readers: Any) -> None:
        readers = install_readers(("Broken", None))

        def fail() -> Any:
            raise CardConnectionException("SCardEstablishContext failed")

        readers[0].createConnection = fail
        with pytest.raises(CardCommunicationError, match="Connection error"):
            CardReader(0)

    def test_empty_certificate_slot(
        self, install_readers: Any, card17: FakeCard
    ) -> None:
        card17.files[CardFile.SIGNING_CERTIFICATE.path] = bytes(1900)
        install_readers(card17)
        with CardReader() as reader, pytest.raises(CardDataError, match="SEQUENCE"):
            reader.read_certificate(CardFile.SIGNING_CERTIFICATE)

    def test_chip_challenge_refused(
        self, install_readers: Any, ec_pki: Pki, basic_key: Any
    ) -> None:
        card = card_from(signed_files(ec_pki, basic_key=basic_key), applet=0x18)
        install_readers(card)  # no private key: INTERNAL AUTHENTICATE fails
        with CardReader() as reader:
            report = reader.verify(trusted_roots=[ec_pki.root_pem])
        assert report.chip_authenticated is False

    def test_undecodable_identity_skips_challenge(
        self, install_readers: Any, card18: FakeCard, ec_pki: Pki
    ) -> None:
        install_readers(card18)
        with CardReader() as reader:
            eid = reader.read()
            files = dict(eid.files)
            files[CardFile.IDENTITY] = b"\x01\x09"
            report = reader.verify(
                replace(eid, files=files), trusted_roots=[ec_pki.root_pem]
            )
        assert not report.is_valid
        assert report.chip_authenticated is None


class TestCardInUse:
    """A card held exclusively by another application (SCARD_E_SHARING_VIOLATION)."""

    @staticmethod
    def _busy() -> CardConnectionException:
        return CardConnectionException(
            "in use", hresult=scard.SCARD_E_SHARING_VIOLATION
        )

    def test_retried_until_released(
        self, install_readers: Any, card17: FakeCard, no_sleep: list[float]
    ) -> None:
        attempts = {"count": 0}
        original = card17.connect

        def connect(*args: Any, **kwargs: Any) -> None:
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise self._busy()
            original(*args, **kwargs)

        card17.connect = connect  # type: ignore[method-assign]
        install_readers(card17)
        with CardReader() as reader:
            assert reader.read_identity().last_name == "Specimen"
        assert attempts["count"] == 3
        assert no_sleep == [0.5, 0.5]

    def test_explicit_reader(
        self, install_readers: Any, card17: FakeCard, no_sleep: list[float]
    ) -> None:
        card17.connect_error = self._busy()
        install_readers(("ACS ACR38U 0", card17))
        with pytest.raises(CardInUseError, match="used exclusively by another"):
            CardReader(0)
        assert len(no_sleep) == 2

    def test_automatic_selection_reports_it(
        self, install_readers: Any, card17: FakeCard, no_sleep: list[float]
    ) -> None:
        card17.connect_error = self._busy()
        install_readers(("Empty", None), ("Busy", card17))
        with pytest.raises(CardInUseError, match="'Busy'"):
            CardReader()

    def test_automatic_selection_prefers_a_free_card(
        self,
        install_readers: Any,
        card17: FakeCard,
        card18: FakeCard,
        no_sleep: list[float],
    ) -> None:
        card17.connect_error = self._busy()
        install_readers(("Busy", card17), ("Free", card18))
        with CardReader() as reader:
            assert reader.reader_name == "Free"

    def test_reported_after_waiting(
        self,
        install_readers: Any,
        card17: FakeCard,
        no_sleep: list[float],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        card17.connect_error = self._busy()
        install_readers(("Busy", card17))
        TestWaitForCard._clock(monkeypatch, 0.0, 0.0, 5.0)
        monkeypatch.setattr(
            card_reader_module,
            "CardRequest",
            TestWaitForCard._request(TestWaitForCard._timeout),
        )
        with pytest.raises(CardInUseError):
            CardReader(timeout=2)
