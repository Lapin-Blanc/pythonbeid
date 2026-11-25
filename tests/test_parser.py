"""Tests of the pure decoding layer (no hardware, no PC/SC)."""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import Any

import pytest

from pythonbeid import (
    CardDataError,
    DocumentType,
    PartialDate,
    Sex,
    SpecialStatus,
    decode_tlv,
    is_valid_national_number,
    parse_address,
    parse_birth_date,
    parse_card_data,
    parse_identity,
)
from pythonbeid.parser import (
    _der_length,
    parse_card_date,
    parse_french_date,
    parse_tlv,
)

from .builders import address_file, identity_file, national_number, tlv
from .fake_card import card_data

# ── decode_tlv ────────────────────────────────────────────────────────────


class TestDecodeTlv:
    def test_records_keyed_by_tag(self) -> None:
        assert dict(decode_tlv(tlv((1, "a"), (2, "bc"), (5, "")))) == {
            1: b"a",
            2: b"bc",
            5: b"",
        }

    def test_result_is_read_only(self) -> None:
        records = decode_tlv(tlv((1, "a")))
        with pytest.raises(TypeError):
            records[2] = b"x"  # type: ignore[index]

    def test_version_tag_allowed_first(self) -> None:
        records = decode_tlv(tlv((0, b"\x02"), (1, "a")))
        assert records[0] == b"\x02"
        assert records[1] == b"a"

    def test_zero_padding_ends_content(self) -> None:
        assert dict(decode_tlv(tlv((1, "a")) + bytes(20))) == {1: b"a"}

    def test_empty_file(self) -> None:
        assert dict(decode_tlv(b"")) == {}

    @pytest.mark.parametrize("length", [254, 255, 256, 510, 600])
    def test_ff_length_continuation(self, length: int) -> None:
        value = bytes([0x41]) * length
        encoded = tlv((1, value), (2, "z"))
        assert decode_tlv(encoded)[1] == value
        assert decode_tlv(encoded)[2] == b"z"

    def test_length_continuation_bytes(self) -> None:
        assert tlv((1, bytes(260)))[1:3] == b"\xff\x05"

    def test_truncated_value(self) -> None:
        with pytest.raises(CardDataError, match="truncated TLV value"):
            decode_tlv(bytes([0x01, 0x05, 0x41]))

    def test_missing_length(self) -> None:
        with pytest.raises(CardDataError, match="truncated TLV length"):
            decode_tlv(bytes([0x01]))

    def test_truncated_continuation(self) -> None:
        with pytest.raises(CardDataError, match="truncated TLV length"):
            decode_tlv(bytes([0x01, 0xFF]))

    def test_duplicate_tag_keeps_first(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            records = decode_tlv(tlv((1, "first"), (1, "second")))
        assert records[1] == b"first"
        assert "Duplicate TLV tag 0x01" in caplog.text


# ── Dates ─────────────────────────────────────────────────────────────────


class TestParseCardDate:
    def test_valid(self) -> None:
        assert parse_card_date("10.03.2021") == date(2021, 3, 10)

    def test_surrounding_spaces(self) -> None:
        assert parse_card_date(" 01.12.2030 ") == date(2030, 12, 1)

    @pytest.mark.parametrize("text", ["2021-03-10", "31.02.2021", "", "10.03"])
    def test_invalid(self, text: str) -> None:
        with pytest.raises(CardDataError, match="invalid card date"):
            parse_card_date(text)


FRENCH = ["JAN", "FEV", "MARS", "AVR", "MAI", "JUIN", "JUIL", "AOUT", "SEPT", "OCT", "NOV", "DEC"]  # fmt: skip
DUTCH = ["JAN", "FEB", "MAAR", "APR", "MEI", "JUN", "JUL", "AUG", "SEP", "OKT", "NOV", "DEC"]  # fmt: skip
GERMAN = ["JAN", "FEB", "MÄR", "APR", "MAI", "JUN", "JUL", "AUG", "SEP", "OKT", "NOV", "DEZ"]  # fmt: skip


class TestParseBirthDate:
    @pytest.mark.parametrize(
        ("month", "abbreviation"), list(enumerate(FRENCH, start=1))
    )
    def test_french(self, month: int, abbreviation: str) -> None:
        text = f"15 {abbreviation:<4} 1980"  # month field padded to 4 characters
        assert parse_birth_date(text) == PartialDate(1980, month, 15)

    @pytest.mark.parametrize(("month", "abbreviation"), list(enumerate(DUTCH, start=1)))
    def test_dutch(self, month: int, abbreviation: str) -> None:
        assert parse_birth_date(f"15 {abbreviation} 1980") == PartialDate(
            1980, month, 15
        )

    @pytest.mark.parametrize(
        ("month", "abbreviation"), list(enumerate(GERMAN, start=1))
    )
    @pytest.mark.parametrize("layout", ["{d}.{m}.{y}", "{d}.{m}. {y}"])
    def test_german(self, month: int, abbreviation: str, layout: str) -> None:
        text = layout.format(d="15", m=abbreviation, y="1980")
        assert parse_birth_date(text) == PartialDate(1980, month, 15)

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("22.DEZ. 1997", PartialDate(1997, 12, 22)),
            ("13.AUG. 1996", PartialDate(1996, 8, 13)),
            ("26 AVR  1975", PartialDate(1975, 4, 26)),
            ("01 janv 1990", PartialDate(1990, 1, 1)),  # legacy alias, lower case
            ("03 MAR 1985", PartialDate(1985, 3, 3)),
            ("05 FÉV 2001", PartialDate(2001, 2, 5)),  # accents are tolerated
            ("05 AOÛT 2001", PartialDate(2001, 8, 5)),
            ("    1984", PartialDate(1984)),
            ("1984", PartialDate(1984)),
            ("   MARS 1950", PartialDate(1950, 3)),
            ("12      1950", PartialDate(1950)),  # day without month is dropped
            ("00 MEI 1950", PartialDate(1950, 5)),
        ],
    )
    def test_special_layouts(self, text: str, expected: PartialDate) -> None:
        assert parse_birth_date(text) == expected

    @pytest.mark.parametrize("text", ["15 XYZ 1980", "15 JANVIER 1980"])
    def test_unknown_month_is_rejected(self, text: str) -> None:
        with pytest.raises(CardDataError, match="unknown month"):
            parse_birth_date(text)

    @pytest.mark.parametrize("text", ["", "1 2 3 4", "AB MARS 1980"])
    def test_unexpected_layout(self, text: str) -> None:
        with pytest.raises(CardDataError, match="unexpected birth date format"):
            parse_birth_date(text)

    @pytest.mark.parametrize("text", ["15 MARS 80", "15 MARS 19800", "MARS 80"])
    def test_invalid_year(self, text: str) -> None:
        with pytest.raises(CardDataError, match="invalid year"):
            parse_birth_date(text)

    def test_invalid_day(self) -> None:
        with pytest.raises(CardDataError, match="invalid birth date"):
            parse_birth_date("31 FEV 1980")


# ── National number ───────────────────────────────────────────────────────


class TestNationalNumber:
    def test_valid_before_2000(self) -> None:
        assert is_valid_national_number(national_number("850324123"))

    def test_valid_after_2000(self) -> None:
        number = national_number("050324123", born_after_2000=True)
        assert is_valid_national_number(number)

    def test_separators_ignored(self) -> None:
        number = national_number("850324123")
        formatted = (
            f"{number[:2]}.{number[2:4]}.{number[4:6]}-{number[6:9]}.{number[9:]}"
        )
        assert is_valid_national_number(formatted)

    @pytest.mark.parametrize("number", ["85032412300", "1234", "8503241234x", ""])
    def test_invalid(self, number: str) -> None:
        assert not is_valid_national_number(number)


# ── Identity file ─────────────────────────────────────────────────────────


class TestParseIdentity:
    def test_belgian_card(self) -> None:
        identity = parse_identity(identity_file())
        assert identity.card_number == "592123456789"
        assert identity.chip_number == "534C494E336600296CFF2623660B0826"
        assert identity.validity_start == date(2021, 3, 10)
        assert identity.validity_end == date(2031, 3, 10)
        assert identity.issuing_municipality == "Bruxelles"
        assert identity.last_name == "Specimen"
        assert identity.first_names == "Alice Geldig"
        assert identity.third_given_name_initial == "B"
        assert identity.given_names == "Alice Geldig B"
        assert identity.nationality == "Belge"
        assert identity.birth_place == "Ixelles"
        assert identity.birth_date == PartialDate(1985, 3, 24)
        assert identity.sex is Sex.FEMALE
        assert identity.noble_condition == ""
        assert identity.document_type is DocumentType.IDENTITY_CARD
        assert identity.special_status is SpecialStatus.NONE
        assert len(identity.photo_hash) == 20
        assert identity.national_number_valid
        assert identity.file_structure_version is None
        assert not identity.member_of_family
        assert identity.basic_key_hash is None
        assert identity.raw[0x07] == b"Specimen"

    @pytest.mark.parametrize(("letter", "sex"), [("M", Sex.MALE), ("F", Sex.FEMALE), ("V", Sex.FEMALE), ("W", Sex.FEMALE)])  # fmt: skip
    def test_sex_letters(self, letter: str, sex: Sex) -> None:
        assert parse_identity(identity_file(tag_0D=letter)).sex is sex

    def test_unexpected_sex(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert parse_identity(identity_file(tag_0D="X")).sex is None
        assert "Unexpected sex value" in caplog.text

    def test_values_are_trimmed(self) -> None:
        identity = parse_identity(
            identity_file(tag_07="Specimen   ", tag_05="\x00Bruxelles\x00")
        )
        assert identity.last_name == "Specimen"
        assert identity.issuing_municipality == "Bruxelles"

    def test_invalid_utf8_is_replaced(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            identity = parse_identity(identity_file(tag_0B=b"Li\xe8ge"))
        assert identity.birth_place == "Li�ge"
        assert "Invalid UTF-8" in caplog.text

    def test_version_tag_on_applet_18(self) -> None:
        identity = parse_identity(identity_file(tag_00=b"\x02", tag_1A=bytes(48)))
        assert identity.file_structure_version == 2
        assert identity.basic_key_hash == bytes(48)

    def test_document_type_without_leading_zero(self) -> None:
        assert (
            parse_identity(identity_file(tag_0F="1")).document_type
            is DocumentType.IDENTITY_CARD
        )

    def test_unknown_document_type(self) -> None:
        document_type = parse_identity(identity_file(tag_0F="99")).document_type
        assert document_type == 99
        assert document_type is not None
        assert document_type.name == "UNKNOWN_99"

    def test_non_numeric_document_type(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert parse_identity(identity_file(tag_0F="AB")).document_type is None
        assert "Non-numeric value in tag 0x0F" in caplog.text

    def test_missing_optional_tags(self) -> None:
        identity = parse_identity(
            identity_file(tag_08=None, tag_09=None, tag_0E=None, tag_0F=None, tag_10=None, tag_11=None)
        )  # fmt: skip
        assert identity.first_names == ""
        assert identity.document_type is None
        assert identity.special_status is SpecialStatus.NONE
        assert identity.photo_hash == b""

    @pytest.mark.parametrize(
        "tag", ["tag_01", "tag_03", "tag_04", "tag_06", "tag_07", "tag_0C"]
    )
    def test_missing_mandatory_tag(self, tag: str) -> None:
        overrides: dict[str, Any] = {tag: None}
        with pytest.raises(CardDataError, match="identity file lacks"):
            parse_identity(identity_file(**overrides))

    def test_special_status_combination(self) -> None:
        status = parse_identity(identity_file(tag_10="5")).special_status
        assert status is SpecialStatus.YELLOW_CANE_AND_EXTENDED_MINORITY
        assert status.yellow_cane
        assert status.extended_minority
        assert not status.white_cane

    def test_foreigner_card(self) -> None:
        identity = parse_identity(
            identity_file(
                tag_01="B021329690",
                tag_0F="31",
                tag_12="01",
                tag_13="5",
                tag_14="",
                tag_15="01.02.2020-SY",
                tag_16="7",
                tag_17="0123.456.789",
                tag_18="",
                tag_19="RF-1234",
                tag_1B="B",
                tag_1C="C",
                tag_1D="D",
                tag_1E="K",
                tag_1F="15.06.2022",
            )
        )
        assert identity.document_type is DocumentType.FOREIGNER_EU
        assert identity.document_type.is_foreigner_card
        assert identity.duplicate == 1
        assert identity.special_organization == "5"
        assert identity.member_of_family is True
        assert identity.date_and_country_of_protection == "01.02.2020-SY"
        assert identity.work_permit == "7"
        assert identity.employer_vat_1 == "0123.456.789"
        assert identity.employer_vat_2 is None
        assert identity.regional_file_number == "RF-1234"
        assert (identity.brexit_mention_1, identity.brexit_mention_2) == ("B", "C")
        assert (identity.card_a_mention_1, identity.card_a_mention_2) == ("D", "K")
        assert identity.eu_registration_date == date(2022, 6, 15)

    def test_invalid_optional_date_is_ignored(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            assert (
                parse_identity(identity_file(tag_1F="2022-06-15")).eu_registration_date
                is None
            )
        assert "Invalid date in tag 0x1F" in caplog.text

    def test_incomplete_birth_date(self) -> None:
        birth = parse_identity(identity_file(tag_0C="    1984")).birth_date
        assert not birth.is_complete
        assert str(birth) == "1984"

    def test_is_valid_on(self) -> None:
        identity = parse_identity(identity_file())
        assert identity.is_valid_on(date(2025, 1, 1))
        assert not identity.is_valid_on(date(2031, 3, 11))


class TestParseAddress:
    def test_padding_and_spaces(self) -> None:
        address = parse_address(address_file())
        assert address.street == "Rue de la Loi 16"
        assert address.postal_code == "1000"
        assert address.municipality == "Bruxelles"
        assert address.file_structure_version is None

    def test_version_tag(self) -> None:
        address = parse_address(
            tlv((0, b"\x01"), (1, "Grote Markt 1"), (2, "2000"), (3, "Antwerpen"))
        )
        assert address.file_structure_version == 1
        assert address.municipality == "Antwerpen"

    def test_empty_file(self) -> None:
        address = parse_address(bytes(121))
        assert (address.street, address.postal_code, address.municipality) == (
            "",
            "",
            "",
        )


class TestParseCardData:
    def test_applet_17(self) -> None:
        info = parse_card_data(card_data(0x17, 0x0003))
        assert info.serial_number == bytes(range(0x10, 0x20)).hex().upper()
        assert info.applet_version == 0x17
        assert info.applet_version_string == "1.7"
        assert info.global_os_version == 3
        assert info.component_code == 0xF3
        assert (info.os_number, info.os_version) == (0x36, 0x01)
        assert (info.softmask_number, info.softmask_version) == (0x25, 0x01)
        assert info.pkcs1_support == 0x21
        assert info.key_exchange_version == 0x01
        assert info.lifecycle == 0x0F
        assert info.pin_attempts_left is None
        assert not info.has_basic_key

    def test_applet_18_extended(self) -> None:
        base = card_data(0x18, 0x0001)
        info = parse_card_data(base, base + b"\x02\xff\xff")
        assert info.applet_version_string == "1.8"
        assert info.has_basic_key
        assert info.pin_attempts_left == 2

    def test_pin_attempts_unknown(self) -> None:
        base = card_data(0x18)
        assert parse_card_data(base, base + b"\xff\xff\xff").pin_attempts_left is None

    def test_too_short(self) -> None:
        with pytest.raises(CardDataError, match="card data too short"):
            parse_card_data(bytes(27))


class TestDerLength:
    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (b"\x30\x03abc\x00\x00", 5),
            (b"\x30\x81\x80" + bytes(128), 131),
            (b"\x30\x82\x01\x00" + bytes(256), 260),
        ],
    )
    def test_lengths(self, data: bytes, expected: int) -> None:
        assert _der_length(data) == expected

    @pytest.mark.parametrize(
        "data",
        [b"\x30", b"\x30\x80", b"\x30\x85" + bytes(10), b"\x30\x82\x01", b"\x30\x05ab"],
    )
    def test_invalid(self, data: bytes) -> None:
        with pytest.raises(CardDataError):
            _der_length(data)


# ── Deprecated API ────────────────────────────────────────────────────────


class TestDeprecatedParsers:
    def test_parse_tlv(self) -> None:
        data = list(tlv((1, "hello"), (2, "world"), (3, "x")))
        with pytest.deprecated_call():
            assert parse_tlv(data, 2) == ["hello", "world"]

    def test_parse_tlv_truncated_and_invalid(self) -> None:
        with pytest.deprecated_call():
            assert parse_tlv([1, 2, 0xFF, 0xFE, 2, 9, 0x41], 5) == [""]

    def test_parse_french_date(self) -> None:
        with pytest.deprecated_call():
            expected = datetime(1985, 3, 3)  # noqa: DTZ001 - legacy naive type
            assert parse_french_date("03 MAR 1985") == expected

    def test_parse_french_date_now_rejects_unknown_month(self) -> None:
        with pytest.deprecated_call(), pytest.raises(ValueError, match="unknown month"):
            parse_french_date("10 UNKN 2005")

    def test_parse_french_date_incomplete(self) -> None:
        with (
            pytest.deprecated_call(),
            pytest.raises(ValueError, match="incomplete date"),
        ):
            parse_french_date("1984")
