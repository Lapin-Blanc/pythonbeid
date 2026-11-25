"""Tests of the data models."""

from __future__ import annotations

import base64
import json
from dataclasses import FrozenInstanceError
from datetime import date

import pytest

from pythonbeid import (
    CardFile,
    DocumentType,
    EidData,
    PartialDate,
    Sex,
    SpecialStatus,
    VerificationReport,
    parse_address,
    parse_card_data,
    parse_identity,
)

from .builders import PHOTO, address_file, identity_file
from .fake_card import card_data


class TestPartialDate:
    def test_complete(self) -> None:
        value = PartialDate(1985, 3, 24)
        assert value.is_complete
        assert value.to_date() == date(1985, 3, 24)
        assert str(value) == "1985-03-24"

    @pytest.mark.parametrize(
        ("value", "text"),
        [(PartialDate(1984), "1984"), (PartialDate(1950, 3), "1950-03")],
    )
    def test_incomplete(self, value: PartialDate, text: str) -> None:
        assert not value.is_complete
        assert str(value) == text
        with pytest.raises(ValueError, match="incomplete date"):
            value.to_date()

    def test_day_without_month(self) -> None:
        with pytest.raises(ValueError, match="day cannot be given without a month"):
            PartialDate(1990, None, 3)

    @pytest.mark.parametrize("month", [0, 13])
    def test_invalid_month(self, month: int) -> None:
        with pytest.raises(ValueError, match="invalid month"):
            PartialDate(1990, month)

    def test_invalid_day(self) -> None:
        with pytest.raises(ValueError, match="day is out of range"):
            PartialDate(1990, 2, 30)

    def test_frozen(self) -> None:
        with pytest.raises(FrozenInstanceError):
            PartialDate(1990).year = 1991  # type: ignore[misc]


class TestEnums:
    def test_document_type_description(self) -> None:
        assert DocumentType(1).description == "Identity card"
        assert DocumentType(19).description == "H. EU Blue Card"

    def test_every_document_type_has_a_label(self) -> None:
        assert all(member.description != "" for member in DocumentType)
        assert not any("Unknown" in member.description for member in DocumentType)

    def test_unknown_document_type(self) -> None:
        member = DocumentType(42)
        assert isinstance(member, DocumentType)
        assert member.name == "UNKNOWN_42"
        assert member.description == "Unknown document type 42"

    def test_document_type_rejects_non_int(self) -> None:
        with pytest.raises(ValueError, match="is not a valid DocumentType"):
            DocumentType("x")  # type: ignore[arg-type]

    @pytest.mark.parametrize(("code", "kids", "foreigner"), [(1, False, False), (6, True, False), (11, False, True), (63, True, True)])  # fmt: skip
    def test_document_type_categories(
        self, code: int, kids: bool, foreigner: bool
    ) -> None:
        assert DocumentType(code).is_kids_card is kids
        assert DocumentType(code).is_foreigner_card is foreigner

    @pytest.mark.parametrize(
        ("code", "white", "yellow", "minority"),
        [(0, False, False, False), (1, True, False, False), (2, False, False, True),
         (3, True, False, True), (4, False, True, False), (5, False, True, True)],
    )  # fmt: skip
    def test_special_status_codes(
        self, code: int, white: bool, yellow: bool, minority: bool
    ) -> None:
        status = SpecialStatus(code)
        assert (status.white_cane, status.yellow_cane, status.extended_minority) == (
            white,
            yellow,
            minority,
        )

    def test_unknown_special_status(self) -> None:
        assert SpecialStatus(9).name == "UNKNOWN_9"
        with pytest.raises(ValueError, match="is not a valid SpecialStatus"):
            SpecialStatus("x")  # type: ignore[arg-type]

    def test_sex_values(self) -> None:
        assert Sex.MALE.value == "M"
        assert Sex("F") is Sex.FEMALE

    def test_card_file_paths(self) -> None:
        assert CardFile.IDENTITY.path == bytes.fromhex("3F00DF014031")
        assert CardFile.RRN_CERTIFICATE.path == bytes.fromhex("3F00DF00503C")
        assert CardFile.RRN_CERTIFICATE.is_certificate
        assert not CardFile.PHOTO.is_certificate


def _eid() -> EidData:
    return EidData(
        card=parse_card_data(card_data()),
        identity=parse_identity(identity_file()),
        address=parse_address(address_file()),
        photo=PHOTO,
    )


class TestSerialisation:
    def test_eid_to_dict_is_json(self) -> None:
        data = _eid().to_dict()
        text = json.dumps(data)
        assert json.loads(text)["identity"]["birth_date"] == "1985-03-24"
        assert data["identity"]["sex"] == "F"
        assert data["identity"]["document_type"] == 1
        assert data["identity"]["validity_start"] == "2021-03-10"
        assert data["identity"]["photo_hash"] == data["identity"]["photo_hash"].lower()
        assert "raw" not in data["identity"]
        assert data["address"]["street"] == "Rue de la Loi 16"
        assert data["card"]["applet_version_string"] == "1.7"
        assert base64.b64decode(data["photo"]) == PHOTO

    def test_eid_to_dict_without_photo(self) -> None:
        assert "photo" not in _eid().to_dict(include_photo=False)

    def test_repr_hides_binary_content(self) -> None:
        text = repr(_eid())
        assert "photo=" not in text
        assert "files=" not in text
        assert "photo_hash" not in text

    def test_report_to_dict(self) -> None:
        report = VerificationReport(
            photo_hash_valid=None,
            identity_signature_valid=True,
            address_signature_valid=False,
            rrn_certificate_trusted=True,
            rrn_certificate_valid_at_issuance=True,
            errors=("the address signature is invalid",),
        )
        data = report.to_dict()
        assert data["is_valid"] is False
        assert data["errors"] == ["the address signature is invalid"]
        assert data["photo_hash_valid"] is None


class TestVerificationReport:
    def _report(self, **overrides: bool | None) -> VerificationReport:
        values: dict[str, bool | None] = {
            "photo_hash_valid": True,
            "identity_signature_valid": True,
            "address_signature_valid": True,
            "rrn_certificate_trusted": True,
            "rrn_certificate_valid_at_issuance": True,
        }
        values.update(overrides)
        return VerificationReport(**values)  # type: ignore[arg-type]

    def test_all_valid(self) -> None:
        assert self._report().is_valid

    def test_not_applicable_checks_do_not_fail(self) -> None:
        assert self._report(photo_hash_valid=None, chip_authenticated=None).is_valid

    @pytest.mark.parametrize(
        "check",
        ["photo_hash_valid", "identity_signature_valid", "rrn_certificate_trusted", "basic_key_valid", "chip_authenticated"],
    )  # fmt: skip
    def test_any_failure_invalidates(self, check: str) -> None:
        assert not self._report(**{check: False}).is_valid
