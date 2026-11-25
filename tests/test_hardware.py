"""Tests against a real Belgian eID card (``pytest --hardware``).

They only check structure and integrity: no value read from the card is
asserted on or printed, so the suite is safe to run on anyone's card.
"""

from __future__ import annotations

import warnings
from datetime import date, datetime
from typing import TYPE_CHECKING

import pytest

from pythonbeid import (
    CardFile,
    CardReader,
    DocumentType,
    PartialDate,
    UnsupportedCardError,
    list_readers,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.hardware


@pytest.fixture(scope="module")
def reader() -> Iterator[CardReader]:
    with CardReader(timeout=30) as connection:
        yield connection


def test_reader_listed() -> None:
    assert list_readers()


def test_card_info(reader: CardReader) -> None:
    info = reader.card_info
    assert info.applet_version in (0x17, 0x18)
    assert len(info.serial_number) == 32
    assert reader.atr[0] == 0x3B


def test_read_and_verify(reader: CardReader) -> None:
    eid = reader.read()
    identity = eid.identity
    assert identity.card_number
    assert isinstance(identity.validity_start, date)
    assert isinstance(identity.birth_date, PartialDate)
    assert identity.document_type is None or isinstance(
        identity.document_type, DocumentType
    )
    assert identity.national_number_valid
    assert eid.photo is not None
    assert eid.photo.startswith(b"\xff\xd8")
    assert eid.address.street == eid.address.street.strip()

    report = reader.verify(eid)
    assert report.is_valid, report.errors
    assert report.photo_hash_valid is True
    assert report.rrn_certificate_trusted


def test_certificates(reader: CardReader) -> None:
    from cryptography import x509

    for file in (
        CardFile.ROOT_CERTIFICATE,
        CardFile.RRN_CERTIFICATE,
        CardFile.CA_CERTIFICATE,
    ):
        certificate = x509.load_der_x509_certificate(reader.read_certificate(file))
        assert certificate.subject.rfc4514_string()


def test_chip_authentication(reader: CardReader) -> None:
    if reader.card_info.has_basic_key:
        assert reader.authenticate_chip()
    else:
        with pytest.raises(UnsupportedCardError):
            reader.authenticate_chip()


def test_legacy_api(reader: CardReader) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        info = reader.read_informations(photo=True)
    assert isinstance(info["validity_start"], datetime)
    assert isinstance(info["photo"], str)
