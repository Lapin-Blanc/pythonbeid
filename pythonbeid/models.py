"""Typed data models describing the content of a Belgian eID card.

All models are immutable (frozen dataclasses). Field names follow the official
specification *ID and Address file contents* (applet 1.8, v5.0) published by
BOSA in the ``Fedict/eid-mw`` repository.
"""

from __future__ import annotations

import base64
import enum
from dataclasses import dataclass, field, fields
from datetime import date
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "Address",
    "CardFile",
    "CardInfo",
    "DocumentType",
    "EidData",
    "Identity",
    "PartialDate",
    "Sex",
    "SpecialStatus",
    "VerificationReport",
]

_DF00 = (0x3F, 0x00, 0xDF, 0x00)
_DF01 = (0x3F, 0x00, 0xDF, 0x01)


class CardFile(enum.Enum):
    """Elementary files of the Belgian eID card, identified by absolute path."""

    IDENTITY = (*_DF01, 0x40, 0x31)
    IDENTITY_SIGNATURE = (*_DF01, 0x40, 0x32)
    ADDRESS = (*_DF01, 0x40, 0x33)
    ADDRESS_SIGNATURE = (*_DF01, 0x40, 0x34)
    PHOTO = (*_DF01, 0x40, 0x35)
    BASIC_PUBLIC_KEY = (*_DF01, 0x40, 0x40)
    """Basic public key (SubjectPublicKeyInfo DER), applet 1.8 only."""
    AUTHENTICATION_CERTIFICATE = (*_DF00, 0x50, 0x38)
    SIGNING_CERTIFICATE = (*_DF00, 0x50, 0x39)
    CA_CERTIFICATE = (*_DF00, 0x50, 0x3A)
    ROOT_CERTIFICATE = (*_DF00, 0x50, 0x3B)
    RRN_CERTIFICATE = (*_DF00, 0x50, 0x3C)
    """Certificate of the National Register, which signs identity and address."""

    @property
    def path(self) -> bytes:
        """Absolute path of the file, as used in a SELECT command."""
        return bytes(self.value)

    @property
    def is_certificate(self) -> bool:
        """Whether the file holds a DER certificate padded with zero bytes."""
        return self.value[:4] == _DF00


class Sex(enum.StrEnum):
    """Sex of the card holder.

    Cards use ``M`` for men and ``F`` (French), ``V`` (Dutch) or ``W``
    (German) for women; all three are normalised to :attr:`FEMALE`.
    """

    MALE = "M"
    FEMALE = "F"


class DocumentType(enum.IntEnum):
    """Type of document (tag ``0x0F`` of the identity file).

    Unknown codes do not raise: they are mapped to a pseudo-member named
    ``UNKNOWN_<code>`` so new card types never break reading.
    """

    IDENTITY_CARD = 1
    KIDS_CARD = 6
    BOOTSTRAP_CARD = 7
    HABILITATION_CARD = 8
    FOREIGNER_A = 11
    FOREIGNER_B = 12
    FOREIGNER_C = 13
    FOREIGNER_D = 14
    FOREIGNER_E = 15
    FOREIGNER_E_PLUS = 16
    FOREIGNER_F = 17
    FOREIGNER_F_PLUS = 18
    FOREIGNER_H = 19
    FOREIGNER_I = 20
    FOREIGNER_J = 21
    FOREIGNER_M = 22
    FOREIGNER_N = 23
    FOREIGNER_K = 27
    FOREIGNER_L = 28
    FOREIGNER_EU = 31
    FOREIGNER_EU_PLUS = 32
    FOREIGNER_A_2021 = 33
    FOREIGNER_B_2021 = 34
    FOREIGNER_F_2021 = 35
    FOREIGNER_F_PLUS_2021 = 36
    KIDS_FOREIGNER_EU = 61
    KIDS_FOREIGNER_EU_PLUS = 62
    KIDS_FOREIGNER_A = 63
    KIDS_FOREIGNER_B = 64
    KIDS_FOREIGNER_K = 65
    KIDS_FOREIGNER_L = 66
    KIDS_FOREIGNER_F = 67
    KIDS_FOREIGNER_F_PLUS = 68
    KIDS_FOREIGNER_M = 69

    @classmethod
    def _missing_(cls, value: object) -> DocumentType | None:
        if not isinstance(value, int):
            return None
        member = int.__new__(cls, value)
        member._name_ = f"UNKNOWN_{value}"
        member._value_ = value
        return member

    @property
    def description(self) -> str:
        """English label, as displayed by the official eID Viewer."""
        return _DOCUMENT_TYPE_LABELS.get(self.value, f"Unknown document type {self}")

    @property
    def is_kids_card(self) -> bool:
        """Whether the document is a card for children under 12."""
        return self.value == 6 or 61 <= self.value <= 69

    @property
    def is_foreigner_card(self) -> bool:
        """Whether the document is a residence card for foreign nationals."""
        return self.value >= 11


_DOCUMENT_TYPE_LABELS: dict[int, str] = {
    1: "Identity card",
    6: "Kids card",
    7: "Bootstrap card",
    8: "Habilitation card",
    11: "A. Proof of registration in the Aliens' Register - Temporary residence",
    12: "B. Proof of registration in the Aliens' Register",
    13: "C. Identity card for aliens",
    14: "D. Long-term EU resident",
    15: "E. Registration certificate",
    16: "E+. Document certifying permanent residence",
    17: "F. Residence card of a family member of a Union citizen",
    18: "F+. Permanent residence card of a family member of a Union citizen",
    19: "H. EU Blue Card",
    20: "I. ICT",
    21: "J. Mobile ICT",
    22: "M. Article 50 TEU",
    23: "N. Article 50 TEU - Local border traffic",
    27: "K. Establishment",
    28: "L. EU long-term resident",
    31: "EU. Registration - Art 8 Directive 2004/38/EC",
    32: "EU+. Permanent residence - Art 19 Directive 2004/38/EC",
    33: "A. Limited stay",
    34: "B. Unlimited stay",
    35: "F. Family member EU - Art 10 Directive 2004/38/EC",
    36: "F+. Family member EU - Art 20 Directive 2004/38/EC",
    61: "EU. Registration - Art 8 Directive 2004/38/EC (kids)",
    62: "EU+. Permanent residence - Art 19 Directive 2004/38/EC (kids)",
    63: "A. Limited stay (kids)",
    64: "B. Unlimited stay (kids)",
    65: "K. Establishment (kids)",
    66: "L. EU long-term resident (kids)",
    67: "F. Family member EU - Art 10 Directive 2004/38/EC (kids)",
    68: "F+. Family member EU - Art 20 Directive 2004/38/EC (kids)",
    69: "M. Article 50 TEU (kids)",
}


class SpecialStatus(enum.IntEnum):
    """Special status of the card holder (tag ``0x10``).

    The codes are an enumeration, not bit flags: 5 means yellow cane *and*
    extended minority. Unknown codes map to a pseudo-member named
    ``UNKNOWN_<code>``.
    """

    NONE = 0
    WHITE_CANE = 1
    EXTENDED_MINORITY = 2
    WHITE_CANE_AND_EXTENDED_MINORITY = 3
    YELLOW_CANE = 4
    YELLOW_CANE_AND_EXTENDED_MINORITY = 5

    @classmethod
    def _missing_(cls, value: object) -> SpecialStatus | None:
        if not isinstance(value, int):
            return None
        member = int.__new__(cls, value)
        member._name_ = f"UNKNOWN_{value}"
        member._value_ = value
        return member

    @property
    def white_cane(self) -> bool:
        """The holder is blind (white cane)."""
        return self.value in (1, 3)

    @property
    def yellow_cane(self) -> bool:
        """The holder is partially sighted (yellow cane)."""
        return self.value in (4, 5)

    @property
    def extended_minority(self) -> bool:
        """The holder is under extended minority."""
        return self.value in (2, 3, 5)


@dataclass(frozen=True, slots=True)
class PartialDate:
    """A date that may lack its day or month.

    Belgian eID cards of some foreign nationals carry a birth date where only
    the year (or the year and month) is known.
    """

    year: int
    month: int | None = None
    day: int | None = None

    def __post_init__(self) -> None:
        if self.month is None and self.day is not None:
            msg = "a day cannot be given without a month"
            raise ValueError(msg)
        if self.month is not None and not 1 <= self.month <= 12:
            msg = f"invalid month: {self.month}"
            raise ValueError(msg)
        if self.month is not None and self.day is not None:
            date(self.year, self.month, self.day)  # validates the day

    @property
    def is_complete(self) -> bool:
        """Whether year, month and day are all known."""
        return self.day is not None

    def to_date(self) -> date:
        """Return the equivalent :class:`datetime.date`.

        Raises:
            ValueError: If the day or the month is unknown.
        """
        if self.month is None or self.day is None:
            msg = f"incomplete date: {self}"
            raise ValueError(msg)
        return date(self.year, self.month, self.day)

    def __str__(self) -> str:
        """ISO 8601 representation with reduced precision when incomplete."""
        text = f"{self.year:04d}"
        if self.month is not None:
            text += f"-{self.month:02d}"
        if self.day is not None:
            text += f"-{self.day:02d}"
        return text


def _readonly(mapping: Mapping[Any, bytes] | None = None) -> Mapping[Any, bytes]:
    return MappingProxyType(dict(mapping or {}))


@dataclass(frozen=True, slots=True)
class Identity:
    """Content of the identity file (``DF01/4031``).

    Attributes:
        card_number: Number printed on the card.
        chip_number: Serial number of the chip, as uppercase hexadecimal.
        validity_start: First day of validity.
        validity_end: Last day of validity.
        issuing_municipality: Municipality that delivered the card.
        national_number: National register number (11 digits).
        last_name: Last name.
        first_names: The first two given names.
        third_given_name_initial: First letter of the third given name.
        nationality: Nationality, in the language of the card.
        birth_place: Place of birth.
        birth_date: Date of birth, possibly incomplete; ``None`` when the
            card holds a format this library does not know (the raw value
            stays in ``raw[0x0C]``).
        sex: Sex, or ``None`` when the card holds an unexpected value.
        noble_condition: Noble title, if any.
        document_type: Type of document.
        special_status: Special status flags.
        photo_hash: Digest of the photo file (SHA-1, SHA-256 or SHA-384).
        duplicate: Duplicate number of the card, if present.
        special_organization: Code of the special organisation (foreigners).
        member_of_family: Whether the holder is a family member (foreigners).
        date_and_country_of_protection: Protection date and country
            (``dd.mm.yyyy-CC``), if present.
        work_permit: Work permit code, if present.
        employer_vat_1: First employer VAT number, if present.
        employer_vat_2: Second employer VAT number, if present.
        regional_file_number: Regional file number, if present.
        basic_key_hash: SHA-384 digest of the basic public key (applet 1.8).
        brexit_mention_1: First Brexit mention code, if present.
        brexit_mention_2: Second Brexit mention code, if present.
        card_a_mention_1: First mention code of an A card, if present.
        card_a_mention_2: Second mention code of an A card, if present.
        eu_registration_date: Registration date of EU/EU+ cards, if present.
        file_structure_version: Version of the file layout (tag ``0x00``), if
            present.
        raw: Every TLV record of the file, keyed by tag.
    """

    card_number: str
    chip_number: str
    validity_start: date
    validity_end: date
    issuing_municipality: str
    national_number: str
    last_name: str
    first_names: str
    third_given_name_initial: str
    nationality: str
    birth_place: str
    birth_date: PartialDate | None
    sex: Sex | None
    noble_condition: str = ""
    document_type: DocumentType | None = None
    special_status: SpecialStatus = SpecialStatus.NONE
    photo_hash: bytes = field(default=b"", repr=False)
    duplicate: int | None = None
    special_organization: str | None = None
    member_of_family: bool = False
    date_and_country_of_protection: str | None = None
    work_permit: str | None = None
    employer_vat_1: str | None = None
    employer_vat_2: str | None = None
    regional_file_number: str | None = None
    basic_key_hash: bytes | None = field(default=None, repr=False)
    brexit_mention_1: str | None = None
    brexit_mention_2: str | None = None
    card_a_mention_1: str | None = None
    card_a_mention_2: str | None = None
    eu_registration_date: date | None = None
    file_structure_version: int | None = None
    raw: Mapping[int, bytes] = field(
        default_factory=_readonly, repr=False, compare=False
    )

    @property
    def given_names(self) -> str:
        """First two given names followed by the initial of the third one."""
        return " ".join(
            part for part in (self.first_names, self.third_given_name_initial) if part
        )

    @property
    def national_number_valid(self) -> bool:
        """Whether the national number passes the modulo-97 checksum."""
        from .parser import is_valid_national_number  # noqa: PLC0415 - cycle

        return is_valid_national_number(self.national_number)

    def is_valid_on(self, day: date) -> bool:
        """Whether the card is within its validity period on *day*."""
        return self.validity_start <= day <= self.validity_end

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation (``raw`` excluded)."""
        return {
            f.name: _jsonable(getattr(self, f.name))
            for f in fields(self)
            if f.name != "raw"
        }


@dataclass(frozen=True, slots=True)
class Address:
    """Content of the address file (``DF01/4033``).

    Attributes:
        street: Street name and house number.
        postal_code: Postal code.
        municipality: Municipality.
        file_structure_version: Version of the file layout, if present.
        raw: Every TLV record of the file, keyed by tag.
    """

    street: str
    postal_code: str
    municipality: str
    file_structure_version: int | None = None
    raw: Mapping[int, bytes] = field(
        default_factory=_readonly, repr=False, compare=False
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation (``raw`` excluded)."""
        return {
            f.name: _jsonable(getattr(self, f.name))
            for f in fields(self)
            if f.name != "raw"
        }


@dataclass(frozen=True, slots=True)
class CardInfo:
    """Chip information returned by the GET CARD DATA command.

    Attributes:
        serial_number: Chip serial number, as uppercase hexadecimal.
        component_code: Component code.
        os_number: Operating system number.
        os_version: Operating system version.
        softmask_number: Softmask number.
        softmask_version: Softmask version.
        applet_version: Applet version byte (``0x17`` for 1.7, ``0x18`` for
            1.8).
        global_os_version: Global OS version.
        applet_interface_version: Applet interface version.
        pkcs1_support: PKCS#1 support byte.
        key_exchange_version: Key exchange version.
        lifecycle: Applet life cycle state.
        pin_attempts_left: Remaining PIN attempts, applet 1.8 only.
    """

    serial_number: str
    component_code: int
    os_number: int
    os_version: int
    softmask_number: int
    softmask_version: int
    applet_version: int
    global_os_version: int
    applet_interface_version: int
    pkcs1_support: int
    key_exchange_version: int
    lifecycle: int
    pin_attempts_left: int | None = None

    @property
    def applet_version_string(self) -> str:
        """Applet version in dotted form, e.g. ``"1.8"``."""
        return f"{self.applet_version >> 4}.{self.applet_version & 0x0F}"

    @property
    def has_basic_key(self) -> bool:
        """Whether the applet supports the basic key (applet 1.8 and later)."""
        return self.applet_version >= 0x18

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        data = {f.name: _jsonable(getattr(self, f.name)) for f in fields(self)}
        data["applet_version_string"] = self.applet_version_string
        return data


@dataclass(frozen=True, slots=True)
class EidData:
    """Everything read from a card in one go.

    Attributes:
        identity: Identity file content.
        address: Address file content.
        card: Chip information (GET CARD DATA). It is not signed by the
            card issuer, so it is informative only; ``None`` when the data
            was not read from a live card.
        photo: JPEG photo, or ``None`` when it was not read.
        files: Raw content of every file that was read, keyed by file. It is
            what :func:`pythonbeid.verify_eid` checks.
    """

    identity: Identity
    address: Address
    card: CardInfo | None = None
    photo: bytes | None = field(default=None, repr=False)
    files: Mapping[CardFile, bytes] = field(
        default_factory=_readonly, repr=False, compare=False
    )

    @classmethod
    def from_files(
        cls, files: Mapping[CardFile, bytes], card: CardInfo | None = None
    ) -> EidData:
        """Decode raw card files, e.g. received by a server from a client.

        Args:
            files: Raw files; the identity and address files are required.
            card: Chip information, if known.

        Raises:
            KeyError: If the identity or address file is missing.
            CardDataError: If a file cannot be decoded.
        """
        from .parser import parse_address, parse_identity  # noqa: PLC0415 - cycle

        return cls(
            identity=parse_identity(files[CardFile.IDENTITY]),
            address=parse_address(files[CardFile.ADDRESS]),
            card=card,
            photo=files.get(CardFile.PHOTO),
            files=_readonly(files),
        )

    def to_dict(self, *, include_photo: bool = True) -> dict[str, Any]:
        """Return a JSON-serialisable representation.

        Args:
            include_photo: Include the photo as a base-64 string.
        """
        data: dict[str, Any] = {
            "card": None if self.card is None else self.card.to_dict(),
            "identity": self.identity.to_dict(),
            "address": self.address.to_dict(),
        }
        if include_photo and self.photo is not None:
            data["photo"] = base64.b64encode(self.photo).decode("ascii")
        return data


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Outcome of the integrity checks of a card.

    A ``None`` value means the check does not apply or could not be run (for
    example the photo was not read, or the card has no basic key).

    Attributes:
        photo_hash_valid: The photo matches the digest in the identity file.
        identity_signature_valid: The identity file is signed by the RRN.
        address_signature_valid: The address file is signed by the RRN.
        rrn_certificate_trusted: The RRN certificate chains up to a trusted
            Belgian root certificate.
        rrn_certificate_period_valid: The validity period of the RRN
            certificate overlaps the validity period of the card. (Cards
            re-signed after issuance carry a newer certificate, and the
            certificate of a valid card may have expired since.)
        content_matches_files: The decoded identity, address and photo are
            exactly those of the signed raw files.
        basic_key_valid: The basic public key matches its signed digest
            (applet 1.8).
        chip_authenticated: The chip proved it holds the basic private key
            (applet 1.8, live card only).
        errors: Human-readable reasons for every failed check.
    """

    photo_hash_valid: bool | None
    identity_signature_valid: bool
    address_signature_valid: bool
    rrn_certificate_trusted: bool
    rrn_certificate_period_valid: bool
    content_matches_files: bool = True
    basic_key_valid: bool | None = None
    chip_authenticated: bool | None = None
    errors: tuple[str, ...] = ()

    @property
    def is_valid(self) -> bool:
        """Whether no applicable check failed."""
        checks = (
            self.photo_hash_valid,
            self.identity_signature_valid,
            self.address_signature_valid,
            self.rrn_certificate_trusted,
            self.rrn_certificate_period_valid,
            self.content_matches_files,
            self.basic_key_valid,
            self.chip_authenticated,
        )
        return all(check is not False for check in checks)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        data = {f.name: _jsonable(getattr(self, f.name)) for f in fields(self)}
        data["is_valid"] = self.is_valid
        return data


def _jsonable(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, PartialDate):
        return str(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return list(value)
    return value
