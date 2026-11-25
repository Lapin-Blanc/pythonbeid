"""Pure decoding of Belgian eID file contents.

Nothing in this module talks to a card: every function takes the raw bytes of
a file and returns typed values, so the parsing can be reused with any
transport (PC/SC, PKCS#11 raw files, test fixtures...).

Reference: *ID and Address file contents* v5.0 and *Belgian Electronic
Identity Card content* v5.4 (``Fedict/eid-mw``, ``doc/sdk/documentation``).
"""

from __future__ import annotations

import logging
import re
import unicodedata
import warnings
from datetime import date, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING

from .exceptions import CardDataError
from .models import (
    Address,
    CardInfo,
    DocumentType,
    Identity,
    PartialDate,
    Sex,
    SpecialStatus,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "decode_tlv",
    "is_valid_national_number",
    "parse_address",
    "parse_birth_date",
    "parse_card_data",
    "parse_card_date",
    "parse_french_date",
    "parse_identity",
    "parse_tlv",
]

logger = logging.getLogger(__name__)

# Month names found on cards, in French, Dutch, German (diacritics removed,
# so "MÄR" becomes "MAR") plus English and legacy pythonbeid aliases.
_MONTHS: dict[str, int] = {
    "JAN": 1, "JANV": 1,
    "FEV": 2, "FEVR": 2, "FEB": 2,
    "MAR": 3, "MARS": 3, "MAAR": 3,
    "AVR": 4, "AVRI": 4, "APR": 4,
    "MAI": 5, "MEI": 5, "MAY": 5,
    "JUN": 6, "JUIN": 6,
    "JUL": 7, "JUIL": 7,
    "AOU": 8, "AOUT": 8, "AUG": 8,
    "SEP": 9, "SEPT": 9,
    "OCT": 10, "OCTO": 10, "OKT": 10,
    "NOV": 11, "NOVE": 11,
    "DEC": 12, "DECE": 12, "DEZ": 12,
}  # fmt: skip

_FEMALE_LETTERS = frozenset("FVW")  # French, Dutch (vrouw), German (weiblich)


# ── TLV ───────────────────────────────────────────────────────────────────


def decode_tlv(data: bytes) -> Mapping[int, bytes]:
    """Decode a TLV file of the Belgian eID card.

    The format is the one of the specification: a one-byte tag, a length
    encoded on one byte (or ``FF`` continuation bytes for 255 and more,
    ``FF 05`` meaning 260) and the value. Tag ``0x00`` (file structure
    version) may only appear first; a zero byte found later is the padding
    that ends the useful content.

    Args:
        data: Raw content of the file.

    Returns:
        A read-only mapping from tag to value, in file order.

    Raises:
        CardDataError: If a record is truncated.
    """
    records: dict[int, bytes] = {}
    index, size = 0, len(data)
    while index < size:
        tag = data[index]
        if tag == 0x00 and index > 0:
            break  # zero padding
        index += 1
        length = 0
        while True:
            if index >= size:
                msg = f"truncated TLV length for tag 0x{tag:02X}"
                raise CardDataError(msg)
            byte = data[index]
            index += 1
            length += byte
            if byte != 0xFF:
                break
        if index + length > size:
            msg = (
                f"truncated TLV value for tag 0x{tag:02X} "
                f"({length} bytes announced, {size - index} available)"
            )
            raise CardDataError(msg)
        if tag in records:
            logger.warning("Duplicate TLV tag 0x%02X ignored", tag)
        else:
            records[tag] = data[index : index + length]
        index += length
    return MappingProxyType(records)


def _text(value: bytes | None) -> str:
    """Decode a UTF-8 card field, trimming spaces and zero padding."""
    if not value:
        return ""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("Invalid UTF-8 in card field, replacing undecodable bytes")
        text = value.decode("utf-8", errors="replace")
    return text.strip("\x00").strip()


def _optional_text(records: Mapping[int, bytes], tag: int) -> str | None:
    if tag not in records:
        return None
    return _text(records[tag]) or None


def _optional_int(records: Mapping[int, bytes], tag: int) -> int | None:
    text = _optional_text(records, tag)
    if text is None:
        return None
    if not text.isdigit():
        logger.warning("Non-numeric value in tag 0x%02X ignored", tag)
        return None
    return int(text)


def _version(records: Mapping[int, bytes]) -> int | None:
    value = records.get(0x00)
    return int.from_bytes(value, "big") if value else None


def _der_length(data: bytes) -> int:
    """Total length of the DER SEQUENCE at the start of *data*.

    Certificates, signatures and keys are stored in files larger than the
    object itself, padded with zero bytes.

    Raises:
        CardDataError: If *data* does not start with a valid DER header.
    """
    if len(data) < 2:
        msg = "DER object too short"
        raise CardDataError(msg)
    if data[0] != 0x30:
        msg = "not a DER SEQUENCE (empty or invalid file)"
        raise CardDataError(msg)
    first = data[1]
    if first < 0x80:
        total = 2 + first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or len(data) < 2 + count:
            msg = "invalid DER length"
            raise CardDataError(msg)
        total = 2 + count + int.from_bytes(data[2 : 2 + count], "big")
    if total > len(data):
        msg = f"truncated DER object ({total} bytes announced, {len(data)} available)"
        raise CardDataError(msg)
    return total


# ── Dates ─────────────────────────────────────────────────────────────────


def parse_card_date(text: str) -> date:
    """Parse a ``DD.MM.YYYY`` date (validity dates of the card).

    Raises:
        CardDataError: If the text is not a valid date in that format.
    """
    try:
        return datetime.strptime(text.strip(), "%d.%m.%Y").date()  # noqa: DTZ007
    except ValueError as exc:
        msg = "invalid card date (DD.MM.YYYY expected)"
        raise CardDataError(msg) from exc


def _month(token: str) -> int:
    plain = "".join(
        char
        for char in unicodedata.normalize("NFKD", token.upper())
        if not unicodedata.combining(char)
    )
    try:
        return _MONTHS[plain]
    except KeyError:
        msg = "unknown month abbreviation in birth date"
        raise CardDataError(msg) from None


def parse_birth_date(text: str) -> PartialDate:
    """Parse the localised birth date of the identity file.

    Supported layouts, as written by the issuing municipality:

    * French and Dutch: ``DD MMMM YYYY`` (``"12 MEI 1990"``, ``"26 AVR  1975"``)
    * German: ``DD.MMM.YYYY`` or ``DD.MMM. YYYY`` (``"22.DEZ. 1997"``)
    * Incomplete dates: blank day and/or month (``"    1984"``,
      ``"   MARS 1950"``)

    Args:
        text: Value of tag ``0x0C``.

    Returns:
        The date, possibly without day and month.

    Raises:
        CardDataError: If the text cannot be interpreted. Unknown month
            names are rejected instead of being guessed. The message never
            contains the date itself, which is personal data.
    """
    tokens = text.replace(".", " ").split()
    try:
        match tokens:
            case [year]:
                result = PartialDate(_year(year))
            case [first, year] if first.isdigit():
                # A day without a month carries no information.
                result = PartialDate(_year(year))
            case [month, year]:
                result = PartialDate(_year(year), _month(month))
            case [day, month, year] if day.isdigit():
                day_value = int(day)
                result = PartialDate(_year(year), _month(month), day_value or None)
            case _:
                msg = "unexpected birth date format"
                raise CardDataError(msg)
    except CardDataError:
        raise
    except ValueError as exc:
        msg = "invalid birth date"
        raise CardDataError(msg) from exc
    return result


def _year(token: str) -> int:
    if not re.fullmatch(r"\d{4}", token):
        msg = "invalid year in birth date"
        raise CardDataError(msg)
    return int(token)


# ── Field helpers ─────────────────────────────────────────────────────────


def _sex(value: str) -> Sex | None:
    letter = value.upper()
    if letter == "M":
        return Sex.MALE
    if letter in _FEMALE_LETTERS:
        return Sex.FEMALE
    logger.warning("Unexpected value in the sex field (tag 0x0D) ignored")
    return None


def _document_type(records: Mapping[int, bytes]) -> DocumentType | None:
    code = _optional_int(records, 0x0F)
    return None if code is None else DocumentType(code)


def _special_status(records: Mapping[int, bytes]) -> SpecialStatus:
    code = _optional_int(records, 0x10)
    return SpecialStatus(code or 0)


def _optional_card_date(records: Mapping[int, bytes], tag: int) -> date | None:
    text = _optional_text(records, tag)
    if text is None:
        return None
    try:
        return parse_card_date(text)
    except CardDataError:
        logger.warning("Invalid date in tag 0x%02X ignored", tag)
        return None


def _birth_date(text: str) -> PartialDate | None:
    try:
        return parse_birth_date(text)
    except CardDataError as exc:
        logger.warning("Birth date not decoded (%s); see Identity.raw[0x0C]", exc)
        return None


def _required(records: Mapping[int, bytes], tag: int, name: str) -> str:
    if tag not in records:
        msg = f"identity file lacks the {name} (tag 0x{tag:02X})"
        raise CardDataError(msg)
    return _text(records[tag])


def is_valid_national_number(national_number: str) -> bool:
    """Check the modulo-97 checksum of a Belgian national register number.

    Separators (dots, dashes, spaces) are ignored. People born in 2000 or
    later use the same rule with a ``2`` prefixed to the first nine digits.
    """
    digits = re.sub(r"[\s.\-]", "", national_number)
    if not re.fullmatch(r"\d{11}", digits):
        return False
    check = int(digits[9:])
    return check in (97 - int(digits[:9]) % 97, 97 - int("2" + digits[:9]) % 97)


# ── Files ─────────────────────────────────────────────────────────────────


def parse_identity(data: bytes) -> Identity:
    """Decode the identity file (``DF01/4031``).

    Raises:
        CardDataError: If a mandatory field is missing or malformed.
    """
    records = decode_tlv(data)
    return Identity(
        card_number=_required(records, 0x01, "card number"),
        chip_number=records.get(0x02, b"").hex().upper(),
        validity_start=parse_card_date(_required(records, 0x03, "validity start")),
        validity_end=parse_card_date(_required(records, 0x04, "validity end")),
        issuing_municipality=_text(records.get(0x05)),
        national_number=_required(records, 0x06, "national number"),
        last_name=_required(records, 0x07, "last name"),
        first_names=_text(records.get(0x08)),
        third_given_name_initial=_text(records.get(0x09)),
        nationality=_text(records.get(0x0A)),
        birth_place=_text(records.get(0x0B)),
        birth_date=_birth_date(_required(records, 0x0C, "birth date")),
        sex=_sex(_text(records.get(0x0D))),
        noble_condition=_text(records.get(0x0E)),
        document_type=_document_type(records),
        special_status=_special_status(records),
        photo_hash=bytes(records.get(0x11, b"")),
        duplicate=_optional_int(records, 0x12),
        special_organization=_optional_text(records, 0x13),
        member_of_family=0x14 in records,
        date_and_country_of_protection=_optional_text(records, 0x15),
        work_permit=_optional_text(records, 0x16),
        employer_vat_1=_optional_text(records, 0x17),
        employer_vat_2=_optional_text(records, 0x18),
        regional_file_number=_optional_text(records, 0x19),
        basic_key_hash=bytes(records[0x1A]) if records.get(0x1A) else None,
        brexit_mention_1=_optional_text(records, 0x1B),
        brexit_mention_2=_optional_text(records, 0x1C),
        card_a_mention_1=_optional_text(records, 0x1D),
        card_a_mention_2=_optional_text(records, 0x1E),
        eu_registration_date=_optional_card_date(records, 0x1F),
        file_structure_version=_version(records),
        raw=records,
    )


def parse_address(data: bytes) -> Address:
    """Decode the address file (``DF01/4033``).

    Raises:
        CardDataError: If the file is malformed.
    """
    records = decode_tlv(data)
    return Address(
        street=_text(records.get(0x01)),
        postal_code=_text(records.get(0x02)),
        municipality=_text(records.get(0x03)),
        file_structure_version=_version(records),
        raw=records,
    )


def parse_card_data(data: bytes, extended: bytes | None = None) -> CardInfo:
    """Decode the answer of GET CARD DATA (``80 E4 00 00 1C``).

    Args:
        data: The 28 bytes returned with ``P2=00``.
        extended: The 31 bytes returned with ``P2=01`` (applet 1.8 only),
            which add the number of remaining PIN attempts.

    Raises:
        CardDataError: If the answer is too short.
    """
    if len(data) < 28:
        msg = f"card data too short: {len(data)} bytes, 28 expected"
        raise CardDataError(msg)
    pin_attempts: int | None = None
    if extended is not None and len(extended) > 28 and extended[28] != 0xFF:
        pin_attempts = extended[28]
    return CardInfo(
        serial_number=data[:16].hex().upper(),
        component_code=data[16],
        os_number=data[17],
        os_version=data[18],
        softmask_number=data[19],
        softmask_version=data[20],
        applet_version=data[21],
        global_os_version=int.from_bytes(data[22:24], "big"),
        applet_interface_version=data[24],
        pkcs1_support=data[25],
        key_exchange_version=data[26],
        lifecycle=data[27],
        pin_attempts_left=pin_attempts,
    )


# ── Deprecated 0.x API ────────────────────────────────────────────────────


def parse_tlv(data: list[int], num_fields: int) -> list[str]:
    """Return the first *num_fields* TLV values, ignoring their tags.

    .. deprecated:: 1.0
        Use :func:`decode_tlv`, which keys values by tag and follows the
        specification (length continuation, padding).
    """
    warnings.warn(
        "parse_tlv() is deprecated, use decode_tlv() instead",
        DeprecationWarning,
        stacklevel=2,
    )
    index, values = 0, list[str]()
    while len(values) < num_fields and index + 1 < len(data):
        length = data[index + 1]
        index += 2
        if index + length > len(data):
            break
        raw = bytes(data[index : index + length])
        index += length
        try:
            values.append(raw.decode("utf-8"))
        except UnicodeDecodeError:
            values.append("")
    return values


def parse_french_date(date_str: str) -> datetime:
    """Parse a complete birth date into a naive :class:`datetime`.

    .. deprecated:: 1.0
        Use :func:`parse_birth_date`, which also supports incomplete dates.
        Despite its name this function accepts French, Dutch and German
        month names; unknown months now raise instead of defaulting to
        January.

    Raises:
        ValueError: If the date is invalid or incomplete.
    """
    warnings.warn(
        "parse_french_date() is deprecated, use parse_birth_date() instead",
        DeprecationWarning,
        stacklevel=2,
    )
    parsed = parse_birth_date(date_str).to_date()
    return datetime(parsed.year, parsed.month, parsed.day)  # noqa: DTZ001
