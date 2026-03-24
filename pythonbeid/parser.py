"""Pure parsing functions for Belgian eID card data.

These functions have no I/O dependencies and can be tested without hardware.
"""
from datetime import datetime

# French month abbreviations as found on Belgian eID cards.
_MONTH_MAP: dict[str, str] = {
    "JANV": "01", "JAN": "01",
    "FEVR": "02", "FEV": "02",
    "MARS": "03", "MAR": "03",
    "AVRI": "04", "AVR": "04",
    "MAI":  "05",
    "JUIN": "06",
    "JUIL": "07",
    "AOUT": "08", "AOU": "08",
    "SEPT": "09", "SEP": "09",
    "OCTO": "10", "OCT": "10",
    "NOVE": "11", "NOV": "11",
    "DECE": "12", "DEC": "12",
}


def parse_tlv(data: list[int], num_fields: int) -> list[str]:
    """Parse a TLV-encoded buffer from a Belgian eID card.

    Each record has the format: [tag: 1 byte] [length: 1 byte] [value: length bytes].
    Parsing stops once *num_fields* records have been extracted or the buffer
    is exhausted (whichever comes first).

    Args:
        data: Raw bytes received from the card (list of ints, 0-255).
        num_fields: Maximum number of fields to extract.

    Returns:
        Decoded string values; an empty string is used for any field that
        cannot be decoded as UTF-8.
    """
    idx = 0
    fields: list[str] = []
    while len(fields) < num_fields:
        # Need at least 2 bytes for tag + length.
        if idx + 1 >= len(data):
            break
        # tag byte (idx) — not used for value extraction
        idx += 1
        length = data[idx]
        idx += 1
        # Guard against a truncated buffer.
        if idx + length > len(data):
            break
        raw = bytes(data[idx: idx + length])
        idx += length
        try:
            fields.append(raw.decode("utf-8"))
        except UnicodeDecodeError:
            fields.append("")
    return fields


def parse_french_date(date_str: str) -> datetime:
    """Parse a French date string as printed on Belgian eID cards.

    Expected format: ``DD MON YYYY`` where *MON* is a French month
    abbreviation (e.g. ``"15 JANV 2000"`` or ``"03 MAR 1985"``).

    Unknown month abbreviations fall back to January ("01").

    Args:
        date_str: Date string to parse.

    Returns:
        Parsed date as a ``datetime`` (time component is midnight, no timezone).
    """
    parts = date_str.split()
    if len(parts) != 3:
        raise ValueError(f"Unexpected date format: {date_str!r}")
    day, month_abbr, year = parts
    month = _MONTH_MAP.get(month_abbr.upper(), "01")
    return datetime.strptime(f"{day}/{month}/{year}", "%d/%m/%Y")
