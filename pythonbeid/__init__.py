"""pythonbeid: read and verify Belgian eID cards through PC/SC.

Quick start::

    from pythonbeid import CardReader

    with CardReader() as reader:
        eid = reader.read()
        print(eid.identity.last_name, eid.identity.birth_date)
        print(reader.verify(eid).is_valid)  # needs pythonbeid[verify]
"""

from importlib.metadata import PackageNotFoundError, version

from .card_reader import CardReader, list_readers
from .exceptions import (
    APDUError,
    BeidError,
    CardCommunicationError,
    CardDataError,
    NoCardError,
    NoReaderError,
    PCSCServiceError,
    UnsupportedCardError,
)
from .integrity import verify_eid, verify_photo
from .models import (
    Address,
    CardFile,
    CardInfo,
    DocumentType,
    EidData,
    Identity,
    PartialDate,
    Sex,
    SpecialStatus,
    VerificationReport,
)
from .parser import (
    decode_tlv,
    is_valid_national_number,
    parse_address,
    parse_birth_date,
    parse_card_data,
    parse_identity,
)

try:
    __version__ = version("pythonbeid")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0+unknown"

__all__ = [
    "APDUError",
    "Address",
    "BeidError",
    "CardCommunicationError",
    "CardDataError",
    "CardFile",
    "CardInfo",
    "CardReader",
    "DocumentType",
    "EidData",
    "Identity",
    "NoCardError",
    "NoReaderError",
    "PCSCServiceError",
    "PartialDate",
    "Sex",
    "SpecialStatus",
    "UnsupportedCardError",
    "VerificationReport",
    "__version__",
    "decode_tlv",
    "is_valid_national_number",
    "list_readers",
    "parse_address",
    "parse_birth_date",
    "parse_card_data",
    "parse_identity",
    "verify_eid",
    "verify_photo",
]
