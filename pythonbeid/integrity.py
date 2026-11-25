"""Integrity and authenticity checks of Belgian eID data.

The National Register (RRN) signs the identity file and the address file;
the identity file holds the digest of the photo and, on applet 1.8 cards, of
the chip's basic public key. Checking all of them proves the data was issued
by the Belgian state and was not altered. On applet 1.8 cards, the chip
challenge (:meth:`pythonbeid.CardReader.authenticate_chip`) additionally
proves the data comes from a genuine chip rather than a copy.

:func:`verify_photo` only needs the standard library. Every other function
needs the ``cryptography`` package::

    pip install "pythonbeid[verify]"

Trusted roots: Belgium Root CA2, CA3, CA4 and CA6, downloaded from
``certs.eid.belgium.be`` and ``crt.eidpki.belgium.be`` (SHA-256 fingerprints
are listed in the README).

The logic mirrors the official eID Viewer (``Fedict/eid-mw``,
``plugins_tools/eid-viewer/certhelpers.c`` and ``verify.c``).
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
from datetime import timedelta
from importlib import resources
from typing import TYPE_CHECKING, Any

from .exceptions import CardDataError
from .models import CardFile, VerificationReport
from .parser import _der_length

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from cryptography.x509 import Certificate

    from .models import EidData

__all__ = [
    "bundled_trusted_roots",
    "verify_chip_signature",
    "verify_eid",
    "verify_photo",
]

logger = logging.getLogger(__name__)

_PHOTO_HASHES = {20: "sha1", 32: "sha256", 48: "sha384"}
# Cards are personalised (and signed) before their validity starts.
_ISSUANCE_GRACE = timedelta(days=31)
_REQUIRED_FILES = (
    CardFile.IDENTITY,
    CardFile.IDENTITY_SIGNATURE,
    CardFile.ADDRESS,
    CardFile.ADDRESS_SIGNATURE,
    CardFile.RRN_CERTIFICATE,
)


def verify_photo(photo: bytes, photo_hash: bytes) -> bool:
    """Check a photo against the digest stored in the identity file.

    The algorithm is deduced from the digest length: SHA-1 (older applet 1.7
    cards), SHA-256 (recent applet 1.7 cards) or SHA-384 (applet 1.8).

    Raises:
        CardDataError: If the digest length matches no known algorithm.
    """
    algorithm = _PHOTO_HASHES.get(len(photo_hash))
    if algorithm is None:
        msg = f"unexpected photo hash length: {len(photo_hash)} bytes"
        raise CardDataError(msg)
    return hmac.compare_digest(hashlib.new(algorithm, photo).digest(), photo_hash)


def _crypto() -> Any:
    try:
        import cryptography.x509
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        msg = (
            "Signature verification needs the 'cryptography' package: "
            "pip install 'pythonbeid[verify]'"
        )
        raise ImportError(msg) from exc
    return cryptography.x509


def bundled_trusted_roots() -> list[bytes]:
    """Return the bundled Belgian root certificates (PEM)."""
    folder = resources.files("pythonbeid").joinpath("trust")
    return [
        item.read_bytes()
        for item in sorted(folder.iterdir(), key=lambda entry: entry.name)
        if item.name.endswith(".pem")
    ]


def _load_certificate(data: bytes) -> Certificate:
    x509 = _crypto()
    if data.lstrip().startswith(b"-----BEGIN"):
        certificate: Certificate = x509.load_pem_x509_certificate(data)
    else:
        certificate = x509.load_der_x509_certificate(data[: _der_length(data)])
    return certificate


def _hash(name: str) -> Any:
    from cryptography.hazmat.primitives import hashes

    return {
        "sha1": hashes.SHA1(),  # noqa: S303 - mandated by applet 1.7 cards
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }[name]


def _verify_signature(
    certificate: Certificate, data: bytes, signature: bytes, hash_hint: str | None
) -> bool:
    """Verify a data signature made with the key of *certificate*.

    RSA signatures (applet 1.7) use PKCS#1 v1.5. Some re-signed cards mix a
    SHA-1 photo digest with SHA-256 signatures, so every usual digest is
    tried. EC signatures (applet 1.8 and re-keyed 1.7 cards) always use
    SHA-384 and are DER-encoded in a zero-padded file.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import (
        ec,
        padding,
        rsa,
    )

    key = certificate.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        try:
            key.verify(
                signature[: _der_length(signature)], data, ec.ECDSA(_hash("sha384"))
            )
        except (InvalidSignature, CardDataError):
            return False
        return True
    if not isinstance(key, rsa.RSAPublicKey):
        logger.warning("Unsupported RRN key type: %s", type(key).__name__)
        return False
    names = dict.fromkeys(
        name for name in (hash_hint, "sha256", "sha1", "sha384", "sha512") if name
    )
    for name in names:
        try:
            key.verify(signature, data, padding.PKCS1v15(), _hash(name))
        except InvalidSignature:
            continue
        return True
    return False


def _issued_by(certificate: Certificate, issuer: Certificate) -> bool:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    if certificate.issuer != issuer.subject:
        return False
    key = issuer.public_key()
    parameters = certificate.signature_algorithm_parameters
    digest = certificate.signature_hash_algorithm
    signature, tbs = certificate.signature, certificate.tbs_certificate_bytes
    try:
        if (
            isinstance(key, rsa.RSAPublicKey)
            and isinstance(parameters, padding.PKCS1v15 | padding.PSS)
            and digest is not None
        ):
            key.verify(signature, tbs, parameters, digest)
        elif isinstance(key, ec.EllipticCurvePublicKey) and isinstance(
            parameters, ec.ECDSA
        ):
            key.verify(signature, tbs, parameters)
        else:
            # A root with the right name but another key type is simply not
            # the issuer.
            return False
    except (InvalidSignature, UnsupportedAlgorithm):
        return False
    return True


def _trusted(certificate: Certificate, roots: Iterable[Certificate]) -> bool:
    return any(_issued_by(certificate, root) for root in roots)


def verify_chip_signature(
    basic_public_key: bytes, nonce: bytes, signature: bytes
) -> bool:
    """Check the answer of the chip to a basic-key challenge (applet 1.8).

    Args:
        basic_public_key: Content of the basic public key file
            (SubjectPublicKeyInfo DER, possibly zero-padded).
        nonce: The 48-byte challenge sent to the chip.
        signature: The raw ``r || s`` ECDSA signature returned by the chip.

    Raises:
        ValueError: If the nonce is not 48 bytes long.
        CardDataError: If the public key is not a valid EC key.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed,
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives.serialization import (
        load_der_public_key,
    )

    if len(nonce) != 48:
        msg = "the nonce must be 48 bytes long (SHA-384 digest size)"
        raise ValueError(msg)
    try:
        key = load_der_public_key(basic_public_key[: _der_length(basic_public_key)])
    except ValueError as exc:
        msg = "invalid basic public key"
        raise CardDataError(msg) from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        msg = "the basic public key is not an EC key"
        raise CardDataError(msg)
    if not signature or len(signature) % 2:
        return False
    half = len(signature) // 2
    der_signature = encode_dss_signature(
        int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
    )
    try:
        key.verify(der_signature, nonce, ec.ECDSA(Prehashed(_hash("sha384"))))
    except InvalidSignature:
        return False
    return True


def _basic_key_valid(eid: EidData, errors: list[str]) -> bool | None:
    if not eid.card.has_basic_key:
        return None
    key_file = eid.files.get(CardFile.BASIC_PUBLIC_KEY)
    expected = eid.identity.basic_key_hash
    if key_file is None:
        return None
    if expected is None:
        errors.append("the identity file holds no basic key digest")
        return False
    candidates = [key_file]
    with contextlib.suppress(CardDataError):
        candidates.append(key_file[: _der_length(key_file)])
    if any(
        hmac.compare_digest(hashlib.sha384(item).digest(), expected)
        for item in candidates
    ):
        return True
    errors.append("the basic public key does not match its signed digest")
    return False


def verify_eid(
    eid: EidData, *, trusted_roots: Sequence[bytes] | None = None
) -> VerificationReport:
    """Check the integrity and authenticity of data read from a card.

    This is an offline check of :class:`~pythonbeid.EidData` obtained with
    ``CardReader.read(integrity=True)``. It does not include the live chip
    challenge, see :meth:`pythonbeid.CardReader.verify`.

    Args:
        eid: The data to check.
        trusted_roots: Root certificates (PEM or DER) to trust instead of the
            bundled Belgian roots.

    Returns:
        The outcome of every check; see :attr:`VerificationReport.is_valid`.

    Raises:
        ValueError: If *eid* lacks files needed for the checks (it was read
            with ``integrity=False``).
        ImportError: If the ``cryptography`` package is not installed.
    """
    missing = [file.name for file in _REQUIRED_FILES if file not in eid.files]
    if missing:
        msg = (
            f"missing files for verification: {', '.join(missing)} "
            "(read the card with integrity=True)"
        )
        raise ValueError(msg)
    errors: list[str] = []
    files = eid.files
    identity = eid.identity

    photo_valid: bool | None = None
    if eid.photo is not None:
        try:
            photo_valid = verify_photo(eid.photo, identity.photo_hash)
        except CardDataError as exc:
            photo_valid = False
            errors.append(str(exc))
        else:
            if not photo_valid:
                errors.append("the photo does not match its signed digest")

    rrn = _load_certificate(files[CardFile.RRN_CERTIFICATE])
    hint = _PHOTO_HASHES.get(len(identity.photo_hash))
    identity_signature = files[CardFile.IDENTITY_SIGNATURE]
    identity_valid = _verify_signature(
        rrn, files[CardFile.IDENTITY], identity_signature, hint
    )
    if not identity_valid:
        errors.append("the identity signature is invalid")

    # The address signature covers the address file without its trailing
    # zero padding, followed by the complete identity signature file.
    signed_address = files[CardFile.ADDRESS].rstrip(b"\x00") + identity_signature
    address_valid = _verify_signature(
        rrn, signed_address, files[CardFile.ADDRESS_SIGNATURE], hint
    )
    if not address_valid:
        errors.append("the address signature is invalid")

    roots = [
        _load_certificate(root)
        for root in (
            bundled_trusted_roots() if trusted_roots is None else trusted_roots
        )
    ]
    rrn_trusted = _trusted(rrn, roots)
    if not rrn_trusted:
        errors.append("the RRN certificate is not issued by a trusted Belgian root")

    start = identity.validity_start
    at_issuance = (
        rrn.not_valid_before_utc.date()
        <= start
        <= rrn.not_valid_after_utc.date() + _ISSUANCE_GRACE
    )
    if not at_issuance:
        errors.append("the RRN certificate was not valid when the card was issued")

    return VerificationReport(
        photo_hash_valid=photo_valid,
        identity_signature_valid=identity_valid,
        address_signature_valid=address_valid,
        rrn_certificate_trusted=rrn_trusted,
        rrn_certificate_valid_at_issuance=at_issuance,
        basic_key_valid=_basic_key_valid(eid, errors),
        errors=tuple(errors),
    )
