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
``plugins_tools/eid-viewer/certhelpers.c`` and ``verify.c``), with stricter
rules: every check is derived from the signed files, the RRN certificate
must be an end-entity signing certificate, and the presence of a basic key
is decided by the signed identity file rather than by the unsigned card
data.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
from importlib import resources
from typing import TYPE_CHECKING, Any

from .exceptions import CardDataError
from .models import CardFile, VerificationReport
from .parser import _der_length, parse_address, parse_identity

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from cryptography.x509 import Certificate

    from .models import EidData, Identity

__all__ = [
    "basic_key_matches",
    "bundled_trusted_roots",
    "verify_chip_signature",
    "verify_eid",
    "verify_photo",
]

logger = logging.getLogger(__name__)

_PHOTO_HASHES = {20: "sha1", 32: "sha256", 48: "sha384"}
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


def _load_certificates(data: bytes) -> list[Certificate]:
    """Load one DER certificate, or every certificate of a PEM bundle."""
    x509 = _crypto()
    if data.lstrip().startswith(b"-----BEGIN"):
        certificates: list[Certificate] = x509.load_pem_x509_certificates(data)
        return certificates
    return [x509.load_der_x509_certificate(data[: _der_length(data)])]


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
    tried (safe: the DigestInfo inside the signature binds the algorithm).
    EC signatures (applet 1.8 and re-keyed 1.7 cards) always use SHA-384 and
    are DER-encoded in a zero-padded file.
    """
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    try:
        key = certificate.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return False
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
    try:
        key = issuer.public_key()
        parameters = certificate.signature_algorithm_parameters
        digest = certificate.signature_hash_algorithm
        signature, tbs = certificate.signature, certificate.tbs_certificate_bytes
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
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        return False
    return True


def _trusted(certificate: Certificate, roots: Iterable[Certificate]) -> bool:
    return any(_issued_by(certificate, root) for root in roots)


def _is_data_signer(certificate: Certificate) -> bool:
    """Whether *certificate* is an end-entity certificate allowed to sign.

    The RRN certificate is not a CA (unlike the Citizen and Foreigner CA
    certificates issued by the same roots) and has the digital signature or
    non-repudiation key usage.
    """
    x509 = _crypto()
    extensions = certificate.extensions
    with contextlib.suppress(x509.ExtensionNotFound):
        if extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
    try:
        usage = extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return bool(usage.digital_signature or usage.content_commitment)


def basic_key_matches(basic_public_key: bytes, basic_key_hash: bytes) -> bool:
    """Check the basic public key file against its signed SHA-384 digest.

    Args:
        basic_public_key: Content of the basic public key file, possibly
            zero-padded.
        basic_key_hash: :attr:`Identity.basic_key_hash` (tag ``0x1A``).
    """
    candidates = [basic_public_key]
    with contextlib.suppress(CardDataError):
        candidates.append(basic_public_key[: _der_length(basic_public_key)])
    return any(
        hmac.compare_digest(hashlib.sha384(item).digest(), basic_key_hash)
        for item in candidates
    )


def verify_chip_signature(
    basic_public_key: bytes, nonce: bytes, signature: bytes
) -> bool:
    """Check the answer of the chip to a basic-key challenge (applet 1.8).

    This only checks the signature against *basic_public_key*: the key must
    itself be checked against its signed digest (:func:`basic_key_matches`),
    as :meth:`pythonbeid.CardReader.authenticate_chip` does.

    Args:
        basic_public_key: Content of the basic public key file
            (SubjectPublicKeyInfo DER, possibly zero-padded).
        nonce: The 48-byte challenge sent to the chip.
        signature: The raw ``r || s`` ECDSA signature returned by the chip.

    Raises:
        ValueError: If the nonce is not 48 bytes long.
        CardDataError: If the public key is not a valid EC key.
    """
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed,
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    if len(nonce) != 48:
        msg = "the nonce must be 48 bytes long (SHA-384 digest size)"
        raise ValueError(msg)
    try:
        key = load_der_public_key(basic_public_key[: _der_length(basic_public_key)])
    except (ValueError, UnsupportedAlgorithm) as exc:
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


def _basic_key_valid(
    identity: Identity | None, files: Mapping[CardFile, bytes], errors: list[str]
) -> bool | None:
    # Decided by the signed identity file, never by the unsigned card data,
    # so a card claiming an older applet cannot escape the check.
    if identity is None or identity.basic_key_hash is None:
        return None
    key_file = files.get(CardFile.BASIC_PUBLIC_KEY)
    if key_file is None:
        errors.append("the basic public key was not read, although it is signed")
        return False
    if basic_key_matches(key_file, identity.basic_key_hash):
        return True
    errors.append("the basic public key does not match its signed digest")
    return False


def _decode_signed(
    files: Mapping[CardFile, bytes], errors: list[str]
) -> tuple[Identity | None, Any]:
    try:
        return parse_identity(files[CardFile.IDENTITY]), parse_address(
            files[CardFile.ADDRESS]
        )
    except CardDataError:
        errors.append("the signed files cannot be decoded")
        return None, None


def _load_rrn(files: Mapping[CardFile, bytes], errors: list[str]) -> Certificate | None:
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        return _load_certificates(files[CardFile.RRN_CERTIFICATE])[0]
    except (ValueError, UnsupportedAlgorithm):  # CardDataError is a ValueError
        errors.append("the RRN certificate cannot be decoded")
        return None


def _photo_valid(
    photo: bytes | None, identity: Identity | None, errors: list[str]
) -> bool | None:
    if photo is None:
        return None
    if identity is None:
        return False
    try:
        valid = verify_photo(photo, identity.photo_hash)
    except CardDataError as exc:
        errors.append(str(exc))
        return False
    if not valid:
        errors.append("the photo does not match its signed digest")
    return valid


def _rrn_checks(
    rrn: Certificate | None,
    roots: Iterable[Certificate],
    identity: Identity | None,
    errors: list[str],
) -> tuple[bool, bool]:
    """Return whether the RRN certificate is trusted and in period."""
    if rrn is None:
        return False, False
    trusted = False
    if not _trusted(rrn, roots):
        errors.append("the RRN certificate is not issued by a trusted Belgian root")
    elif not _is_data_signer(rrn):
        errors.append("the RRN certificate is not a data signing certificate")
    else:
        trusted = True
    if identity is None:
        return trusted, False
    in_period = (
        rrn.not_valid_before_utc.date() <= identity.validity_end
        and rrn.not_valid_after_utc.date() >= identity.validity_start
    )
    if not in_period:
        errors.append("the RRN certificate was not valid during the card validity")
    return trusted, in_period


def verify_eid(
    eid: EidData, *, trusted_roots: Sequence[bytes] | None = None
) -> VerificationReport:
    """Check the integrity and authenticity of data read from a card.

    Every check is made on the raw files (:attr:`EidData.files`), and the
    decoded fields of *eid* must match them (``content_matches_files``), so
    data received from an untrusted source (e.g. uploaded to a server) can be
    checked safely. Build such data with :meth:`EidData.from_files`.

    This offline check does not include the live chip challenge, see
    :meth:`pythonbeid.CardReader.verify`. Card content never makes it raise:
    malformed data gives failed checks.

    Args:
        eid: The data to check.
        trusted_roots: Root certificates (PEM, PEM bundles or DER) to trust
            instead of the bundled Belgian roots.

    Returns:
        The outcome of every check; see :attr:`VerificationReport.is_valid`.

    Raises:
        ValueError: If *eid* lacks files needed for the checks (it was read
            with ``integrity=False``), or a trusted root cannot be loaded.
        ImportError: If the ``cryptography`` package is not installed.
    """
    missing = [file.name for file in _REQUIRED_FILES if file not in eid.files]
    if missing:
        msg = (
            f"missing files for verification: {', '.join(missing)} "
            "(read the card with integrity=True)"
        )
        raise ValueError(msg)
    roots = [
        certificate
        for root in (
            bundled_trusted_roots() if trusted_roots is None else trusted_roots
        )
        for certificate in _load_certificates(root)
    ]
    errors: list[str] = []
    files = eid.files

    identity, address = _decode_signed(files, errors)
    photo = files.get(CardFile.PHOTO, eid.photo)
    content_ok = (
        identity is not None
        and eid.identity == identity
        and eid.address == address
        and (eid.photo is None or eid.photo == photo)
    )
    if identity is not None and not content_ok:
        errors.append("the decoded content does not match the signed files")

    photo_valid = _photo_valid(photo, identity, errors)
    rrn = _load_rrn(files, errors)
    hint = _PHOTO_HASHES.get(len(identity.photo_hash)) if identity else None
    identity_signature = files[CardFile.IDENTITY_SIGNATURE]
    identity_valid = rrn is not None and _verify_signature(
        rrn, files[CardFile.IDENTITY], identity_signature, hint
    )
    if rrn is not None and not identity_valid:
        errors.append("the identity signature is invalid")

    # The address signature covers the address file without its trailing
    # zero padding, followed by the complete identity signature file.
    signed_address = files[CardFile.ADDRESS].rstrip(b"\x00") + identity_signature
    address_valid = rrn is not None and _verify_signature(
        rrn, signed_address, files[CardFile.ADDRESS_SIGNATURE], hint
    )
    if rrn is not None and not address_valid:
        errors.append("the address signature is invalid")

    rrn_trusted, period_valid = _rrn_checks(rrn, roots, identity, errors)

    return VerificationReport(
        photo_hash_valid=photo_valid,
        identity_signature_valid=identity_valid,
        address_signature_valid=address_valid,
        rrn_certificate_trusted=rrn_trusted,
        rrn_certificate_period_valid=period_valid,
        content_matches_files=content_ok,
        basic_key_valid=_basic_key_valid(identity, files, errors),
        errors=tuple(errors),
    )
