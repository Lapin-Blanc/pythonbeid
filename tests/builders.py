"""Builders for synthetic card content and a synthetic Belgian-like PKI.

Nothing here comes from a real card: names are fictitious and every key is
generated for the test session.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from pythonbeid.models import CardFile

PHOTO = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 11 + b"\xff\xd9"  # 2822 bytes
KeyKind = Literal["rsa", "ec"]


def tlv(*records: tuple[int, bytes | str]) -> bytes:
    """Encode records with the eID TLV rules (``FF`` length continuation)."""
    out = bytearray()
    for tag, value in records:
        raw = value.encode("utf-8") if isinstance(value, str) else value
        out.append(tag)
        length = len(raw)
        while length >= 0xFF:
            out.append(0xFF)
            length -= 0xFF
        out.append(length)
        out += raw
    return bytes(out)


def national_number(base9: str, *, born_after_2000: bool = False) -> str:
    """Append the modulo-97 checksum to the first nine digits."""
    number = int(("2" if born_after_2000 else "") + base9)
    return f"{base9}{97 - number % 97:02d}"


def identity_records(
    photo: bytes = PHOTO, *, photo_hash: str = "sha1", **overrides: bytes | str | None
) -> list[tuple[int, bytes | str]]:
    """Records of a plausible identity file; ``tag_XX=None`` removes a tag."""
    records: dict[int, bytes | str] = {
        0x01: "592123456789",
        0x02: bytes.fromhex("534C494E336600296CFF2623660B0826"),
        0x03: "10.03.2021",
        0x04: "10.03.2031",
        0x05: "Bruxelles",
        0x06: national_number("850324123"),
        0x07: "Specimen",
        0x08: "Alice Geldig",
        0x09: "B",
        0x0A: "Belge",
        0x0B: "Ixelles",
        0x0C: "24 MARS 1985",
        0x0D: "F",
        0x0E: "",
        0x0F: "01",
        0x10: "0",
        0x11: hashlib.new(photo_hash, photo).digest(),
    }
    for key, value in overrides.items():
        tag = int(key.removeprefix("tag_"), 16)
        if value is None:
            records.pop(tag, None)
        else:
            records[tag] = value
    return sorted(records.items())


def identity_file(
    photo: bytes = PHOTO,
    /,
    *,
    photo_hash: str = "sha1",
    **overrides: bytes | str | None,
) -> bytes:
    return tlv(*identity_records(photo, photo_hash=photo_hash, **overrides))


def address_file(street: str = "Rue de la Loi 16   ", padding: int = 58) -> bytes:
    return tlv((0x01, street), (0x02, "1000"), (0x03, "Bruxelles")) + bytes(padding)


# ── PKI ───────────────────────────────────────────────────────────────────


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BE"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _key(kind: KeyKind) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP384R1())


def _certificate(  # noqa: PLR0917 - private test helper
    subject: str,
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    issuer: str,
    issuer_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    not_before: datetime,
    not_after: datetime,
    signature_hash: hashes.SHA256 | hashes.SHA384,
    *,
    ca: bool | None = None,
    signing_usage: bool = True,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=signing_usage,
            content_commitment=signing_usage,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=not signing_usage,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    return builder.sign(issuer_key, signature_hash)


@dataclass
class Pki:
    """A root CA and an RRN certificate, as found on a card."""

    kind: KeyKind
    root_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    root: x509.Certificate
    rrn_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    rrn: x509.Certificate

    @property
    def root_pem(self) -> bytes:
        return self.root.public_bytes(serialization.Encoding.PEM)

    @property
    def rrn_file(self) -> bytes:
        """RRN certificate file: DER followed by zero padding."""
        return self.rrn.public_bytes(serialization.Encoding.DER) + bytes(64)

    def sign(self, data: bytes, digest: str = "sha256") -> bytes:
        """Signature file content for *data*, padded like on a card."""
        if isinstance(self.rrn_key, rsa.RSAPrivateKey):
            return self.rrn_key.sign(data, padding.PKCS1v15(), _hash(digest))
        der = self.rrn_key.sign(data, ec.ECDSA(hashes.SHA384()))
        return der + bytes(256 - len(der))


def _hash(name: str) -> hashes.HashAlgorithm:
    return {
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
    }[name]


def make_pki(
    kind: KeyKind = "rsa",
    *,
    rrn_not_before: datetime | None = None,
    rrn_not_after: datetime | None = None,
    rrn_ca: bool | None = False,
    rrn_signing_usage: bool = True,
) -> Pki:
    now = datetime.now(UTC)
    root_key, rrn_key = _key(kind), _key(kind)
    digest: hashes.SHA256 | hashes.SHA384 = (
        hashes.SHA256() if kind == "rsa" else hashes.SHA384()
    )
    root = _certificate(
        "Test Root CA", root_key, "Test Root CA", root_key,
        now - timedelta(days=3650), now + timedelta(days=3650), digest,
    )  # fmt: skip
    rrn = _certificate(
        "RRN", rrn_key, "Test Root CA", root_key,
        rrn_not_before or datetime(2020, 1, 1, tzinfo=UTC),
        rrn_not_after or datetime(2030, 1, 1, tzinfo=UTC),
        digest, ca=rrn_ca, signing_usage=rrn_signing_usage,
    )  # fmt: skip
    return Pki(kind, root_key, root, rrn_key, rrn)


def signed_files(
    pki: Pki,
    *,
    identity: bytes | None = None,
    address: bytes | None = None,
    photo: bytes = PHOTO,
    digest: str = "sha256",
    basic_key: ec.EllipticCurvePrivateKey | None = None,
) -> dict[CardFile, bytes]:
    """Card files signed like the National Register does."""
    extra: dict[str, bytes | str | None] = {}
    key_file = b""
    if basic_key is not None:
        key_file = basic_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        extra["tag_1A"] = hashlib.sha384(key_file).digest()
    if identity is None:
        identity = identity_file(
            photo, photo_hash="sha384" if pki.kind == "ec" else "sha1", **extra
        )
    if address is None:
        address = address_file()
    identity_signature = pki.sign(identity, digest)
    address_signature = pki.sign(address.rstrip(b"\x00") + identity_signature, digest)
    files = {
        CardFile.IDENTITY: identity,
        CardFile.IDENTITY_SIGNATURE: identity_signature,
        CardFile.ADDRESS: address,
        CardFile.ADDRESS_SIGNATURE: address_signature,
        CardFile.PHOTO: photo,
        CardFile.RRN_CERTIFICATE: pki.rrn_file,
    }
    if basic_key is not None:
        files[CardFile.BASIC_PUBLIC_KEY] = key_file
    return files
