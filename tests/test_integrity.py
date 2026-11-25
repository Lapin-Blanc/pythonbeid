"""Tests of the integrity checks, with a synthetic PKI."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)

from pythonbeid import (
    CardDataError,
    CardFile,
    EidData,
    parse_address,
    parse_card_data,
    parse_identity,
    verify_eid,
    verify_photo,
)
from pythonbeid.integrity import bundled_trusted_roots, verify_chip_signature

from .builders import PHOTO, address_file, identity_file, make_pki, signed_files
from .fake_card import card_data

if TYPE_CHECKING:
    from .builders import Pki


def _eid(
    files: dict[CardFile, bytes], *, applet: int = 0x17, photo: bool = True
) -> EidData:
    return EidData(
        card=parse_card_data(card_data(applet)),
        identity=parse_identity(files[CardFile.IDENTITY]),
        address=parse_address(files[CardFile.ADDRESS]),
        photo=files[CardFile.PHOTO] if photo else None,
        files=files,
    )


class TestVerifyPhoto:
    @pytest.mark.parametrize("algorithm", ["sha1", "sha256", "sha384"])
    def test_algorithms(self, algorithm: str) -> None:
        assert verify_photo(PHOTO, hashlib.new(algorithm, PHOTO).digest())

    def test_mismatch(self) -> None:
        assert not verify_photo(PHOTO + b"x", hashlib.sha1(PHOTO).digest())

    def test_unknown_digest_length(self) -> None:
        with pytest.raises(CardDataError, match="unexpected photo hash length"):
            verify_photo(PHOTO, bytes(16))


class TestBundledRoots:
    def test_belgian_roots(self) -> None:
        names = [
            x509.load_pem_x509_certificate(pem)
            .subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
            .value
            for pem in bundled_trusted_roots()
        ]
        assert names == [
            "Belgium Root CA2",
            "Belgium Root CA3",
            "Belgium Root CA4",
            "Belgium Root CA6",
        ]

    def test_fingerprints(self) -> None:
        fingerprints = {
            x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()).hex()
            for pem in bundled_trusted_roots()
        }
        assert fingerprints == {
            "9f9744463be13714754e1a3becf98c08cc205e4ab32028f4e2830c4a1b2775b8",
            "a8d14e945e3e5156bcae5e39737cf6a1b1f51028bbbf982f50ce5f4c05568b4d",
            "702dd5c1a093cf0a9d71fadd9bf9a7c5857d89fb73b716e867228b3c2beb968f",
            "9c872bc979a7c09a58d4a274c199e5cb16cfa9b9618d98bc9a9988e984b8495c",
        }

    def test_synthetic_rrn_is_not_trusted_by_default(self, rsa_pki: Pki) -> None:
        report = verify_eid(_eid(signed_files(rsa_pki)))
        assert not report.rrn_certificate_trusted
        assert report.identity_signature_valid
        assert "not issued by a trusted Belgian root" in report.errors[0]


class TestVerifyEid:
    @pytest.mark.parametrize("digest", ["sha1", "sha256"])
    def test_rsa_card(self, rsa_pki: Pki, digest: str) -> None:
        report = verify_eid(
            _eid(signed_files(rsa_pki, digest=digest)), trusted_roots=[rsa_pki.root_pem]
        )
        assert report.is_valid, report.errors
        assert report.photo_hash_valid is True
        assert report.basic_key_valid is None
        assert report.chip_authenticated is None
        assert report.errors == ()

    def test_ec_card(self, ec_pki: Pki, basic_key: ec.EllipticCurvePrivateKey) -> None:
        files = signed_files(ec_pki, basic_key=basic_key)
        report = verify_eid(_eid(files, applet=0x18), trusted_roots=[ec_pki.root_pem])
        assert report.is_valid, report.errors
        assert report.basic_key_valid is True

    def test_der_trusted_root(self, rsa_pki: Pki) -> None:
        root_der = rsa_pki.root.public_bytes(serialization.Encoding.DER)
        assert verify_eid(
            _eid(signed_files(rsa_pki)), trusted_roots=[root_der]
        ).is_valid

    def test_without_photo(self, rsa_pki: Pki) -> None:
        files = signed_files(rsa_pki)
        del files[CardFile.PHOTO]
        report = verify_eid(_eid(files, photo=False), trusted_roots=[rsa_pki.root_pem])
        assert report.photo_hash_valid is None
        assert report.is_valid

    def test_tampered_identity(self, rsa_pki: Pki) -> None:
        files = signed_files(rsa_pki)
        files[CardFile.IDENTITY] = identity_file(tag_07="Forged")
        report = verify_eid(_eid(files), trusted_roots=[rsa_pki.root_pem])
        assert not report.identity_signature_valid
        assert report.address_signature_valid
        assert not report.is_valid
        assert "the identity signature is invalid" in report.errors

    def test_tampered_address(self, ec_pki: Pki) -> None:
        files = signed_files(ec_pki)
        files[CardFile.ADDRESS] = address_file("Elsewhere 1")
        report = verify_eid(_eid(files), trusted_roots=[ec_pki.root_pem])
        assert report.identity_signature_valid
        assert not report.address_signature_valid

    def test_address_signature_bound_to_identity_signature(self, rsa_pki: Pki) -> None:
        """Swapping the identity signature breaks the address signature."""
        files = signed_files(rsa_pki)
        other = signed_files(rsa_pki, identity=identity_file(tag_01="000000000000"))
        files[CardFile.IDENTITY_SIGNATURE] = other[CardFile.IDENTITY_SIGNATURE]
        report = verify_eid(_eid(files), trusted_roots=[rsa_pki.root_pem])
        assert not report.address_signature_valid

    def test_tampered_photo(self, rsa_pki: Pki) -> None:
        files = signed_files(rsa_pki)
        files[CardFile.PHOTO] = PHOTO[:-1] + b"\x00"
        report = verify_eid(_eid(files), trusted_roots=[rsa_pki.root_pem])
        assert report.photo_hash_valid is False
        assert "photo does not match" in report.errors[0]

    def test_bad_photo_hash_length(self, rsa_pki: Pki) -> None:
        identity = identity_file(tag_11=bytes(10))
        report = verify_eid(
            _eid(signed_files(rsa_pki, identity=identity)),
            trusted_roots=[rsa_pki.root_pem],
        )
        assert report.photo_hash_valid is False
        assert report.identity_signature_valid

    def test_foreign_root(self, rsa_pki: Pki) -> None:
        other = make_pki("rsa")
        report = verify_eid(_eid(signed_files(rsa_pki)), trusted_roots=[other.root_pem])
        assert not report.rrn_certificate_trusted

    def test_mixed_key_types_in_trust_store(self, rsa_pki: Pki, ec_pki: Pki) -> None:
        report = verify_eid(
            _eid(signed_files(rsa_pki)),
            trusted_roots=[ec_pki.root_pem, rsa_pki.root_pem],
        )
        assert report.rrn_certificate_trusted

    def test_rrn_expired_before_issuance(self) -> None:
        pki = make_pki(
            "rsa",
            rrn_not_before=datetime(2010, 1, 1, tzinfo=UTC),
            rrn_not_after=datetime(2015, 1, 1, tzinfo=UTC),
        )
        report = verify_eid(_eid(signed_files(pki)), trusted_roots=[pki.root_pem])
        assert not report.rrn_certificate_period_valid
        assert "not valid during the card validity" in report.errors[0]

    def test_resigned_card_with_newer_rrn(self) -> None:
        """Re-signed cards carry an RRN certificate newer than the card."""
        pki = make_pki("ec", rrn_not_before=datetime(2022, 1, 1, tzinfo=UTC))
        report = verify_eid(_eid(signed_files(pki)), trusted_roots=[pki.root_pem])
        assert report.rrn_certificate_period_valid
        assert report.is_valid

    def test_rrn_issued_after_card_expiry(self) -> None:
        pki = make_pki(
            "ec",
            rrn_not_before=datetime(2032, 1, 1, tzinfo=UTC),
            rrn_not_after=datetime(2040, 1, 1, tzinfo=UTC),
        )
        report = verify_eid(_eid(signed_files(pki)), trusted_roots=[pki.root_pem])
        assert not report.rrn_certificate_period_valid

    def test_rrn_expired_today_is_fine(self) -> None:
        """Observed on real cards: the RRN certificate outlives its own validity."""
        pki = make_pki(
            "rsa",
            rrn_not_before=datetime(2020, 1, 1, tzinfo=UTC),
            rrn_not_after=datetime(2021, 3, 20, tzinfo=UTC),
        )
        assert verify_eid(
            _eid(signed_files(pki)), trusted_roots=[pki.root_pem]
        ).is_valid

    def test_missing_files(self, rsa_pki: Pki) -> None:
        files = signed_files(rsa_pki)
        del files[CardFile.RRN_CERTIFICATE]
        with pytest.raises(ValueError, match="RRN_CERTIFICATE"):
            verify_eid(_eid(files))

    def test_garbage_ec_signature(self, ec_pki: Pki) -> None:
        files = signed_files(ec_pki)
        files[CardFile.IDENTITY_SIGNATURE] = b"\x30\x90" + bytes(100)
        report = verify_eid(_eid(files), trusted_roots=[ec_pki.root_pem])
        assert not report.identity_signature_valid

    def test_unsupported_rrn_key(
        self, rsa_pki: Pki, caplog: pytest.LogCaptureFixture
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        key = ed25519.Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "RRN")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(rsa_pki.root.subject)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
            .sign(rsa_pki.root_key, hashes.SHA256())
        )
        files = signed_files(rsa_pki)
        files[CardFile.RRN_CERTIFICATE] = certificate.public_bytes(
            serialization.Encoding.DER
        )
        report = verify_eid(_eid(files), trusted_roots=[rsa_pki.root_pem])
        assert not report.identity_signature_valid
        assert report.rrn_certificate_trusted
        assert "Unsupported RRN key type" in caplog.text


class TestBasicKey:
    def test_mismatch(self, ec_pki: Pki, basic_key: ec.EllipticCurvePrivateKey) -> None:
        files = signed_files(ec_pki, basic_key=basic_key)
        other = ec.generate_private_key(ec.SECP384R1()).public_key()
        files[CardFile.BASIC_PUBLIC_KEY] = other.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        report = verify_eid(_eid(files, applet=0x18), trusted_roots=[ec_pki.root_pem])
        assert report.basic_key_valid is False
        assert "basic public key does not match" in report.errors[0]

    def test_padded_key_file(
        self, ec_pki: Pki, basic_key: ec.EllipticCurvePrivateKey
    ) -> None:
        files = signed_files(ec_pki, basic_key=basic_key)
        files[CardFile.BASIC_PUBLIC_KEY] += bytes(16)
        assert verify_eid(
            _eid(files, applet=0x18), trusted_roots=[ec_pki.root_pem]
        ).basic_key_valid

    def test_garbage_key_file(
        self, ec_pki: Pki, basic_key: ec.EllipticCurvePrivateKey
    ) -> None:
        files = signed_files(ec_pki, basic_key=basic_key)
        files[CardFile.BASIC_PUBLIC_KEY] = b"\x30"
        assert (
            verify_eid(
                _eid(files, applet=0x18), trusted_roots=[ec_pki.root_pem]
            ).basic_key_valid
            is False
        )

    def test_no_signed_digest(
        self, ec_pki: Pki, basic_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Without a signed digest there is nothing to check."""
        files = signed_files(ec_pki, basic_key=basic_key)
        key_file = files[CardFile.BASIC_PUBLIC_KEY]
        files = signed_files(ec_pki)  # identity without tag 0x1A
        files[CardFile.BASIC_PUBLIC_KEY] = key_file
        report = verify_eid(_eid(files, applet=0x18), trusted_roots=[ec_pki.root_pem])
        assert report.basic_key_valid is None

    def test_key_file_not_read(
        self, ec_pki: Pki, basic_key: ec.EllipticCurvePrivateKey
    ) -> None:
        files = signed_files(ec_pki, basic_key=basic_key)
        del files[CardFile.BASIC_PUBLIC_KEY]
        report = verify_eid(_eid(files, applet=0x17), trusted_roots=[ec_pki.root_pem])
        assert report.basic_key_valid is False  # fails closed, whatever the applet
        assert "was not read" in report.errors[0]


class TestChipSignature:
    @staticmethod
    def _key_file(key: ec.EllipticCurvePrivateKey) -> bytes:
        return key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def _sign(key: ec.EllipticCurvePrivateKey, nonce: bytes) -> bytes:
        r, s = decode_dss_signature(
            key.sign(nonce, ec.ECDSA(Prehashed(hashes.SHA384())))
        )
        return r.to_bytes(48, "big") + s.to_bytes(48, "big")

    def test_valid(self, basic_key: ec.EllipticCurvePrivateKey) -> None:
        nonce = bytes(range(48))
        assert verify_chip_signature(
            self._key_file(basic_key), nonce, self._sign(basic_key, nonce)
        )

    def test_wrong_nonce(self, basic_key: ec.EllipticCurvePrivateKey) -> None:
        signature = self._sign(basic_key, bytes(48))
        assert not verify_chip_signature(
            self._key_file(basic_key), bytes([1]) * 48, signature
        )

    @pytest.mark.parametrize("signature", [b"", b"\x01" * 95])
    def test_malformed_signature(
        self, basic_key: ec.EllipticCurvePrivateKey, signature: bytes
    ) -> None:
        assert not verify_chip_signature(
            self._key_file(basic_key), bytes(48), signature
        )

    def test_nonce_length(self, basic_key: ec.EllipticCurvePrivateKey) -> None:
        with pytest.raises(ValueError, match="48 bytes"):
            verify_chip_signature(self._key_file(basic_key), bytes(32), bytes(96))

    def test_invalid_key(self) -> None:
        with pytest.raises(CardDataError, match="invalid basic public key"):
            verify_chip_signature(b"\x30\x03abc", bytes(48), bytes(96))

    def test_rsa_key(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with pytest.raises(CardDataError, match="not an EC key"):
            verify_chip_signature(der, bytes(48), bytes(96))


def test_report_is_replaceable(rsa_pki: Pki) -> None:
    report = verify_eid(_eid(signed_files(rsa_pki)), trusted_roots=[rsa_pki.root_pem])
    changed: Any = replace(report, chip_authenticated=False)
    assert not changed.is_valid


class TestReviewFindings:
    """Regression tests for issues found by an independent review."""

    def test_forged_decoded_fields(self, rsa_pki: Pki) -> None:
        """Genuine files with forged decoded fields must not pass."""
        files = signed_files(rsa_pki)
        forged_photo = PHOTO[:-1] + b"\x01"
        forged = EidData(
            identity=parse_identity(
                identity_file(
                    forged_photo,
                    tag_07="Forged",
                    tag_11=hashlib.sha1(forged_photo).digest(),
                )
            ),
            address=parse_address(files[CardFile.ADDRESS]),
            photo=forged_photo,
            files=files,
        )
        report = verify_eid(forged, trusted_roots=[rsa_pki.root_pem])
        assert not report.content_matches_files
        assert report.identity_signature_valid
        assert not report.is_valid
        assert "does not match the signed files" in report.errors[0]

    def test_from_files(self, rsa_pki: Pki) -> None:
        eid = EidData.from_files(signed_files(rsa_pki))
        assert eid.card is None
        assert eid.photo == PHOTO
        report = verify_eid(eid, trusted_roots=[rsa_pki.root_pem])
        assert report.is_valid, report.errors
        assert report.content_matches_files

    def test_photo_taken_from_files(self, rsa_pki: Pki) -> None:
        files = signed_files(rsa_pki)
        eid = replace(EidData.from_files(files), photo=PHOTO + b"x")
        report = verify_eid(eid, trusted_roots=[rsa_pki.root_pem])
        assert report.photo_hash_valid is True  # the signed photo file is fine
        assert not report.content_matches_files

    def test_undecodable_files(self, rsa_pki: Pki) -> None:
        files = signed_files(rsa_pki)
        eid = EidData.from_files(files)
        files[CardFile.IDENTITY] = b"\x01\x09"
        report = verify_eid(replace(eid, files=files), trusted_roots=[rsa_pki.root_pem])
        assert not report.content_matches_files
        assert report.photo_hash_valid is False
        assert not report.rrn_certificate_period_valid
        assert "cannot be decoded" in report.errors[0]

    def test_ca_certificate_as_signer(self) -> None:
        pki = make_pki("rsa", rrn_ca=True, rrn_signing_usage=False)
        report = verify_eid(_eid(signed_files(pki)), trusted_roots=[pki.root_pem])
        assert report.identity_signature_valid
        assert not report.rrn_certificate_trusted
        assert "not a data signing certificate" in report.errors[0]

    def test_signer_without_signing_usage(self) -> None:
        pki = make_pki("ec", rrn_ca=None, rrn_signing_usage=False)
        report = verify_eid(_eid(signed_files(pki)), trusted_roots=[pki.root_pem])
        assert not report.rrn_certificate_trusted

    def test_signer_without_key_usage(self, rsa_pki: Pki) -> None:
        from pythonbeid.integrity import _is_data_signer

        certificate = (
            x509.CertificateBuilder()
            .subject_name(rsa_pki.rrn.subject)
            .issuer_name(rsa_pki.root.subject)
            .public_key(rsa_pki.rrn_key.public_key())
            .serial_number(2)
            .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
            .sign(rsa_pki.root_key, hashes.SHA256())
        )
        assert _is_data_signer(certificate)

    @pytest.mark.parametrize("content", [b"\x30\x03abc", bytes(1200), b"garbage"])
    def test_malformed_rrn_certificate(self, rsa_pki: Pki, content: bytes) -> None:
        files = signed_files(rsa_pki)
        files[CardFile.RRN_CERTIFICATE] = content
        report = verify_eid(_eid(files), trusted_roots=[rsa_pki.root_pem])
        assert not report.identity_signature_valid
        assert not report.rrn_certificate_trusted
        assert "RRN certificate cannot be decoded" in report.errors[0]

    def test_pem_bundle(self, rsa_pki: Pki) -> None:
        bundle = make_pki("rsa").root_pem + rsa_pki.root_pem
        report = verify_eid(_eid(signed_files(rsa_pki)), trusted_roots=[bundle])
        assert report.rrn_certificate_trusted

    def test_basic_key_matches(self, basic_key: ec.EllipticCurvePrivateKey) -> None:
        from pythonbeid.integrity import basic_key_matches

        der = basic_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashlib.sha384(der).digest()
        assert basic_key_matches(der, digest)
        assert basic_key_matches(der + bytes(8), digest)
        assert not basic_key_matches(der, bytes(48))


def test_unreadable_public_key() -> None:
    from unittest.mock import MagicMock

    from pythonbeid.integrity import _verify_signature

    certificate = MagicMock()
    certificate.public_key.side_effect = ValueError("unsupported key")
    assert _verify_signature(certificate, b"data", b"signature", None) is False
