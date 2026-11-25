"""Shared fixtures: simulated readers and cards, synthetic PKI."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pythonbeid import card_reader

from .builders import Pki, make_pki, signed_files
from .fake_card import FakeCard, FakeReader

if TYPE_CHECKING:
    from collections.abc import Callable

    from pythonbeid.models import CardFile


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--hardware",
        action="store_true",
        default=False,
        help="run the tests that need a reader with a Belgian eID card",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--hardware"):
        return
    skip = pytest.mark.skip(reason="needs --hardware and a Belgian eID card")
    for item in items:
        if "hardware" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def rsa_pki() -> Pki:
    return make_pki("rsa")


@pytest.fixture(scope="session")
def ec_pki() -> Pki:
    return make_pki("ec")


@pytest.fixture(scope="session")
def basic_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def card_from(files: dict[CardFile, bytes], **options: Any) -> FakeCard:
    return FakeCard(
        files={file.path: content for file, content in files.items()}, **options
    )


@pytest.fixture
def card17(rsa_pki: Pki) -> FakeCard:
    """An applet 1.7 card with RSA signatures."""
    return card_from(signed_files(rsa_pki))


@pytest.fixture
def card18(ec_pki: Pki, basic_key: ec.EllipticCurvePrivateKey) -> FakeCard:
    """An applet 1.8 card with ECDSA signatures and a basic key."""
    return card_from(
        signed_files(ec_pki, basic_key=basic_key),
        applet=0x18,
        global_os=0x0001,
        basic_key=basic_key,
    )


@pytest.fixture
def install_readers(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[FakeReader]]:
    """Replace the PC/SC layer with fake readers.

    Usage: ``install_readers(card)`` or ``install_readers(("Name", card), ...)``.
    """

    def install(
        *entries: FakeCard | tuple[str, FakeCard | None] | None
    ) -> list[FakeReader]:
        fakes = []
        for index, entry in enumerate(entries):
            if isinstance(entry, tuple):
                fakes.append(FakeReader(*entry))
            else:
                fakes.append(FakeReader(f"Fake Reader {index}", entry))
        monkeypatch.setattr(card_reader, "_pcsc_readers", lambda: fakes)
        monkeypatch.setattr(
            card_reader, "_wrap_connection", lambda connection: connection
        )
        return fakes

    return install


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    delays: list[float] = []
    monkeypatch.setattr("pythonbeid.card_reader.time.sleep", delays.append)
    return delays
