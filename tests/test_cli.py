"""Tests of the command-line interface."""

from __future__ import annotations

import json
import re
import runpy
from typing import TYPE_CHECKING, Any

import pytest

from pythonbeid import __version__, cli

from .builders import PHOTO

if TYPE_CHECKING:
    from pathlib import Path

    from .builders import Pki
    from .fake_card import FakeCard


@pytest.fixture
def trust_synthetic_root(
    monkeypatch: pytest.MonkeyPatch, rsa_pki: Pki, ec_pki: Pki
) -> None:
    from pythonbeid import integrity

    monkeypatch.setattr(
        integrity, "bundled_trusted_roots", lambda: [rsa_pki.root_pem, ec_pki.root_pem]
    )


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_command_required(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main([])
    assert info.value.code == 2
    assert "required" in capsys.readouterr().err


def test_readers(
    install_readers: Any, card17: FakeCard, capsys: pytest.CaptureFixture[str]
) -> None:
    install_readers(("ACS ACR38U 0", card17), ("Other", None))
    assert cli.main(["readers"]) == 0
    assert capsys.readouterr().out.splitlines() == ["0: ACS ACR38U 0", "1: Other"]


def test_info_text(
    install_readers: Any, card17: FakeCard, capsys: pytest.CaptureFixture[str]
) -> None:
    install_readers(card17)
    assert cli.main(["info"]) == 0
    out = capsys.readouterr().out
    assert re.search(r"applet version string\s+: 1\.7", out)
    assert re.search(r"atr\s+: 3B 98", out)


def test_info_json(
    install_readers: Any, card18: FakeCard, capsys: pytest.CaptureFixture[str]
) -> None:
    install_readers(("Reader", card18))
    assert cli.main(["info", "--json", "--reader", "Reader"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["applet_version_string"] == "1.8"
    assert data["pin_attempts_left"] == 3
    assert data["reader"] == "Reader"


def test_read_text(
    install_readers: Any, card17: FakeCard, capsys: pytest.CaptureFixture[str]
) -> None:
    install_readers(card17)
    assert cli.main(["read", "-r", "0"]) == 0
    out = capsys.readouterr().out
    assert "last name" in out
    assert "Specimen" in out
    assert "Rue de la Loi 16" in out
    assert "noble condition" not in out  # empty values are hidden


def test_read_json_and_photo(
    install_readers: Any,
    card17: FakeCard,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    install_readers(card17)
    photo = tmp_path / "photo.jpg"
    assert cli.main(["read", "--json", "--photo", str(photo)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["identity"]["last_name"] == "Specimen"
    assert "photo" not in data
    assert photo.read_bytes() == PHOTO


def test_read_text_with_photo(
    install_readers: Any,
    card17: FakeCard,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    install_readers(card17)
    photo = tmp_path / "photo.jpg"
    assert cli.main(["read", "--photo", str(photo)]) == 0
    assert f"Photo saved to {photo}" in capsys.readouterr().out


@pytest.mark.usefixtures("trust_synthetic_root")
def test_verify_valid(
    install_readers: Any, card18: FakeCard, capsys: pytest.CaptureFixture[str]
) -> None:
    install_readers(card18)
    assert cli.main(["verify"]) == 0
    out = capsys.readouterr().out
    assert "chip authenticated" in out
    assert "Result: VALID" in out


@pytest.mark.usefixtures("trust_synthetic_root")
def test_verify_invalid(
    install_readers: Any, card17: FakeCard, capsys: pytest.CaptureFixture[str]
) -> None:
    card17.files[next(iter(card17.files))] += b"\x00"  # alter the identity file
    install_readers(card17)
    assert cli.main(["verify", "--no-chip"]) == cli.EXIT_INVALID
    out = capsys.readouterr().out
    assert "! the identity signature is invalid" in out
    assert "Result: INVALID" in out


@pytest.mark.usefixtures("trust_synthetic_root")
def test_verify_json(
    install_readers: Any, card17: FakeCard, capsys: pytest.CaptureFixture[str]
) -> None:
    install_readers(card17)
    assert cli.main(["verify", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["is_valid"] is True
    assert data["chip_authenticated"] is None


def test_error_exit(install_readers: Any, capsys: pytest.CaptureFixture[str]) -> None:
    install_readers()
    assert cli.main(["-vv", "info"]) == cli.EXIT_ERROR
    assert "error: No smart card reader detected" in capsys.readouterr().err


def test_module_entry_point(
    install_readers: Any,
    card17: FakeCard,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_readers(card17)
    monkeypatch.setattr("sys.argv", ["pythonbeid", "readers"])
    with pytest.raises(SystemExit) as info:
        runpy.run_module("pythonbeid", run_name="__main__")
    assert info.value.code == 0
    assert "Fake Reader 0" in capsys.readouterr().out
