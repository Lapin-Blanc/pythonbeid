"""Command-line interface: ``pythonbeid`` or ``python -m pythonbeid``."""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__
from .card_reader import CardReader, list_readers
from .exceptions import BeidError

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["main"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INVALID = 3


def _reader_argument(value: str) -> int | str:
    return int(value) if value.isdigit() else value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pythonbeid",
        description="Read and verify Belgian eID cards through PC/SC.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="show progress (-v) or the APDU trace without card data (-vv)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("readers", help="list the connected readers")

    card_options = argparse.ArgumentParser(add_help=False)
    card_options.add_argument(
        "-r",
        "--reader",
        type=_reader_argument,
        help="reader index or name (default: first reader holding an eID card)",
    )
    card_options.add_argument(
        "-t",
        "--timeout",
        type=float,
        help="seconds to wait for a card to be inserted",
    )
    card_options.add_argument(
        "--json", action="store_true", help="print JSON instead of text"
    )

    commands.add_parser(
        "info", parents=[card_options], help="show reader, ATR and chip information"
    )
    read = commands.add_parser(
        "read", parents=[card_options], help="read identity and address"
    )
    read.add_argument(
        "--photo", type=Path, metavar="FILE", help="also save the photo (JPEG)"
    )
    verify = commands.add_parser(
        "verify",
        parents=[card_options],
        help="check signatures, certificates and chip (needs pythonbeid[verify])",
    )
    verify.add_argument(
        "--no-chip",
        action="store_true",
        help="skip the chip challenge of applet 1.8 cards",
    )
    return parser


def _print_section(title: str, values: dict[str, Any]) -> None:
    print(title)
    width = max(len(key) for key in values)
    for key, value in values.items():
        if value in ("", None, []):
            continue
        print(f"  {key.replace('_', ' '):<{width}} : {value}")


def _open(args: argparse.Namespace) -> CardReader:
    return CardReader(args.reader, timeout=args.timeout)


def _info(args: argparse.Namespace) -> int:
    with _open(args) as reader:
        data = {
            "reader": reader.reader_name,
            "atr": reader.atr.hex(" ").upper(),
            **reader.card_info.to_dict(),
        }
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        _print_section("Card", data)
    return EXIT_OK


def _read(args: argparse.Namespace) -> int:
    with _open(args) as reader:
        eid = reader.read(photo=args.photo is not None, integrity=False)
    if args.photo is not None and eid.photo is not None:
        args.photo.write_bytes(eid.photo)
    if args.json:
        # ASCII escapes keep the JSON lossless whatever the console encoding.
        print(json.dumps(eid.to_dict(include_photo=False), indent=2))
    else:
        _print_section("Identity", eid.identity.to_dict())
        _print_section("Address", eid.address.to_dict())
        if args.photo is not None:
            print(f"Photo saved to {args.photo}")
    return EXIT_OK


def _verify(args: argparse.Namespace) -> int:
    with _open(args) as reader:
        report = reader.verify(authenticate_chip=not args.no_chip)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        checks = report.to_dict()
        errors = checks.pop("errors")
        valid = checks.pop("is_valid")
        _print_section(
            "Verification",
            {key: _VERDICTS[value] for key, value in checks.items()},
        )
        for error in errors:
            print(f"  ! {error}")
        print("Result: VALID" if valid else "Result: INVALID")
    return EXIT_OK if report.is_valid else EXIT_INVALID


_VERDICTS = {True: "ok", False: "FAILED", None: "not applicable"}


def _tolerate_console_encoding() -> None:
    """Avoid crashing on names a legacy console code page cannot encode."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="replace")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the exit status."""
    args = _build_parser().parse_args(argv)
    _tolerate_console_encoding()
    level = {0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    try:
        if args.command == "readers":
            for index, name in enumerate(list_readers()):
                print(f"{index}: {name}")
            return EXIT_OK
        handlers = {"info": _info, "read": _read, "verify": _verify}
        return handlers[args.command](args)
    except (BeidError, ImportError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
