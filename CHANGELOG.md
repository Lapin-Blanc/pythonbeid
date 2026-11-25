# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.2] - 2026-11-25

### Fixed

- Transient transmission errors made reading fail with some readers (about
  one command in two hundred with a reader using the Windows generic CCID
  driver, `ERROR_IO_DEVICE`). The command is now repeated, and the whole
  operation replayed after reconnecting if errors persist, as the official
  middleware does for `SCARD_E_COMM_DATA_LOST` and `SCARD_E_NOT_TRANSACTED`.

### Changed

- Documentation: applet 1.8 support validated on a physical card (every
  check, including the basic key and the chip challenge).

## [1.0.1] - 2026-11-25

### Fixed

- A card held exclusively by another application (for instance the eID
  middleware during a browser authentication) was reported as missing.
  The connection is now retried for one second, then fails with the new
  `CardInUseError`, which says so.

## [1.0.0] - 2026-11-25

### Added

- Typed API: `CardReader.read()` returns an immutable `EidData` with
  `Identity`, `Address` and `CardInfo` dataclasses; `read_identity()`,
  `read_address()`, `read_photo()`, `read_file()`, `read_certificate()`,
  `read_card_info()`.
- Every field of the identity file defined by the specification v5.0
  (tags `0x00` to `0x1F`), including noble condition, document type, special
  status, photo and basic key digests and the fields of residence cards.
- `PartialDate` for incomplete birth dates, `Sex`, `DocumentType` and
  `SpecialStatus` enums, `is_valid_national_number()`.
- Authenticity checks (`pip install "pythonbeid[verify]"`): photo digest,
  identity and address signatures (RSA and ECDSA), RRN certificate chain to
  the bundled Belgian roots CA2, CA3, CA4 and CA6 (end-entity signing
  certificate only), consistency of the decoded data with the signed files,
  basic key and chip challenge on applet 1.8 cards. `CardReader.verify()`,
  `CardReader.authenticate_chip()`, `verify_eid()`, `verify_photo()`,
  `basic_key_matches()`.
- `EidData.from_files()` to decode and verify raw files received from
  elsewhere (e.g. on a server).
- Reader selection by index, name or substring; automatic selection of the
  reader holding a Belgian eID card; `timeout` to wait for a card.
- Command line: `pythonbeid readers | info | read | verify` and
  `python -m pythonbeid`.
- `py.typed` marker, `__version__`, `CardFile` enum of the card files.
- `BeidError` base exception, `PCSCServiceError`, `UnsupportedCardError`,
  `CardDataError`; `APDUError.sw`.
- Card values (names, dates...) never appear in log or exception messages.

### Fixed

- Birth dates written in Dutch or German: most months were silently read as
  January, and German dates (`22.DEZ. 1997`) raised an error.
- Reading a file whose size is a multiple of the block size raised
  `APDUError` (`6B00` at end of file).
- `61xx` answers were accepted without GET RESPONSE, silently returning
  truncated data.
- TLV parsing ignored tags: fields were taken by position, which breaks when
  a tag is absent or when the version tag `0x00` is present. Lengths of 255
  bytes and more are now decoded as specified.
- Values kept their padding spaces and zero bytes.
- The field read as `suffix` is the first letter of the third given name.
- pyscard exceptions leaked out of the library; they are now wrapped.
- Closing the connection powered the card down for other applications.
- Negative reader indexes silently selected the last reader.

### Changed

- Commands run inside PC/SC transactions; the connection recovers when
  another application resets the card.
- Files are read in 252-byte blocks, like the official middleware.
- Requires Python 3.11 or later and pyscard 2.0.8 or later.
- Unknown month names raise `CardDataError` instead of defaulting to January.

### Deprecated

- `CardReader.read_informations()` (use `read()`), `reader_index` (pass the
  index as `reader`), `parse_tlv()` (use `decode_tlv()`),
  `parse_french_date()` (use `parse_birth_date()`). They keep their 0.x
  output and will be removed in 2.0.

## [0.3.0] - 2026-06-10

### Added

- `list_readers()` public function.
- Publication to PyPI with Trusted Publishing on version tags.

## [0.2.0] - 2026-03-03

### Changed

- Package restructured (`card_reader`, `parser`, `exceptions`), English
  dictionary keys, context manager, dedicated exceptions, `pyproject.toml`,
  test suite.

## [0.1.1] - 2024-06-22

### Fixed

- Packaging metadata.

## [0.1.0] - 2024-06-22

### Added

- First release on PyPI: identity, address and photo reading.

[1.0.2]: https://github.com/Lapin-Blanc/pythonbeid/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Lapin-Blanc/pythonbeid/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Lapin-Blanc/pythonbeid/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/Lapin-Blanc/pythonbeid/releases/tag/v0.3.0
[0.2.0]: https://pypi.org/project/pythonbeid/0.2.0/
[0.1.1]: https://pypi.org/project/pythonbeid/0.1.1/
[0.1.0]: https://pypi.org/project/pythonbeid/0.1.0/
