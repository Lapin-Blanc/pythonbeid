# pythonbeid

[![PyPI](https://img.shields.io/pypi/v/pythonbeid)](https://pypi.org/project/pythonbeid/)
[![Python](https://img.shields.io/pypi/pyversions/pythonbeid)](https://pypi.org/project/pythonbeid/)
[![CI](https://github.com/Lapin-Blanc/pythonbeid/actions/workflows/ci.yml/badge.svg)](https://github.com/Lapin-Blanc/pythonbeid/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/pypi/l/pythonbeid)](LICENSE)

Read and verify **Belgian electronic identity cards** (eID, Kids-ID, residence
cards for foreign nationals) from Python, with any PC/SC smart card reader.

```python
from pythonbeid import CardReader

with CardReader() as reader:
    eid = reader.read()
    print(eid.identity.last_name, eid.identity.birth_date)
    print(eid.address.street, eid.address.postal_code, eid.address.municipality)
```

## Features

- **Complete card content**: every field of the identity and address files
  (applet 1.7 and 1.8 layouts), the photo, chip information and certificates.
- **Correct in every language**: birth dates written in French, Dutch or
  German, incomplete birth dates, `M`/`F`/`V`/`W` sex letters, document types
  and special statuses.
- **Authenticity checks**: photo digest, National Register signatures of the
  identity and address files, certificate chain up to the Belgian root CAs and,
  on applet 1.8 cards, the chip challenge that detects cloned data.
- **Robust transport**: follows the official middleware (block size, `6Cxx`,
  `61xx`, end of file), runs inside PC/SC transactions so other applications
  cannot interfere, recovers when another application resets the card, and
  leaves the card powered for them.
- **Typed API**: immutable dataclasses, enums and `datetime.date`, shipped
  with `py.typed`; strict mypy clean.
- **Command line**: `pythonbeid read`, `pythonbeid verify`...
- No PIN is ever sent: only public card content is read.

## Installation

```bash
pip install pythonbeid             # reading
pip install "pythonbeid[verify]"   # reading + signature verification
```

Requirements: Python 3.11 or later and a PC/SC reader.

- **Windows, macOS**: nothing else to install.
- **Linux**: the PC/SC daemon must run, and [pyscard](https://pypi.org/project/pyscard/)
  is compiled at install time:

  ```bash
  sudo apt install pcscd libpcsclite-dev   # Debian, Ubuntu, Mint, MX Linux...
  ```

## Reading a card

`CardReader()` picks the first reader that holds a Belgian eID card. You can
also choose the reader and wait for the card to be inserted:

```python
from pythonbeid import CardReader, list_readers

print(list_readers())                      # ['ACS ACR38U 0', ...]

with CardReader("ACR38U", timeout=30) as reader:   # index, name or part of it
    identity = reader.read_identity()
    address = reader.read_address()
    photo = reader.read_photo()            # JPEG bytes
    print(reader.card_info.applet_version_string)  # "1.7" or "1.8"
```

`reader.read()` reads everything in a single transaction and returns an
`EidData` object (`card`, `identity`, `address`, `photo`, raw `files`). Pass
`photo=False` or `integrity=False` to skip the photo or the files used by the
verification. All models offer `to_dict()` for JSON serialisation.

Reading speed depends on the reader: `read()` takes about 9 s on an old
9600-baud ACS ACR38U and proportionally less on faster readers. The photo
(3 KB) is the largest file; skip it when you do not need it.

### Identity fields

| Field | Type | Notes |
|---|---|---|
| `card_number`, `chip_number` | `str` | chip number in hexadecimal |
| `validity_start`, `validity_end` | `date` | `is_valid_on(day)` helper |
| `issuing_municipality` | `str` | |
| `national_number` | `str` | `national_number_valid` checks the modulo-97 checksum |
| `last_name` | `str` | |
| `first_names` | `str` | the first two given names only |
| `third_given_name_initial` | `str` | `given_names` joins both |
| `nationality`, `birth_place` | `str` | in the language of the card |
| `birth_date` | `PartialDate \| None` | `.to_date()`; year or month may be unknown; `None` for an unknown format (raw value in `raw[0x0C]`) |
| `sex` | `Sex \| None` | `Sex.MALE` / `Sex.FEMALE` |
| `noble_condition` | `str` | |
| `document_type` | `DocumentType \| None` | `.description`, `.is_kids_card`, `.is_foreigner_card` |
| `special_status` | `SpecialStatus` | `.white_cane`, `.yellow_cane`, `.extended_minority` |
| `photo_hash`, `basic_key_hash` | `bytes` | used by the verification |
| foreign nationals | | `duplicate`, `special_organization`, `member_of_family`, `date_and_country_of_protection`, `work_permit`, `employer_vat_1/2`, `regional_file_number`, `brexit_mention_1/2`, `card_a_mention_1/2`, `eu_registration_date` |
| `raw` | `Mapping[int, bytes]` | every TLV record, for future tags |

The address has `street` (street and house number), `postal_code` and
`municipality`.

## Verifying authenticity

Requires the `verify` extra.

```python
with CardReader() as reader:
    report = reader.verify()
    print(report.is_valid)
    for error in report.errors:
        print(error)
```

| Check | Meaning |
|---|---|
| `photo_hash_valid` | the photo matches the digest in the identity file |
| `identity_signature_valid` | the identity file is signed by the National Register (RRN) |
| `address_signature_valid` | the address file is signed by the RRN (and bound to the identity signature) |
| `rrn_certificate_trusted` | the RRN certificate is an end-entity signing certificate issued by a bundled Belgian root CA |
| `rrn_certificate_period_valid` | the RRN certificate validity overlaps the card validity |
| `content_matches_files` | the decoded identity, address and photo are those of the signed files |
| `basic_key_valid` | applet 1.8: the chip public key is the one signed by the RRN |
| `chip_authenticated` | applet 1.8: the chip signed a random challenge with its private key |

A check that does not apply is `None`. The RRN certificate is not required to
be valid today: certificates of valid cards may have expired since, and cards
re-signed after issuance carry a newer one. Whether a card has a basic key is
decided by the signed identity file, never by the unsigned chip information,
so a clone cannot avoid the chip challenge by claiming an older applet.

Raw files can be checked offline, for instance on a server receiving them
from a client:

```python
from pythonbeid import EidData, verify_eid

eid = EidData.from_files(files)        # {CardFile: bytes}
report = verify_eid(eid)               # everything is checked on the raw files
```

The chip challenge needs the live card: `reader.authenticate_chip(identity)`
checks the chip against an identity file whose signature you verified.

Bundled trust anchors, downloaded from `certs.eid.belgium.be` and
`crt.eidpki.belgium.be` (SHA-256):

| Root | Fingerprint |
|---|---|
| Belgium Root CA2 | `9f9744463be13714754e1a3becf98c08cc205e4ab32028f4e2830c4a1b2775b8` |
| Belgium Root CA3 | `a8d14e945e3e5156bcae5e39737cf6a1b1f51028bbbf982f50ce5f4c05568b4d` |
| Belgium Root CA4 | `702dd5c1a093cf0a9d71fadd9bf9a7c5857d89fb73b716e867228b3c2beb968f` |
| Belgium Root CA6 | `9c872bc979a7c09a58d4a274c199e5cb16cfa9b9618d98bc9a9988e984b8495c` |

Pass `trusted_roots=[...]` (PEM or DER) to use your own.

## Command line

```console
$ pythonbeid readers
0: ACS ACR38U 0
$ pythonbeid info              # reader, ATR, applet version
$ pythonbeid read --json       # identity and address
$ pythonbeid read --photo me.jpg
$ pythonbeid verify            # exit status 3 when a check fails
```

`python -m pythonbeid` works too. Options: `--reader`, `--timeout`, `--json`,
`-v` / `-vv` (APDU trace, without card data).

## Errors

All exceptions derive from `pythonbeid.BeidError`:

| Exception | Raised when |
|---|---|
| `NoReaderError` | no reader, or none matches the requested one |
| `PCSCServiceError` | the PC/SC service is not running (subclass of `NoReaderError`) |
| `NoCardError` | no card in the reader, or the card was removed |
| `UnsupportedCardError` | the card is not a Belgian eID card, or lacks a feature |
| `CardInUseError` | another application holds the card exclusively (subclass of `CardCommunicationError`) |
| `CardCommunicationError` | transport failure |
| `APDUError` | the card refused a command (`.sw` holds the status word) |
| `CardDataError` | card content cannot be decoded (also a `ValueError`) |

## Troubleshooting

**`CardInUseError`: the card is used exclusively by another application.**
The usual culprit on developer machines is GnuPG's `scdaemon` (shipped with
Git for Windows and GPG suites): it grabs PC/SC readers exclusively as soon
as any program asks GnuPG about smart cards, and it is restarted on demand.

- Free the card now: `gpgconf --kill scdaemon`.
- Fix it for good: add `pcsc-shared` to `scdaemon.conf`, or `disable-scdaemon`
  to `gpg-agent.conf` if you do not use OpenPGP cards, in the GnuPG home
  directory (`gpgconf --list-dirs homedir`), then run
  `gpgconf --kill scdaemon`.

The eID middleware may also hold the card while a browser authenticates.

**`PCSCServiceError` on Linux**: start the PC/SC daemon with
`sudo systemctl enable --now pcscd`.

**`NoCardError` although a card is inserted**: check the card orientation and
run `pythonbeid readers`; with several readers, pass `--reader`.

## Migrating from 0.x

The 0.x API still works and emits a `DeprecationWarning`:

| 0.x | 1.0 |
|---|---|
| `cr.read_informations(photo=True)` | `reader.read()` returning typed `EidData` |
| `CardReader(reader_index=1)` | `CardReader(1)` or `CardReader("name")` |
| `info["birth_date"]` (`datetime`) | `identity.birth_date` (`PartialDate`) |
| `info["suffix"]` | `identity.third_given_name_initial` |
| `info["address"]`, `info["city"]` | `address.street`, `address.municipality` |
| `info["photo"]` (base-64 `str`) | `eid.photo` (`bytes`) |
| `parse_tlv`, `parse_french_date` | `decode_tlv`, `parse_birth_date` |

Behaviour fixes that may be visible: birth dates written in Dutch or German
are now parsed correctly (0.x silently returned January for most months, and
failed on German cards); values are stripped of padding spaces; unknown month
names raise instead of defaulting to January.

## Compatibility

- Applet 1.7 cards (RSA keys): validated on real cards.
- Applet 1.8 cards (elliptic-curve keys, current generation): implemented
  after the official specification and middleware, and covered by simulated
  tests. Reports from 1.8 card holders are welcome (see the issue template;
  never share personal data).
- Python 3.11 to 3.15 on Windows, macOS and Linux.

## Privacy

Card content is personal data (GDPR). pythonbeid never logs it: debug logs
only contain command headers, status words and lengths. Ask for consent and
keep only what you need.

## Development

```bash
git clone https://github.com/Lapin-Blanc/pythonbeid && cd pythonbeid
python -m venv .venv && . .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[dev]" && pre-commit install
pytest                 # simulated card, no hardware needed
pytest --hardware      # also runs the tests on a real card (no data is printed)
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## References

Official documentation, in the
[Fedict/eid-mw](https://github.com/Fedict/eid-mw/tree/master/doc/sdk/documentation)
repository:

- *ID and Address file contents*, applet 1.8, v5.0 (2023)
- *Belgian Electronic Identity Card content*, v5.4
- *Reference manual Belpic V1.8 eID card* and *V1.7*

## License

MIT, see [LICENSE](LICENSE).
