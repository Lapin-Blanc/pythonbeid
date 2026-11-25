# Security policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities **privately** through
[GitHub security advisories](https://github.com/Lapin-Blanc/pythonbeid/security/advisories/new),
not in a public issue. You should get an answer within a week.

Never include personal data read from an eID card in a report: synthetic data
or a description of the card structure is enough.

## Scope

pythonbeid reads public card content and never sends a PIN. Issues of
interest include: accepting forged or altered card data as authentic,
leaking card data (logs, exceptions), and trust anchors (bundled root
certificates in `pythonbeid/trust/`).
