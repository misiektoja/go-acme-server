# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Report it privately through [GitHub security advisories](https://github.com/misiektoja/go-acme-server/security/advisories/new), which keeps the report visible only to the maintainer until an advisory is published. If you cannot use that, email <misiektoja-github@rm-rf.ninja>.

Do not include private keys, account keys, external account binding secrets, full CSRs or production endpoint details in a report. Include the affected revision, the impact, the preconditions to reproduce it and a sanitized proof when you have one.

The maintainer will acknowledge the report and coordinate disclosure once a fix is available.

## Supported versions

Security fixes are made on the default branch and shipped in the next [GitHub release](https://github.com/misiektoja/go-acme-server/releases). Only the latest released version is supported. Earlier versions receive no backports.
