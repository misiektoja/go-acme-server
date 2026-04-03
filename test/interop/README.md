# Interoperability tests

This separate module tests go-acme-server with acmez v3.1.6 and Certbot 5.4.0. Both obtain a
certificate over HTTPS using HTTP-01 on an unprivileged loopback port. Clients trust a generated
root explicitly. Tests check the issued key, exact identifiers, validity, chain and stored resource
state. An incorrect acmez proof must fail before any CA issuance.

The SQLite adapter uses modernc.org/sqlite v1.48.1 with WAL, `synchronous=FULL`, foreign keys,
a five-second busy timeout and `BEGIN IMMEDIATE` writes. It is test infrastructure with no schema
migration or production support contract. SQLite lock conflicts return `ErrRevisionMismatch` so
the caller can retry the atomic operation. Unique IDs and account keys return `ErrConflict`.

Two live processes exercise lease exclusion and fencing. Another test keeps the HTTP process
running while killing a worker after the test CA commits issuance but before ACME publication.
A new worker recovers identical DER with one issuance across two CA calls.

## Run locally

Run from the repository root. Install Python 3.14 and create an isolated client environment:

```bash
python3 -m venv .cache/certbot
.cache/certbot/bin/python -m pip install --no-deps --only-binary=:all: -r test/interop/requirements.txt
.cache/certbot/bin/python -m pip check
ACME_CERTBOT="$PWD/.cache/certbot/bin/certbot" make test-interop
```

`ACME_CERTBOT` selects the executable. Its version must match the pin. Missing tools, failed tests
and skipped required scenarios fail the gate. `make test-recovery` runs process recovery and fencing
without needing Certbot. `make lint` and `make tidy-check` cover both modules.

`go.mod` and `go.sum` pin the Go dependencies. `requirements.txt` pins every Certbot dependency.
CI uses Python 3.14.3 and the Go version from the root `go.mod`. Refresh these pins together and
rerun the required scenarios when updating a client.

## Evidence

Test databases, generated keys and client logs remain under `.cache/acme-tests` by default.
Set `ACME_TEST_SCRATCH` to an absolute path to retain artifacts elsewhere. Do not commit or upload
these files. The gate prints diagnostics and writes `interop-summary.json` in that directory with
only Go version, operating system, architecture, test names, outcomes and elapsed times. CI uses
its temporary directory and uploads only the summary, including after failure.

These tests establish the named HTTP-01 interoperability and recovery scenarios. Local validator
tests separately check RFC 8555, RFC 8737 and RFC 8738 proof and egress rules. They do not establish
complete RFC conformance or the broader client and challenge matrix.
