# Interoperability tests

This separate module tests go-acme-server with acmez v3.1.6, Certbot 5.8.0, lego v4.35.2, the Go
crypto/acme client v0.56.0 and go-jose v4.1.5.
Clients reach the server over HTTPS and trust a generated root explicitly. Tests check the issued
key, exact identifiers, validity, chain and stored resource state. An incorrect proof of any
challenge type must leave the order invalid without any CA issuance.

acmez obtains certificates through HTTP-01, DNS-01 and TLS-ALPN-01. The DNS-01 scenario orders a
wildcard together with its base domain, so two proofs share one TXT owner name in the local TCP DNS
responder. The TLS-ALPN-01 scenario serves the challenge certificates that acmez itself generates
from a local TLS listener. Certbot uses its standalone HTTP-01 solver on an unprivileged port
and its manual plugin for a DNS-01 wildcard with its base domain. The manual hooks are shell
scripts written into the test directory that append and remove TXT values in files the local
responder reads. Certbot then revokes the certificate through its account. lego issues through
its own HTTP-01 server and through DNS-01 for the same wildcard pair with a provider that writes
to the responder directly. It revokes with a reason code and receives `alreadyRevoked` on the
second attempt. The test CA records revocations by operation ID so each test confirms one CA call.
Certbot and lego also issue while the test CA answers Pending for two seconds, so both wait out a
processing order without ordering again.

The Go crypto/acme client updates its contact, rolls its key over, issues through HTTP-01, revokes
with the certificate key and a reason code, and deactivates the account. Its repeated revocation
reports success because the client treats `alreadyRevoked` as done, so the stored state is checked
instead.

A raw go-jose client covers tkauth-01, which no independent client speaks. It orders a TNAuthList
identifier, answers with an Authority Token from a local Token Authority the harness trusts,
finalizes a CSR that carries the TN authorization list and checks that the token expiry bounds the
certificate. A token issued to another account key leaves the order invalid without issuance.

go-jose signs requests independently of the server's JWS code. The cross-check creates accounts
with every advertised algorithm, compares stored RFC 7638 thumbprints with go-jose, changes keys
through an inner JWS, binds an external account with HS256 and confirms that refused signatures
return the expected problem types, including a fresh nonce on every refusal. The harness enables
single-use bindings, so a retry with the same key returns the bound account and another key
cannot reuse the identifier.

A raw go-jose client also repeats and races requests the way clients do after a lost response.
Registering one key again or from several connections at once yields one account. Repeated
and concurrent challenge responses validate once and repeated finalizations with the same CSR
issue once, while a different CSR is refused before and after issuance. Competing CSRs, racing
key changes and one nonce used from several connections each succeed exactly once. Four
authorizations of one order complete concurrently and two workers share one SQLite store
without processing any task twice.

The SQLite adapter uses modernc.org/sqlite v1.58.0 with WAL, `synchronous=FULL`, foreign keys,
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
and skipped required scenarios fail the gate. The DNS, TLS and go-jose scenarios need no extra
tools. lego runs in process and reads no host resolver because CNAME discovery is disabled.
`make test-recovery` runs process recovery and fencing without needing Certbot. `make lint`
and `make tidy-check` cover both modules.

`go.mod` and `go.sum` pin the Go dependencies. `requirements.txt` pins every Certbot dependency.
CI uses Python 3.14.7 and the Go version from the root `go.mod`. Refresh these pins together and
rerun the required scenarios when updating a client.

## Evidence

Test databases, generated keys and client logs remain under `.cache/acme-tests` by default.
Set `ACME_TEST_SCRATCH` to an absolute path to retain artifacts elsewhere. Do not commit or upload
these files. The gate prints diagnostics and writes `interop-summary.json` in that directory with
only Go version, operating system, architecture, test names, outcomes and elapsed times. CI uses
its temporary directory and uploads only the summary, including after failure.

These tests establish the named acmez, Certbot, lego, crypto/acme, go-jose, tkauth-01, concurrency
and recovery scenarios. Local validator tests separately check RFC 8555, RFC 8737, RFC 8738 and
RFC 9448 proof and egress rules. They do not establish complete RFC conformance, alternate chain
selection or cert-manager behavior.
