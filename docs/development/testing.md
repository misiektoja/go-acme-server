# Testing

The library is tested at three levels: unit tests in each package, fuzz targets over every parser
and independent ACME clients in a separate module. This page explains how to run each level and
what it proves.

## Unit tests

```bash
make test
```

Runs `go vet` and every test under the race detector with coverage written to the scratch
directory. The root package tests drive complete flows through the handler with `memstore`, a test
CA and test validators, including account, order, renewal, revocation, timeout, recovery and
`tkauth-01` scenarios. The `challenge` tests check proof and egress rules against local servers.
`memstore` runs the `storetest` suite.

## Fuzzing

```bash
make fuzz
make fuzz FUZZ_TIME=2m
```

Fuzzes the JWS, JWK, strict JSON, identifier, DNS response and TLS-ALPN proof parsers for
`FUZZ_TIME` each. CI runs a shorter pass on every push. Go writes a failing input under the
package's `testdata/fuzz` directory. Commit that input with the fix so it stays a regression test.

## Interoperability

```bash
make test-interop
```

Runs acmez, Certbot, lego, the Go `crypto/acme` client and a raw go-jose client against the server
over HTTPS with the SQLite store, plus the concurrency and two-process recovery tests. Missing
tools, failed tests and skipped required scenarios fail the gate. The clients, versions and
scenarios are listed on [Tested clients](../interoperability/tested-clients.md).

Certbot runs from a pinned Python environment. Install Python 3.14, then:

```bash
python3 -m venv .cache/certbot
.cache/certbot/bin/python -m pip install --no-deps --only-binary=:all: --require-hashes -r test/interop/requirements.txt
.cache/certbot/bin/python -m pip check
ACME_CERTBOT="$PWD/.cache/certbot/bin/certbot" make test-interop
```

`ACME_CERTBOT` selects the executable and its version must match the pin. The Go clients run in
process and need no installation. `make test-recovery` runs the process recovery and fencing tests
alone, without Certbot.

`test/interop/README.md` describes every scenario, the SQLite adapter and the evidence the gate
writes.

## The cert-manager scenario

```bash
make test-cert-manager
```

Starts a kind cluster, deploys the server from `test/interop/cmd/server` with the test CA and an
HTTP-01 validator, issues and renews a certificate through a cert-manager `ClusterIssuer` and
verifies both against the test root. It needs Docker, kind, kubectl and openssl. The cluster is
deleted afterwards unless `ACME_KEEP_CLUSTER=1` is set. CI runs it weekly and on request.

## Testing your integration

The pieces you implement have their own verification paths:

| Your code | Verify with |
| --- | --- |
| `Store` | `storetest.Run` in your test suite, plus a crash test between `BeginIssuance` and `CompleteIssuance` |
| `Issuer` and `Revoker` | A test that calls `Issue` or `Revoke` twice with one `OperationID` and expects one CA action |
| `Validator` | The same table-driven tests the `challenge` package uses against a local target |
| The whole host | An ACME client against a staging deployment, as in [Getting started](../getting-started.md) |

`acmeserver.ClockFunc` replaces the clock in tests, which makes expiry and retry timing
deterministic. `Config.AllowInsecureBaseURL` and the validators' `TestPort` options exist for
tests that cannot bind privileged ports or terminate TLS.

## Evidence

The interoperability gate writes `interop-summary.json` into the scratch directory with the Go
version, operating system, architecture, test names, outcomes and elapsed times. Nothing else.
CI uploads only that summary. Keys, databases and client logs stay local.
