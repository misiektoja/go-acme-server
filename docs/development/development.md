# Development

How to build, check and change the library. Contribution rules are in
[CONTRIBUTING.md](https://github.com/misiektoja/go-acme-server/blob/main/CONTRIBUTING.md).

## Prerequisites

* Go at the version `go.mod` declares. Every Make target runs with exactly that toolchain, which Go downloads on first use when the installed version differs.
* Python 3 with the pinned MkDocs dependencies for the documentation site, installed by `make docs-deps`.
* Python 3.14 for the Certbot environment of the interoperability tests. See [Testing](testing.md).
* Docker, kind and kubectl only for the cert-manager scenario.

Linters and other tools are downloaded into `bin/` at pinned versions by the Make targets that
need them.

## Repository layout

| Path | Content |
| --- | --- |
| root package `acmeserver` | The protocol: request verification, resources, worker, issuance and revocation |
| `challenge/` | HTTP-01, DNS-01, TLS-ALPN-01 and tkauth-01 validators with the resolver and egress policy |
| `memstore/` | The in-memory store for tests and examples |
| `nonce/` | The single-process nonce manager |
| `storetest/` | The store contract suite |
| `internal/jws/` | JWS, JWK and strict JSON parsing, not part of the public API |
| `test/interop/` | A separate module with the independent client tests, the SQLite adapter and the cert-manager harness |
| `docs/` | This site |

## Common commands

```bash
make test           # go vet and the tests under the race detector
make lint           # golangci-lint over both modules
make actionlint     # lint the GitHub Actions workflows
make fuzz           # fuzz every parser for FUZZ_TIME each, 20s by default
make test-interop   # the independent client gate, needs the Certbot environment
make test-recovery  # two-process fencing and recovery without Certbot
make docs-build     # strict MkDocs build
make help           # every target
```

`make lint-fix` applies the fixes golangci-lint offers. `make tidy-check` fails when either
module's `go.mod` or `go.sum` is not tidy. `make govulncheck` reports known vulnerabilities that
reach the code and `make gitleaks` scans the tree and history for credentials.

## Documentation

The site is built with MkDocs and the Material theme from `docs/` and `mkdocs.yml`. Set `PYTHON`
when the MkDocs toolchain lives in a virtual environment:

```bash
make docs-deps PYTHON=.venv/bin/python
make docs-serve PYTHON=.venv/bin/python
```

`make docs-build` runs with `--strict`, so a broken link, a missing anchor or a page absent from
the navigation fails the build. CI runs the same build on every change to the documentation and
publishes the site from the default branch.

Package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-acme-server)
comes from the Go doc comments. Every exported identifier and every configuration field has one.
User-facing behavior changes belong in both places: the doc comment for the API and the relevant
page here for the walkthrough.

## Test artifacts

Tests write generated keys, databases and client logs under `.cache/acme-tests` by default. Set
`ACME_TEST_SCRATCH` to an absolute path to use another directory. These files must never be
committed or uploaded.

## Code style

`.editorconfig` records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing
whitespace, tabs for Go and Make recipes and two-space indentation for YAML and TOML. `gofmt` and
golangci-lint enforce the rest. Every exported identifier carries a doc comment. Protocol
decisions cite the RFC section they implement.

Protocol changes need negative tests and an RFC citation. Interoperability claims need sanitized
evidence naming the client and its version.
