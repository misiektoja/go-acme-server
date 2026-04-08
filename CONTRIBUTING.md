# Contributing

go-acme-server is a Go library for embedding an ACME server into CA and PKI applications. Bug reports, interoperability results and code contributions are welcome.

## Before contributing

Contribute only code you have the right to license under Apache-2.0. Do not copy code from another ACME implementation without checking its license and naming the source in the pull request. Other implementations may inform protocol behavior, but the code here is written independently.

Never commit credentials, private keys, account keys, external account binding secrets, full CSRs or non-public PKI documentation. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the formatting, vet, lint, test and supply chain checks.

## Development checks

Run these before submitting a change:

```bash
make lint
make test
make test-interop
```

`make test` runs `go vet` and the tests under the race detector. `make lint` runs golangci-lint at the version CI uses, installed under `bin/`. Run `make actionlint` when a workflow changes and `make govulncheck` when a dependency changes. `make help` lists every target.

Run `make fuzz` when parsing code changes. It fuzzes the JWS, JWK, JSON, identifier, DNS response and TLS-ALPN proof parsers for `FUZZ_TIME` each, 20 seconds by default. CI runs a shorter pass. Go writes a failing input under the package's `testdata/fuzz` directory. Commit that input with the fix so it stays a regression test.

Test artifacts default to `.cache/acme-tests`. Set `ACME_TEST_SCRATCH` to an absolute path to use
another directory. Generated keys, databases and client logs must not be committed or uploaded.
Install the pinned Certbot environment as described in [the interoperability guide](test/interop/README.md)
before running `make test-interop`. That gate requires both independent clients and the SQLite process
tests. `make lint` and `make tidy-check` check both Go modules.

Every target runs with the Go toolchain named in `go.mod`, which is downloaded on first use when the installed Go differs.

Protocol changes need negative tests and an RFC citation. Interoperability claims need sanitized evidence naming the client and its version.

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes plus two-space indentation for YAML and TOML. Markdown keeps meaningful trailing spaces and `LICENSE` remains verbatim. Most editors apply these settings automatically, while a few need a plugin.
