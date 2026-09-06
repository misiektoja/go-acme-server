# Contributing

go-acme-server is a Go library for embedding an ACME server into CA and PKI applications. Bug reports, interoperability results and code contributions are welcome. Usage questions belong in Discussions, as [SUPPORT.md](SUPPORT.md) describes.

## Before contributing

Contribute only code you have the right to license under Apache-2.0. Do not copy code from another ACME implementation without checking its license and naming the source in the pull request. Other implementations may inform protocol behavior, but the code here is written independently.

Never commit credentials, private keys, account keys, external account binding secrets, full CSRs or non-public PKI documentation. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the formatting, vet, lint, test, documentation and supply chain checks.

## Development checks

Run these before submitting a change:

```bash
make lint
make test
make test-interop
make docs-build
```

`make test` runs `go vet` and the tests under the race detector. `make lint` runs golangci-lint at the version CI uses, installed under `bin/`. `make docs-build` builds the documentation site strictly and needs `make docs-deps` once. Run `make actionlint` when a workflow changes, `make govulncheck` when a dependency changes and `make fuzz` when parsing code changes. `make help` lists every target.

[Development](https://misiektoja.github.io/go-acme-server/development/development/) and [Testing](https://misiektoja.github.io/go-acme-server/development/testing/) describe the repository layout, the test levels, the Certbot environment that `make test-interop` needs and where test artifacts go.

Protocol changes need negative tests and an RFC citation. Interoperability claims need sanitized evidence naming the client and its version. User-facing behavior changes update the Go doc comments and the relevant page under `docs/`.

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Compatibility

The module uses semantic versioning and the public API may change in minor releases before v1.0.0. [Compatibility policy](https://misiektoja.github.io/go-acme-server/reference/compatibility/) states which packages form the public API, what may change and how upgrades are announced.

## Releasing

A release is started by pushing a version tag that is reachable from `main` and by nothing else. [Release process](https://misiektoja.github.io/go-acme-server/development/release-process/) lists the steps, the checks and the artifacts every release carries.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes plus two-space indentation for YAML and TOML. Markdown keeps meaningful trailing spaces and `LICENSE` remains verbatim. Most editors apply these settings automatically, while a few need a plugin.
