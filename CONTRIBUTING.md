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

## Compatibility

The module uses semantic versioning. The public API is every exported identifier of the root package and of `challenge`, `memstore`, `nonce` and `storetest`. The `internal` packages and the `test/interop` module are not part of it.

Before v1.0.0 a minor release may change the public API. The release notes name every such change and the reason. Patch releases keep the API. These rules apply to every release:

* Structs may gain fields. Construct them with field names and, when a host stores resources as JSON, tolerate fields it does not know.
* Statuses, error types, challenge types, identifier types and task kinds may gain values. Switch statements over them need a default case.
* Interfaces the host implements, such as `Store`, `Issuer`, `Revoker`, `Validator`, `Policy`, `RenewalAdvisor` and `challenge.TokenAuthorities`, may gain methods before v1.0.0. A store change comes with a `storetest` update, so run that suite when upgrading. After v1.0.0 new server capabilities go through optional interfaces that the server detects.
* Wire behavior that clients can observe changes only with a release notes entry and an RFC citation.

## Releasing

A release is started by pushing a version tag that is reachable from `main` and by nothing else. `RELEASE_NOTES.md` carries one section per version and its section becomes the release description.

1. On `dev`, add or complete the `## [X.Y.Z] - D Mon YYYY` section in `RELEASE_NOTES.md` and read it as a user of the library.
2. Run `make lint`, `make test`, `make test-interop` and `VERSION=vX.Y.Z make release-check`. The release check exports `HEAD` with `git archive`, verifies, builds and tests the export and imports it from a separate module, so it catches files that are ignored, untracked or only present locally.
3. Merge `dev` into `main`, create a signed annotated tag such as `git tag -s v0.1.0 -m 'v0.1.0'` and push `main` and the tag.
4. `release.yml` repeats the release check on the tag, builds the source archives, the SBOM and the checksums, attests their provenance and creates a **draft** release with the release notes section as its description. Review the draft and publish it. Never draft a release in the GitHub UI, because that creates the tag and starts the workflow against a release that is already published. The workflow refuses to rebuild a published release.
5. Confirm the module proxy serves the version with `GOPROXY=https://proxy.golang.org GOFLAGS=-mod=mod go list -m github.com/misiektoja/go-acme-server@vX.Y.Z` from a directory outside the repository and check that pkg.go.dev shows the package documentation.

Each release carries the complete source as `go-acme-server-<version>-source.zip` and `.tar.gz`, a CycloneDX SBOM, a SHA-256 checksum manifest and a signed provenance bundle `go-acme-server-<version>.intoto.jsonl`. Verify a file with `gh attestation verify <file> --repo misiektoja/go-acme-server` or offline with `--bundle`.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes plus two-space indentation for YAML and TOML. Markdown keeps meaningful trailing spaces and `LICENSE` remains verbatim. Most editors apply these settings automatically, while a few need a plugin.
