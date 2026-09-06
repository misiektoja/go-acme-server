# Compatibility policy

The module uses semantic versioning. The public API is every exported identifier of the root
package and of `challenge`, `memstore`, `nonce` and `storetest`. The `internal` packages and the
`test/interop` module are not part of it.

## Before v1.0.0

A minor release may change the public API. The release notes name every such change and the
reason. Patch releases keep the API.

## Rules for every release

* **Structs may gain fields.** Construct them with field names and, when a host stores resources as JSON, tolerate fields it does not know.
* **Enumerations may gain values.** Statuses, error types, challenge types, identifier types and task kinds may grow. Switch statements over them need a default case.
* **Host interfaces may gain methods before v1.0.0.** This applies to `Store`, `Issuer`, `Revoker`, `Validator`, `Policy`, `RenewalAdvisor` and `challenge.TokenAuthorities`. A store change comes with a `storetest` update, so run that suite when upgrading. After v1.0.0 new server capabilities go through optional interfaces that the server detects.
* **Wire behavior changes are announced.** Behavior that clients can observe changes only with a release notes entry and an RFC citation.

## Upgrading

1. Read the release notes section for the new version.
2. Run `go get github.com/misiektoja/go-acme-server@vX.Y.Z` and build. A new interface method is a compile error that names what to implement.
3. Run your `storetest` suite.
4. Run your own integration tests against the ACME clients you support. The [tested clients](../interoperability/tested-clients.md) page names the versions each release was verified with.

## Go version

The module declares the minimum Go version in `go.mod`. Every release is built and tested with
exactly that toolchain.
