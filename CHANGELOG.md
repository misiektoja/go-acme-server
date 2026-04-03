# Changelog

## Unreleased (TBD)

Embed an ACME server with network challenge validation and recoverable issuance through a host CA.

### Features

* **ACME resources** support accounts, external account binding, key rollover, orders, authorizations,
  finalization, certificate retrieval and revocation through replaceable host interfaces.
* **HTTP-01, DNS-01 and TLS-ALPN-01** validators use explicit resolvers, bounded network work and
  public-destination egress by default. Private networks require explicit exceptions. HTTP and TLS
  destination port overrides are for tests only.
* **Issuance recovery** preserves a durable dispatch decision and retains unpublished CA results for
  host reconciliation. Host issuers must deduplicate operations and enforce authorization deadlines.
* **`make test-interop`** requires acmez and Certbot HTTP-01 issuance over trusted HTTPS, incorrect-proof
  rejection and SQLite process recovery. Test artifacts use a configurable output directory.
  The SQLite adapter is test infrastructure.
