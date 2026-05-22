# Changelog

## Unreleased (TBD)

Embed an ACME server with network challenge validation and recoverable issuance through a host CA.

### Features

* **ACME resources** support accounts, external account binding, key rollover, orders, authorizations,
  finalization, certificate retrieval and revocation through replaceable host interfaces.
  Processing orders and challenges carry a Retry-After header. `SingleUseExternalAccounts` binds
  each external account key identifier to one account.
* **HTTP-01, DNS-01 and TLS-ALPN-01** validators use explicit resolvers, bounded network work and
  public-destination egress by default. Private networks require explicit exceptions. HTTP and TLS
  destination port overrides are for tests only.
* **Issuance recovery** preserves a durable dispatch decision and retains unpublished CA results for
  host reconciliation. Host issuers must deduplicate operations and enforce authorization deadlines.
  Revocations carry a durable operation ID that retries repeat, so revokers deduplicate the same way.
* **`make test-interop`** requires acmez issuance through HTTP-01, DNS-01 with a wildcard and its
  base domain, and TLS-ALPN-01, Certbot HTTP-01 and manual-hook DNS-01 wildcard issuance with
  revocation, lego HTTP-01 issuance with revocation and DNS-01 wildcard issuance, incorrect-proof
  rejection for every challenge type, go-jose signed account, key change and external account
  binding requests, retried and concurrent registrations, challenge responses, finalizations, key
  changes and nonce use, two workers sharing one store and SQLite process recovery, all over
  trusted HTTPS. Test artifacts use a configurable output directory. The SQLite adapter is test
  infrastructure.
* **`make fuzz`** runs bounded fuzz targets for JWS, JWK, JSON, identifier, DNS response and
  TLS-ALPN proof parsing. `FUZZ_TIME` sets the budget per target. CI runs a short pass.
