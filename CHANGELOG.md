# Changelog

## 0.1.0 (2026-09-06)

First release. Embed an ACME server in a Go CA or PKI application. The library implements
RFC 8555 with TLS-ALPN-01, IP identifiers, Authority Token challenges and renewal information.
The host supplies storage, the CA and the challenge validators.

### Features

* **ACME resources** support accounts, external account binding, key rollover, orders, authorizations,
  finalization, certificate retrieval and revocation through replaceable host interfaces.
  Processing orders and challenges carry a Retry-After header and every order response names the
  order in Location. `SingleUseExternalAccounts` binds
  each external account key identifier to one account.
* **HTTP-01, DNS-01 and TLS-ALPN-01** validators use explicit resolvers, bounded network work and
  public-destination egress by default. Private networks require explicit exceptions. HTTP and TLS
  destination port overrides are for tests only.
* **tkauth-01 and TNAuthList identifiers** implement RFC 9447 and RFC 9448. `TNAuthListIdentifiers`
  accepts orders for one base64url DER TN authorization list, which is offered the Authority Token
  challenge alone. The validator checks the token against the challenge identifier and the account
  key, accepts the `tktype` spelling of either RFC, and asks a host `TokenAuthorities`
  implementation for the signing certificate instead of fetching `x5u`. `Config.TokenAuthority`
  advertises where clients may obtain a token. Every authorization of an order must have granted
  the CA basic constraint the certificate request asks for, so a request for a CA certificate is
  refused unless every challenge granted one. Issued certificates may not outlive the token.
* **Renewal information** implements RFC 9773 behind `Config.RenewalInfo`. The directory
  advertises `renewalInfo`, an unauthenticated GET returns the suggested window with Retry-After
  and `replaces` on a new order claims the predecessor for one live order at a time, answering
  `alreadyReplaced` otherwise. `LifetimeRenewal` is the built-in schedule and hosts can supply
  their own `RenewalAdvisor`. Stores index certificates by their RFC 9773 identifier.
* **Issuance recovery** preserves a durable dispatch decision and retains unpublished CA results for
  host reconciliation. Host issuers must deduplicate operations and enforce authorization deadlines.
  Revocations carry a durable operation ID that retries repeat, so revokers deduplicate the same way.
* **`make test-interop`** runs independent clients against the server over trusted HTTPS.
  acmez, Certbot, lego and the Go crypto/acme client issue through HTTP-01, DNS-01 with a wildcard
  and its base domain, TLS-ALPN-01 and an IP identifier, revoke, replace certificates through
  renewal information and wait out delayed issuance. An incorrect proof of every challenge type is
  rejected. go-jose signs raw requests to check tkauth-01 with a local Token Authority, external
  account binding, key changes and retried or concurrent requests. Two workers share one SQLite
  store and a killed worker is recovered. Test artifacts use a configurable output directory. The
  SQLite adapter is test infrastructure.
* **`make test-cert-manager`** issues and renews a certificate through cert-manager 1.21.1 in a
  throwaway kind cluster against a small server built from the library. CI runs it weekly and on
  request.
* **`make fuzz`** runs bounded fuzz targets for JWS, compact JWS, JWK, JSON, identifier, DNS response
  and TLS-ALPN proof parsing. `FUZZ_TIME` sets the budget per target. CI runs a short pass.
