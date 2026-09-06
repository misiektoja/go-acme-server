# Changelog

## Unreleased (TBD)

Embed an ACME server with network and Authority Token challenge validation and recoverable issuance
through a host CA.

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
* **`make test-interop`** requires acmez issuance through HTTP-01, DNS-01 with a wildcard and its
  base domain, TLS-ALPN-01 and an IP identifier, Certbot HTTP-01 and manual-hook DNS-01 wildcard issuance with
  revocation, lego HTTP-01 issuance with revocation, DNS-01 wildcard and TLS-ALPN-01 issuance,
  renewal information and certificate replacement through acmez and lego, delayed issuance
  through Certbot and lego, Go crypto/acme account changes, issuance, key-signed revocation and
  deactivation, tkauth-01 issuance with a local Token Authority, incorrect-proof rejection for
  every challenge type, go-jose signed account, key change and external account binding requests,
  retried and concurrent registrations, challenge responses, finalizations, key changes and nonce
  use, two workers sharing one store and SQLite process recovery, all over trusted HTTPS. Test artifacts use a configurable output directory. The SQLite adapter is test
  infrastructure.
* **`make test-cert-manager`** issues and renews a certificate through cert-manager 1.21.1 in a
  throwaway kind cluster against a small server built from the library. CI runs it weekly and on
  request.
* **`make fuzz`** runs bounded fuzz targets for JWS, compact JWS, JWK, JSON, identifier, DNS response
  and TLS-ALPN proof parsing. `FUZZ_TIME` sets the budget per target. CI runs a short pass.
