# Release notes

All notable changes to this project are documented in this file.

## [0.4.0] - 30 Sep 2026

Certificate requests can carry **composite ML-DSA keys**, which pair an ML-DSA key with a classical key in one certificate.

### Protocol

* **Composite ML-DSA certificate requests** are accepted for every composite algorithm from draft-ietf-lamps-pq-composite-sigs-19 that go-composite-mldsa supports. The server checks both component signatures of the request. Account keys stay classical, so revoke these certificates through an authorized account. Tested with Certbot 5.8.0 and the Go crypto/acme client.

### Host integration

* **`IssueRequest.CSR.PublicKey` is nil for a composite key** because `crypto/x509` cannot parse it. Read the key with `compositex509.ParsePKIXPublicKey` from `CSR.RawSubjectPublicKeyInfo` and certify it with `compositex509.CreateCertificate`.

## [0.3.0] - 29 Sep 2026

Hosts can issue from a **composite ML-DSA CA**, whose certificates carry an ML-DSA signature and a classical signature together.

### Host integration

* **Composite ML-DSA issuer chains** are accepted when the host CA signs with a composite ML-DSA key from draft-ietf-lamps-pq-composite-sigs-19. The server checks every composite signature in the returned chain before it publishes the certificate. Certificate requests with composite keys are not accepted. Tested with lego v4.35.2 and the Go crypto/acme client v0.57.0.

## [0.2.0] - 27 Sep 2026

Hosts can issue certificates for **post-quantum ML-DSA public keys** while retaining classical ACME account authentication.

### Protocol

* **ML-DSA certificate requests** support **post-quantum** ML-DSA-44, ML-DSA-65 and ML-DSA-87. The host CA supplies compatible issuance. Account keys remain classical and ML-DSA certificates use account-authorized revocation.

### Host integration

* **Go 1.27.1 or newer** is required for standard-library ML-DSA certificate support.
* **Runnable quickstart** in `examples/quickstart` accompanies the setup guide.

## [0.1.0] - 6 Sep 2026

The first release of **go-acme-server**, a Go library for embedding an ACME server into a CA or PKI application.

The library implements the ACME protocol of RFC 8555. The host application supplies storage, the CA and the challenge validators through Go interfaces. Bundled validators cover HTTP-01, DNS-01, TLS-ALPN-01 and the Authority Token challenge. IP identifiers, TNAuthList identifiers and RFC 9773 renewal information are enabled by configuration.

This release was tested with **acmez v3.1.6**, **Certbot 5.8.0**, **lego v4.35.2**, the Go **crypto/acme** client v0.56.0 and **cert-manager v1.21.1**.

Step-by-step guides for hosts are at [misiektoja.github.io/go-acme-server](https://misiektoja.github.io/go-acme-server/). The API may change before v1.0.0 as the [Compatibility policy](https://misiektoja.github.io/go-acme-server/reference/compatibility/) describes.

### Protocol

* **Complete RFC 8555 flow** - Accounts with external account binding, key rollover and deactivation, orders, authorizations, challenges, finalization, certificate download and revocation by the account, the certificate key or another authorized account. Processing orders and challenges carry a Retry-After header.
* **Three network challenges** - The HTTP-01, DNS-01 and TLS-ALPN-01 validators resolve names through an explicitly configured resolver, refuse private and special-purpose destinations unless the host allows them and bound every response they read. An incorrect proof is final and a transport failure is retried.
* **IP identifiers** - RFC 8738 IPv4 and IPv6 identifiers are validated through HTTP-01 and TLS-ALPN-01 when `Config.IPIdentifiers` is set.
* **Authority Token challenges** - RFC 9447 `tkauth-01` with RFC 9448 TNAuthList identifiers when `Config.TNAuthListIdentifiers` is set. The host names the trusted Token Authorities. A token can authorize a CA certificate and its expiry bounds the certificate validity.
* **Renewal information** - RFC 9773 behind `Config.RenewalInfo`. Clients fetch a suggested renewal window per certificate and name the certificate they replace on a new order. A second order for the same certificate is refused with `alreadyReplaced`. `LifetimeRenewal` is the built-in schedule.

### Host integration

* **Bring your own storage and CA** - `Store`, `Issuer`, `Revoker` and `Validator` are the host interfaces. An in-memory store and a store contract test suite are included. Issuers and revokers receive a durable operation ID so retries are deduplicated.
* **Issuance survives restarts** - The dispatch decision is stored before the CA is called. A worker that dies after the CA issued recovers the same certificate. Chains that fail publication checks are kept for host reconciliation instead of being served.
* **Policy hooks** - Review new accounts, new orders and the first issuance dispatch. Directory metadata, terms of service and single-use external account keys are configuration.

### Verification

* **Independent clients** - acmez, Certbot, lego, crypto/acme and go-jose issue, revoke and replace certificates against the server over HTTPS in `make test-interop`. cert-manager issues and renews in a kind cluster in a weekly job.
* **Fuzzed parsers** - JWS, JWK, JSON, identifier, DNS response and TLS-ALPN proof parsing have bounded fuzz targets that CI runs.

### Known limitations

* **No pre-authorization or authorization reuse** - The directory omits `newAuthz` and every order validates each identifier again.
* **No alternate chains** - One chain per certificate and no `rel="alternate"` link.
* **No rate limits, TLS termination or CA** - The host serves the handler behind its HTTPS origin, signs with its own CA and supplies durable storage. `memstore` is for tests and examples.
* **Drafts are not exposed** - Certificate profiles, `dns-account-01`, short-term automatic renewal, delegation, subdomain authorizations and email, onion or device identifiers are not implemented.
