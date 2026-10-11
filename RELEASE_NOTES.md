# Release notes

All notable changes to this project are documented in this file.

## [0.5.0] - TBD

This version fixes stalled challenges, revocation retries, unrecorded challenge responses, DNS failover and issuance after authority-token expiry. It tightens JSON and worker lease checks, updates composite ML-DSA support and makes the cert-manager runner refuse existing clusters. Stores must record why an authorization change invalidated its order.

### Protocol

* **Challenge responses that the store did not record** are answered with `serverInternal` and logged as `challenge update failed`. Previously the client received the unchanged pending challenge with status 200 while no validation ran.
* **A challenge whose authorization moved on during validation** becomes `invalid` with `authorization was <status> before validation` (RFC 8555 section 7.1.6). This happens when the authorization is deactivated or another challenge proves it first. Previously the challenge stayed `processing` with no task left to finish it.
* **An order invalidated by a deactivated authorization** carries the `error` member `an order authorization is no longer valid` (RFC 8555 section 7.1.3). Previously the order had no error.
* **JSON member names are exact** (RFC 8259 section 8.3). A name that matches a known member only when case is ignored, such as `Status` for `status`, is refused with `malformed`. This includes Unicode case variants. Previously it was decoded as that member, so a payload with both `contact` and `Contact` kept the second list.

### Host integration

* **A `*Problem` returned by the `Revoker`** now discards the revocation attempt. The next request starts a new operation with a new `OperationID` and the reason the client sends. Previously every later request repeated the refused operation and reason, so the certificate could not be revoked through ACME.
* **An expired authority token** now ends issuance before the CA is called. The order becomes invalid with `authority token expired before issuance dispatch`. `IssueRequest.Deadline` also ends at the token expiry. Previously the CA was asked to sign a certificate whose validity had already ended.
* **The SQLite example store** in `test/interop/sqlitestore` reports a lock that stays busy past its timeout as a backend error instead of `ErrRevisionMismatch`. Apply the same change to stores derived from it.
* **`Store.UpdateAuthorization` sets `Order.Error`** to `InvalidAuthorizationProblem()` when it invalidates the order. `memstore` and the SQLite example do this. Update custom stores and run `storetest`, which now checks it.
* **A task run ends with its lease.** `New` refuses a `WorkerConfig.Lease` shorter than twice `TaskTimeout`. When only one of them is set, the other follows. `Lease` defaults to 2 minutes or twice `TaskTimeout`, whichever is longer. `TaskTimeout` defaults to 30 seconds or half the lease, whichever is shorter. `Run` returns within one lease after its context is canceled. Previously a slow run could outlast its lease and overlap the worker that claimed the task next.
* **A `*Problem` from `ExternalAccountKeys` or `RenewalAdvisor`** reaches the client unchanged, as documented. Previously the client received `serverInternal`.
* **`Policy.NewOrder` may change only `NotBefore` and `NotAfter`.** Any other change, or a `NotAfter` that is not later than `NotBefore`, is logged and answered with `serverInternal`. Previously such changes were stored without being checked.
* **`Config.BaseURL` with a path that needs percent-encoding**, such as one with a space or a non-ASCII character, is refused by `New`. Previously the server started and refused every signed request.
* **The quickstart CA signs composite ML-DSA requests.** Previously it failed with `x509: unsupported public key type` and the order stayed `processing`. The getting started guide now runs `go mod tidy` after saving the program, which the build needs.
* **DNS resolver fallback** now receives part of the remaining lookup timeout when an earlier server is silent. All configured servers and CNAME hops share the total lookup deadline.
* **go-composite-mldsa v0.2.1** replaces v0.2.0. It rejects signers that do not match a composite CA key and checks key usage supplied through CSR attributes.

### Verification

* **The cert-manager runner** refuses an existing cluster named by `ACME_KIND_CLUSTER` or its default `acme-cert-manager`. It uses a separate kubeconfig and deletes only a cluster it created. `ACME_KEEP_CLUSTER=1` retains that cluster after success or failure.

## [0.4.1] - 9 Oct 2026

This version requires Go 1.27.2 and updates composite ML-DSA support to the published v0.2.0 library.

### Host integration

* **Go 1.27.2 or newer** is required. **go-composite-mldsa v0.2.0** validates composite key encodings more strictly. Valid keys retain the same encoding and algorithm support.

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
