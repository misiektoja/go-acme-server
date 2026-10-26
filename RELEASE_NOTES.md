# Release notes

All notable changes to this project are documented in this file.

## [0.8.0] - TBD

This release stops one account from monopolizing the validation workers. **`Config.MaxPendingValidations`** bounds the validations an account may have waiting or running, the `Limiter` is asked about **challenge responses** and **`Ready`** no longer fails because clients keep the workers busy. Custom stores need two new counting methods. The module now requires Go 1.27.3.

### Protocol

* **Challenge responses are bounded per account.** A response is refused with `rateLimited` and a `Retry-After` of `WorkerConfig.TaskTimeout` once the account has `MaxPendingValidations` validations waiting or running, `MaxIdentifiers` by default. The challenge stays `pending`, so the client can respond again later. Earlier versions accepted any number of responses. An account whose names pointed at destinations that never answered could delay every other account's validations for as long as it kept responding.

### Host integration

* **`Config.MaxPendingValidations`** sets the bound. Zero selects `MaxIdentifiers`, which lets one full order validate at once.
* **`LimitChallengeResponse`** is a new `Limiter` kind, asked before a validation is enqueued with the account, the identifier of the authorization and the account's `PendingValidations`. A limiter that allows unknown kinds keeps working unchanged.
* **`Ready` passes while any task is leased.** It fails only when work has waited longer than `StaleAfter` and no worker holds a lease, so a deep queue behind busy workers no longer trips readiness probes. A worker that died holding leases is reported once they expire, at most `WorkerConfig.Lease` later.
* **Stores gain `LeasedTasks` and `AccountValidations`.** The first counts tasks under a lease, the second the unfinished validation tasks of an account. `storetest` checks both, so run it again. The SQLite example store indexes tasks by account and kind.
* **Go 1.27.3** is the minimum, which carries the crypto/x509 fix for GO-2026-6809.

## [0.7.0] - 19 Oct 2026

This release adds **SLH-DSA keys** (FIPS 205, RFC 9909) for all twelve parameter sets. Clients can order certificates for SLH-DSA keys and revoke them through an authorized account. The host CA can sign with an SLH-DSA key and the server checks those signatures in the chain it returns. The CA must certify these keys from `CSR.RawSubjectPublicKeyInfo`. Hosts that accept or sign with the SHA2-256f or SHAKE-256f sets must raise `MaxRequestBody` to 128 KiB. It works with Certbot 5.8.0, lego v4.35.2 and Go crypto/acme v0.58.0. The library now depends on `github.com/cloudflare/circl` for SLH-DSA.

### Protocol

* **SLH-DSA certificate requests** from RFC 9909 are accepted in all 12 FIPS 205 parameter sets. The CSR must be signed in pure mode with an empty context and the key's own parameter set. HashSLH-DSA requests are refused with `badCSR`. Revoke these certificates through an authorized account.
* **SLH-DSA issuer chains.** The host CA may sign with an SLH-DSA key in any of the 12 parameter sets. The server checks each such signature in the returned chain in pure mode with an empty context, together with the issuer's CA flag and certificate signing key usage.

### Host integration

* **`CSR.PublicKey` is nil for SLH-DSA keys.** Certify `CSR.RawSubjectPublicKeyInfo` unchanged.
* **Set `MaxRequestBody` to 128 KiB for the SHA2-256f and SHAKE-256f sets.** A finalize request for such a key and a revocation request for a certificate such a CA signed are about 90 KB. The 64 KiB default refuses them with HTTP 413.
* **Dependencies.** github.com/cloudflare/circl v1.6.5 checks SLH-DSA signatures. golang.org/x/crypto v0.58.0 is now a direct dependency and golang.org/x/sys v0.49.0 an indirect one.

### Verification

* **Certbot 5.8.0** obtains and revokes certificates for an SLH-DSA-SHA2-128s CSR and for an SLH-DSA-SHA2-192s CSR from an SLH-DSA-SHA2-192s CA.
* **lego v4.35.2** and **Go crypto/acme v0.58.0** obtain and revoke certificates from SLH-DSA CAs, up to an SLH-DSA-SHAKE-256f key from an SLH-DSA-SHA2-256f CA.

## [0.6.0] - 16 Oct 2026

Adds certificate profiles, 5G network function certificates and hooks that let the host pre-approve names, limit request rates and record refused requests. Failed validations are retried with their cause shown. Several RFC checks are stricter. Custom stores need an update.

### Protocol

* **Certificate profiles** from draft-ietf-acme-profiles-02. `Config.Profiles` lists them in the directory and `Config.DefaultProfile` applies when an order names none. An unknown name is refused with `invalidProfile`. A server without profiles now refuses an order that names one. Earlier versions ignored it.
* **5G network function certificates** from 3GPP TS 33.310 Annex J. `Config.NfInstanceIDIdentifiers` accepts an `NfInstanceId` identifier proved by `tkauth-01` with an NF Certificate Authority Token. The token can grant an NF type and extra names.
* **STIR/SHAKEN clients built to ATIS-1000080** can send their token in the `atc` field. `Config.TNAuthListCertificatesOutliveTokens` lets their certificates outlive the token, as that standard specifies.
* **Failed validations are retried and show their cause.** Connection, TLS and DNS failures, including a name that does not exist yet, are retried. While the challenge is `processing` its `error` shows the last cause as `connection`, `tls` or `dns`. Earlier versions reported `serverInternal` after the last attempt.
* **Stricter checks.** Internationalized names must be valid A-labels and are refused with `rejectedIdentifier` otherwise. External account binding keys must be as long as the MAC algorithm requires and at least 256 bits.
* **acme.sh retries an expired nonce.** The `badNonce` detail now uses the wording it looks for.
* **Revocation.** `badRevocationReason` lists the reasons the server allows. Renewal information for a revoked certificate now ends at the time of the request, so clients renew at once. In 0.5.0 a client could wait up to a minute after the revocation.

### Host integration

* **`PreApprover` and `ProfileChooser`** are optional `Policy` extensions. The first names order identifiers that need no challenge, for example names approved for an external account binding. The second picks the profile of an order that names none.
* **`Config.Limits`** takes a `Limiter` that is asked about every `newNonce`, new account and `newOrder`. Refuse with a `rateLimited` problem and the client gets status 429 and `Retry-After`. The client address comes from `RemoteAddr` only. Without a `Limiter` nothing is limited.
* **`Config.Refusals`** takes a `RefusalRecorder` that is told about every `finalize` and `revokeCert` request refused after the requester is known.
* **`Config.RevocationReasons`** sets the reason codes clients may request. The default is unchanged. `certificateHold` is never allowed.
* **`IssueRequest.Profile`** and **`ValidationGrant.Names` and `NFType`** pass the order profile and the token grants to the CA.
* **New helpers.** `Retryable` marks a custom validator failure for retry. `ImmediateRenewal` serves custom `RenewalAdvisor` implementations. `noncetest` checks a custom `NonceManager`, including replicas that share nonces.
* **Custom stores must be updated.** Persist `Authorization.PreApproved`, `GrantNames` and `GrantNFType`, `Validation.Names` and `NFType` and `Order.Profile`. Leave pre-approved authorizations out of `AuthorizedFor`. Implement `WorkStore.RetryValidation`. Then run `storetest`.
* **Dependencies.** golang.org/x/net v0.61.0 is now the minimum. It clears five HTTP/2 advisories against v0.59.0 that the library does not reach but dependency scanners report. golang.org/x/text is a new indirect dependency, used for the A-label checks.

### Verification

* **Tested clients:** acmez v3.1.7, Certbot 5.8.0, lego v4.35.2 and Go crypto/acme v0.58.0.

## [0.5.0] - 11 Oct 2026

Fixes stuck challenges, revocation retries and DNS failover. Custom stores and worker settings may need updates.

### Protocol

* **Processing challenges** become `invalid` when their authorization is deactivated or proved by another challenge. Updates that were not saved return `serverInternal`.
* **JSON member names** must match exactly. Case variants such as `Status` for `status`, including Unicode variants, return `malformed` (RFC 8259 section 8.3).
* **Expired authority tokens** invalidate the order before the CA is called. Token expiry also bounds `IssueRequest.Deadline`.

### Host integration

* **Custom stores** must set `Order.Error` to `InvalidAuthorizationProblem()` when `Store.UpdateAuthorization` invalidates an order. Update your store and run `storetest`.
* **`WorkerConfig.Lease`** must be at least twice `TaskTimeout`. Task runs and shutdown are bounded by the lease. Defaults are 2 minutes and 30 seconds, adjusted when only one setting is supplied.
* **Revocation retries** use a new `OperationID` and the next request's reason after the `Revoker` returns a `*Problem`.
* **`ExternalAccountKeys` and `RenewalAdvisor`** return their `*Problem` to the client unchanged.
* **`Policy.NewOrder`** may change only `NotBefore` and `NotAfter`. Other edits or invalid date ranges return `serverInternal`.
* **`Config.BaseURL`** paths that need percent-encoding are rejected at startup.
* **DNS fallback servers** get time to respond when an earlier server is silent, within the shared lookup deadline.
* **Composite ML-DSA** support uses go-composite-mldsa v0.2.1. The quickstart CA now signs composite requests.
* **The SQLite example** reports lock timeouts as backend errors instead of `ErrRevisionMismatch`. Update stores derived from it.

### Verification

* **The cert-manager runner** refuses existing cluster names and uses its own kubeconfig. It removes only the cluster it creates, unless `ACME_KEEP_CLUSTER=1`.

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
