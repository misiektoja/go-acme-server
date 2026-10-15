# Release notes

All notable changes to this project are documented in this file.

## [0.6.0] - TBD

Servers can offer certificate profiles. 5G network functions can enroll through Authority Tokens. STIR/SHAKEN clients built to ATIS-1000080 work. Validation failures that may clear are retried and each attempt reports its cause. Internationalized names and external account binding keys are checked as the RFCs require. Renewal information asks clients to renew a revoked certificate at once. Policies can approve order names in advance and pick the profile of an order that names none. Hosts can record the certificate requests and revocations the server refuses and choose which revocation reasons clients may use. Hosts can limit how often clients get nonces, create accounts and place orders. A contract suite checks custom nonce managers. Custom stores need an update.

### Protocol

* **Certificate profiles** from draft-ietf-acme-profiles-02. `Config.Profiles` lists named profiles in the directory `meta` and accepts a `profile` member on new orders. An order without one gets `Config.DefaultProfile`. The order object shows the selected profile. A name the server does not offer is refused with the new `invalidProfile` error. Finalizing an order whose profile was removed is refused the same way. A server without profiles now refuses a new order that names one. Earlier versions ignored the member. Tested with Certbot 5.8.0 and lego v4.35.2.
* **5G network function certificates** from 3GPP TS 33.310 Annex J. `Config.NfInstanceIDIdentifiers` accepts one `NfInstanceId` identifier per order, validated by `tkauth-01` with an NF Certificate Authority Token. The token may grant an NF type and further DNS names, IP addresses and `https` URIs. The certificate request must carry the instance as `urn:uuid:<value>` and may add only granted names. Its common name is not checked. Another account cannot revoke an NF certificate through its own authorizations.
* **STIR/SHAKEN clients** built to ATIS-1000080 answer `tkauth-01` with an `atc` field instead of the `tkauth` field of RFC 9448. Both are accepted. A response carrying both with different tokens is refused with `malformed`. Earlier versions ignored `atc` and refused the response as missing its token.
* **Failed validations name their cause.** A refused or unanswered connection gives `connection`, a failed TLS handshake gives `tls` and a name that cannot be resolved gives `dns`. These failures are retried. Each failed attempt is shown as the `error` of the challenge while it stays `processing`, as RFC 8555 section 8.2 requires, and the last one makes it `invalid`. Earlier versions showed nothing until the last attempt and then reported `serverInternal`. A wrong proof still fails at once with `incorrectResponse`.
* **A name that does not exist (NXDOMAIN)** is retried and the next DNS server is asked, because a record the client has just added may not have reached every resolver yet. It was final before.
* **Internationalized DNS names** must be valid A-labels. A label starting with `xn--` that is not proper Punycode for a name the IDNA2008 registration rules allow is refused with `rejectedIdentifier`, as RFC 8555 section 7.1.4 requires. Earlier versions accepted any letters, digits and hyphens.
* **External account binding keys** must be at least as long as the hash of the MAC algorithm, as RFC 7518 section 3.2 requires. A binding whose algorithm needs a longer key is refused with `badSignatureAlgorithm`, which lists the algorithms the key allows. A key shorter than 256 bits is refused with `unauthorized` and logged. Earlier versions accepted any key length.
* **acme.sh retries a bad nonce.** The `badNonce` detail now starts with "JWS has an invalid anti-replay nonce", the wording acme.sh looks for. Earlier versions made acme.sh fail when its cached nonce had expired.
* **A refused revocation reason names the allowed ones.** The `badRevocationReason` detail lists them, for example "unspecified (0), keyCompromise (1), affiliationChanged (3), superseded (4) and cessationOfOperation (5)", so the client operator can pick one that works.
* **Renewal information for a revoked certificate** gives a window that ends at the time of the request. In 0.5.0 it ended a minute after the revocation, so during that minute a client that picks a random time in the window could wait instead of renewing at once.

### Host integration

* **`PreApprover`** is an optional extension of `Policy` that names the identifiers of a new order that need no challenge, for example names an administrator approved for an external account binding. Their authorizations start `valid` with `PreApproved` set and no challenges. An order whose identifiers are all pre-approved starts `ready`. `IssueRequest.Validations` marks them with `PreApproved`. A pre-approved authorization never lets an account revoke a certificate another account ordered.
* **`ProfileChooser`** is an optional extension of `Policy` that picks the profile of a new order whose client named none, for example a profile the account's external account binding allows. An empty answer keeps `Config.DefaultProfile`. Without it, such an order gets the default as before.
* **`Config.Refusals`** takes a `RefusalRecorder` that is told about every `finalize` and `revokeCert` request refused after the requester is known: a CSR that does not match its order, a revocation without authority, a reason that is not allowed or a refusal from the `Revoker`. Each `Refusal` carries the account, the order or certificate and the problem the client receives. Unauthenticated requests and `serverInternal` problems are not reported. A recorder error is logged and does not change the answer.
* **`Config.Limits`** takes a `Limiter` that is asked once for every `newNonce`, every `newAccount` that creates an account and every `newOrder`. It gets the kind of request, the client address, the account, the order identifiers and the certificate a renewal `replaces`. Return a `rateLimited` problem with `WithRetryAfter` to refuse. The client gets status 429 and `Retry-After`. A refused `newNonce` carries no nonce. Any other error is answered with `serverInternal`. The client address comes from `RemoteAddr`. Forwarded headers are never read. `Replaces` is set only after the server checked that the account may renew that certificate. Without a `Limiter` nothing is limited, as before.
* **`Config.RevocationReasons`** sets the RFC 5280 reason codes clients may request. The default is unchanged: 0, 1, 3, 4 and 5. A host may add `cACompromise` (2), `privilegeWithdrawn` (9) and `aACompromise` (10). `certificateHold` (6) is never allowed, because an ACME revocation is final.
* **`Config.TNAuthListCertificatesOutliveTokens`** lets a certificate for a TNAuthList identifier keep its own validity after the token expires, as ATIS-1000080 clause 6.3.8 specifies for STIR/SHAKEN. The token must still be valid when signing starts. By default the token expiry still bounds the certificate, as RFC 9447 recommends.
* **`IssueRequest.Profile`** names the certificate profile of the order, so the CA can apply it.
* **`ValidationGrant.Names` and `NFType`** carry extra names and an NF type from a `GrantingValidator` to `IssueRequest.Validations`. Granted names are normalized. A grant of any type other than `dns`, `ip` or `uri` fails the challenge with `serverInternal`.
* **Custom stores** must persist `Authorization.PreApproved`, `GrantNames` and `GrantNFType`, `Validation.Names` and `NFType` and `Order.Profile`, and leave pre-approved authorizations out of `AuthorizedFor`. They must also implement `WorkStore.RetryValidation`, which stores the challenge of a retried validation and releases its task in one transaction. Update your store and run `storetest`.
* **golang.org/x/text** is a new indirect dependency, used by golang.org/x/net/idna for the A-label checks.
* **`Retryable`** lets a custom validator mark a failure for retry and name the problem reported once the attempts run out. Other errors are still reported as `serverInternal`.
* **`ImmediateRenewal`** returns the window that asks for renewal at once, for custom `RenewalAdvisor` implementations. `LifetimeRenewal.Clock` dates the window of a revoked certificate and defaults to the system clock.
* **`noncetest`** checks a custom `NonceManager`. `Run` covers single use, unknown values and concurrent requests. `RunShared` checks that replicas sharing nonces accept each other's nonces exactly once.
* **Data retention guidance** now says to keep authorizations until they expire, because a valid authorization lets an account revoke another account's certificate for the same names.
* **`Ready`** no longer says that `Run` is not active when work waits. Several processes may share the store, so waiting work can also mean that every worker is busy or stuck.

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
