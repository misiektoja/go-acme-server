# Configuration

`acmeserver.Config` is passed to `New`, which validates it and returns an error naming the first
problem. Zero values select the defaults below. Negative limits are refused.

## Required fields

| Field | Type | Purpose |
| --- | --- | --- |
| `BaseURL` | `string` | The absolute `https` URL the handler is served under, including any path prefix. A trailing slash is added. See [Embedding the server](../guide/embedding.md#the-base-url) |
| `Store` | `Store` | Persists resources and background work. See [Storage](../guide/storage.md) |
| `Nonces` | `NonceManager` | Issues and consumes request nonces. `nonce.New` for one process |
| `Issuer` | `Issuer` | Signs certificates. See [Issuing certificates](../guide/issuance.md) |
| `Revoker` | `Revoker` | Revokes certificates. See [Revocation](../guide/revocation.md) |
| `Validators` | `map[ChallengeType]Validator` | At least one. Only configured types are offered. See [Challenge validators](../guide/validators.md) |

## Optional fields

| Field | Default | Purpose |
| --- | --- | --- |
| `AllowInsecureBaseURL` | `false` | Accepts an `http` base URL for tests and local examples |
| `Clock` | `SystemClock()` | Supplies the current time |
| `Logger` | discards everything | Receives operational events as `*slog.Logger` |
| `Meta` | empty | Directory metadata: terms of service, website, CAA identities, external account requirement |
| `MaxRequestBody` | 64 KiB | Bounds a request body in bytes |
| `ExternalAccounts` | none | Verifies external account bindings. Required when `Meta.ExternalAccountRequired` or `SingleUseExternalAccounts` is set |
| `SingleUseExternalAccounts` | `false` | Binds each external key identifier to at most one account |
| `Policy` | `AllowAll{}` | Reviews new accounts and orders |
| `IssuancePolicy` | none | Reviews the first issuance dispatch with the accepted CSR and evidence |
| `RequireTermsOfServiceAgreed` | `false` | Refuses accounts that do not agree. Needs `Meta.TermsOfService` |
| `IPIdentifiers` | `false` | Accepts RFC 8738 IP identifiers |
| `TNAuthListIdentifiers` | `false` | Accepts RFC 9448 TNAuthList identifiers. Needs a `ChallengeTKAuth01` validator |
| `TNAuthListCertificatesOutliveTokens` | `false` | Lets a TNAuthList certificate keep its own validity after the token expires, as ATIS-1000080 clause 6.3.8 specifies for STIR/SHAKEN. Needs `TNAuthListIdentifiers` |
| `TokenAuthority` | empty | The `https` URL advertised as `token-authority` on `tkauth-01` challenges |
| `OrderLifetime` | 7 days | How long a new order and its pending authorizations stay valid |
| `AuthorizationLifetime` | 30 days | How long a validated authorization stays valid |
| `MaxIdentifiers` | 100 | Bounds the identifiers of one order |
| `RevocationReasons` | 0, 1, 3, 4 and 5 | The RFC 5280 reason codes clients may request. May hold 0 to 5, 9 and 10. See [Revocation](../guide/revocation.md#reason-codes) |
| `Refusals` | none | Learns about `finalize` and `revokeCert` requests the server refuses. See [Recording refusals](../guide/embedding.md#recording-refusals) |
| `DetachedWriteTimeout` | 30 seconds | Bounds a store write that finishes after the client request ended, such as recording a revocation the CA already carried out |
| `RenewalInfo` | none | Serves RFC 9773 renewal information and accepts `replaces`. `LifetimeRenewal{}` is the built-in advisor |
| `Profiles` | none | The certificate profiles advertised in the directory and accepted on new orders. See [Certificate profiles](../guide/certificate-profiles.md) |
| `DefaultProfile` | empty | The profile of an order that names none. Required with `Profiles` and must be one of them |
| `Workers` | see below | Tunes `Run` and `Ready` |

## `DirectoryMeta`

| Field | Wire member | Notes |
| --- | --- | --- |
| `TermsOfService` | `termsOfService` | Also sent as a `Link` header on `newAccount` |
| `Website` | `website` | |
| `CAAIdentities` | `caaIdentities` | Informational. CAA is not checked by the library |
| `ExternalAccountRequired` | `externalAccountRequired` | Refuses accounts without a binding |

The `meta` object is omitted from the directory when every field is empty and no profiles are
configured. Configured profiles appear in it as `profiles`.

## `Profile`

| Field | Purpose |
| --- | --- |
| `Name` | The name clients send. 1 to 64 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit |
| `Description` | Plain text the server publishes at `<BaseURL>profiles/<Name>` |
| `URL` | An absolute `https` URL of a description published elsewhere. Set exactly one of `Description` and `URL` |

## `WorkerConfig`

| Field | Default | Purpose |
| --- | --- | --- |
| `Concurrency` | 4 | Tasks processed at the same time by one `Run` |
| `PollInterval` | 1 second | How often an idle worker looks for work. Also the minimum delay before a pending issuance is asked again |
| `Lease` | 2 minutes, or twice `TaskTimeout` if that is longer | How long a claimed task stays leased before another worker may take it. A task run stops when its lease ends. It must be at least twice `TaskTimeout` |
| `TaskTimeout` | 30 seconds, or half of `Lease` if that is shorter | Bounds each phase of a task separately: one validator or issuer call, and each store operation that records its outcome. The lease bounds the whole run |
| `MaxAttempts` | 5 | Limits validation and pre-dispatch policy retries. Issuance recovery is not limited |
| `RetryDelay` | 5 seconds | The first retry delay, doubled on every further attempt up to 32 times the base |
| `StaleAfter` | 1 minute | How long accepted work may wait unclaimed before `Ready` reports a problem |
| `External` | `false` | Declares that `Run` is active in another process, which silences the warning logged when work is accepted while no local worker runs |

## Package defaults

The `challenge` and `nonce` packages have their own option types with defaults documented on each
field:

| Option | Default |
| --- | --- |
| `ResolverOptions.Timeout`, `MaxCNAMEs`, `MaxResponseBytes`, `MaxRecords` | 10 seconds, 8, 16 KiB, 64 |
| `NetworkOptions.Timeout`, `MaxAddresses` | 10 seconds, 32 |
| `HTTPOptions.MaxRedirects`, `MaxResponseBytes` | 10, 4096 bytes |
| `DNSOptions.Timeout` | 10 seconds |
| `TKAuthOptions.ClockSkew` | 1 minute |
| `nonce.Options.TTL`, `Capacity` | 1 hour, 100000 |
| `LifetimeRenewal.Start`, `End`, `RetryAfter`, `Clock` | 2/3, 5/6, 6 hours, system clock |

## Validation errors

`New` returns an error with the `acmeserver:` prefix for:

* a missing or malformed `BaseURL` or an `http` scheme without `AllowInsecureBaseURL`
* a missing `Store`, `Nonces`, `Issuer` or `Revoker`
* an empty `Validators` map, a nil validator or an unknown challenge type
* `Meta.ExternalAccountRequired` or `SingleUseExternalAccounts` without `ExternalAccounts`
* `RequireTermsOfServiceAgreed` without `Meta.TermsOfService`
* `TNAuthListIdentifiers` without a `tkauth-01` validator
* `TNAuthListCertificatesOutliveTokens` without `TNAuthListIdentifiers`
* a `TokenAuthority` that is not an absolute `https` URL
* an invalid or repeated profile name, a profile without exactly one of `Description` and `URL`, a
  profile `URL` that is not an absolute `https` URL or a `Description` that is not valid UTF-8
* `DefaultProfile` without `Profiles` or a `DefaultProfile` that names none of them
* a `RevocationReasons` code other than 0 to 5, 9 and 10
* a negative limit or worker value
