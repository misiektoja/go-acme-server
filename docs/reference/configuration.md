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
| `TokenAuthority` | empty | The `https` URL advertised as `token-authority` on `tkauth-01` challenges |
| `OrderLifetime` | 7 days | How long a new order and its pending authorizations stay valid |
| `AuthorizationLifetime` | 30 days | How long a validated authorization stays valid |
| `MaxIdentifiers` | 100 | Bounds the identifiers of one order |
| `DetachedWriteTimeout` | 30 seconds | Bounds a store write that finishes after the client request ended, such as recording a revocation the CA already carried out |
| `RenewalInfo` | none | Serves RFC 9773 renewal information and accepts `replaces`. `LifetimeRenewal{}` is the built-in advisor |
| `Workers` | see below | Tunes `Run` and `Ready` |

## DirectoryMeta

| Field | Wire member | Notes |
| --- | --- | --- |
| `TermsOfService` | `termsOfService` | Also sent as a `Link` header on `newAccount` |
| `Website` | `website` | |
| `CAAIdentities` | `caaIdentities` | Informational. CAA is not checked by the library |
| `ExternalAccountRequired` | `externalAccountRequired` | Refuses accounts without a binding |

The `meta` object is omitted from the directory when every field is empty.

## WorkerConfig

| Field | Default | Purpose |
| --- | --- | --- |
| `Concurrency` | 4 | Tasks processed at the same time by one `Run` |
| `PollInterval` | 1 second | How often an idle worker looks for work. Also the minimum delay before a pending issuance is asked again |
| `Lease` | 2 minutes | How long a claimed task stays leased before another worker may take it |
| `TaskTimeout` | 30 seconds | Bounds each phase of a task separately: one validator or issuer call, and each store operation that records its outcome |
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
| `LifetimeRenewal.Start`, `End`, `RetryAfter` | 2/3, 5/6, 6 hours |

## Validation errors

`New` returns an error with the `acmeserver:` prefix for:

* a missing or malformed `BaseURL` or an `http` scheme without `AllowInsecureBaseURL`
* a missing `Store`, `Nonces`, `Issuer` or `Revoker`
* an empty `Validators` map, a nil validator or an unknown challenge type
* `Meta.ExternalAccountRequired` or `SingleUseExternalAccounts` without `ExternalAccounts`
* `RequireTermsOfServiceAgreed` without `Meta.TermsOfService`
* `TNAuthListIdentifiers` without a `tkauth-01` validator
* a `TokenAuthority` that is not an absolute `https` URL
* a negative limit or worker value
