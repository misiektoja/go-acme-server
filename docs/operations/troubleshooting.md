# Troubleshooting

Symptoms, ordered by how often they come up, with the check that finds the cause. Most problems
are on the host side of the contracts, so start with the integration rather than the client.

## The challenge stays pending or processing

The client posted its response and nothing happens. The challenge shows `processing` with a
`Retry-After` and never changes.

* **No worker is running.** `Run` must be active in this or another process on the same store. Call `Ready`, which fails once tasks have waited longer than `WorkerConfig.StaleAfter`. The handler logs `work accepted while Run is not active in this process` unless `WorkerConfig.External` is set.
* **The worker runs against another store.** With `memstore` every process has its own store, so a handler and a worker in different processes never meet. Use a shared durable store.
* **The validator is slow.** Each attempt takes up to `NetworkOptions.Timeout` and a transport failure is retried with backoff up to `WorkerConfig.MaxAttempts`. Look for `validation will be retried` in the log with the error.

## Validation fails with incorrectResponse

The proof was fetched and did not match or the target answered something other than the proof.

* **HTTP-01 reached the wrong server.** The validator connects to the address the configured resolver returns for the name, on port 80 unless `TestPort` is set. Confirm the resolver's answer and that the client's solver listens there.
* **A redirect was refused.** Redirects may only go to `http` or `https` on ports 80 and 443 and each hop must pass the egress policy. The detail names the rule.
* **DNS-01 record not visible.** The validator asks the configured resolver, not the authoritative server directly. Wait for propagation to that resolver or point the resolver at the authoritative servers for tests. The record is looked up at `_acme-challenge.<name>`.
* **TLS-ALPN-01 certificate wrong.** Exactly one SAN equal to the identifier and a critical `acmeIdentifier` extension are required. `acme-tls/1` must be negotiated.

## Validation fails with a policy detail

`validation destination is denied by egress policy` means the name resolved to a private,
loopback, link-local or otherwise special-purpose address. Add the range to
`NetworkOptions.AllowedNetworks` when the CA issues to that network on purpose. The resolver
address itself does not need an exception.

## The signed URL does not match

The client receives `unauthorized` with the detail `JWS url does not match the request URL`. The
URL the client signed differs from the one the server built from `Config.BaseURL`. Compare the
directory URL the client uses with the base URL, character by character, including the scheme,
port and trailing slash. Common causes:

* a reverse proxy that strips the path prefix
* a base URL with the internal listen address instead of the public origin
* TLS terminated at a proxy while the base URL says `http` or the reverse

## Repeated `badNonce` errors

A single `badNonce` is normal after a restart or when a nonce expires. Clients retry with the nonce
in the response. Persistent `badNonce`:

* **Several handler replicas** with in-memory nonces. See [Deployment](deployment.md#replicas).
* **Nonce capacity exceeded.** `nonce.Options.Capacity` bounds outstanding nonces and the oldest are dropped. Raise it or shorten the TTL.

## The account is gone after a restart

The store forgot the account. `memstore` keeps nothing across restarts. The client keeps its account
URL and key, so it is refused until it registers again. Use a durable store or delete the client's
account state in development.

## The order is invalid after finalization

Read `Order.Error`:

| Detail | Cause |
| --- | --- |
| `issuer returned an unacceptable certificate` | The CA's chain failed a publication check. The result is in `Order.UnpublishedResult` and the log names the order. See [Issuing certificates](../guide/issuance.md#publication-checks) |
| `issuer returned a duplicate certificate` | The leaf digest or renewal identifier already exists. The CA reused a serial or a result |
| `authorization expired before issuance dispatch` | The client finalized so late that an authorization or the order expired first |
| `an order authorization is no longer valid` | An authorization was deactivated or invalidated between validation and dispatch |
| `account is no longer valid` | The account was deactivated |
| a problem from your `IssuancePolicy` | The policy refused the dispatch |

## Finalization fails with `badCSR`

* The CSR key equals the account key, is an RSA key outside 2048 to 4096 bits, an unsupported curve or an unsupported type.
* The SANs plus the common name do not equal the order's identifiers. The common name counts unless a TNAuthList is the only identifier.
* The CA basic constraint does not match what the authorizations granted. Only a `tkauth-01` token can grant a CA certificate.

## The renewalInfo resource is missing or 404

The directory advertises it only with `Config.RenewalInfo` set. A certificate without an authority
key identifier has no renewal identifier and no renewal information. Check that your CA sets the
extension.

## A renewal is refused with `alreadyReplaced`

Another order already named this certificate in `replaces` and is not invalid yet. Clients such as
lego and acmez retry without `replaces`. If the earlier order belongs to a crashed client, it frees
the claim when it expires after `Config.OrderLifetime`.

## Revocation returns serverInternal

The `Revoker` returned an error that is not a `*Problem`. The log line `revocation failed` carries
it. The operation ID and reason are already stored on the certificate, so the client's retry calls
`Revoke` again with the same `OperationID`.

## Ready fails in a healthy system

`Ready` counts tasks that were runnable more than `WorkerConfig.StaleAfter` ago and are not leased.
A queue that is deeper than the workers drain within a minute trips it. Raise `Concurrency`, add
worker processes or raise `StaleAfter` to match the expected queue delay.

## Getting help

[SUPPORT.md](https://github.com/misiektoja/go-acme-server/blob/main/SUPPORT.md) lists where to ask.
Include the library and Go versions, the client and its version, the challenge type, which host
interfaces are your own, the problem document the client received and the relevant log lines.
Never post account keys, private keys, external account binding secrets, full CSRs or production
endpoint details.
