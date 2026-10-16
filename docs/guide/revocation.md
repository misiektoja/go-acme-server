# Revocation

The `Revoker` interface is where the host CA records a revocation. The server decides who may
revoke and makes the operation durable. The CA publishes it through its CRL or OCSP responder.

```go
type Revoker interface {
	Revoke(ctx context.Context, req RevokeRequest) error
}
```

## Who may revoke

A `revokeCert` request is accepted from:

* the account that ordered the certificate
* the certificate's own private key, with the request signed by the certificate key as an embedded JWK
* another valid account that holds a valid authorization proved by a challenge for every identity the certificate asserts

For the third case the server collects every SAN and adds a common name the SANs do not already
cover, then asks the store's `AuthorizedFor` for the whole set. A wildcard authorization covers
the wildcard name. The account has to prove the names through ordinary orders first, since there
is no pre-authorization. Names a policy pre-approved for the account do not count, see
[Pre-approved identifiers](accounts-and-policy.md#pre-approved-identifiers).

A network function certificate, one that carries an `NfInstanceId` URN, is never revoked this third
way. 3GPP TS 33.310 clause J.4 limits its revocation to the enrolling account and the holder of the
certificate key, see [Authority Token challenges](authority-tokens.md#network-function-certificates).

A certificate the server did not issue is refused with a `404` `malformed` problem.

## Reason codes

Reason codes follow RFC 5280. By default `unspecified` (0), `keyCompromise` (1),
`affiliationChanged` (3), `superseded` (4) and `cessationOfOperation` (5) are accepted.
`Config.RevocationReasons` replaces that list. It may also hold `cACompromise` (2),
`privilegeWithdrawn` (9) and `aACompromise` (10). `certificateHold` (6) is never accepted, because
an ACME revocation is final and the certificate cannot be released again. Any other code is
refused with `badRevocationReason`, whose detail names the allowed reasons.

A refused revocation is reported to `Config.Refusals` when it is set, see
[Recording refusals](embedding.md#recording-refusals).

## The request

| Field | Meaning |
| --- | --- |
| `OperationID` | Stable across retries until the CA accepts or refuses the revocation. Committed before the first call |
| `Certificate`, `DER` | The parsed leaf and its encoding |
| `Reason` | The CRL reason code. A retry keeps the recorded reason |
| `AccountID` | The requesting account, empty when the certificate key signed the request |

## The sequence

1. The server checks the signature, the reason and the requester's authority.
2. It stores `RevocationOperationID`, `RevocationReason` and `RevocationRequestedAt` on the certificate. A concurrent request for the same certificate finds the record and continues the same operation.
3. It calls `Revoke`.
4. If `Revoke` returns a `*Problem`, the server clears the recorded operation and sends the problem. The next request starts a new operation with its own reason.
5. On success it stores `Revoked` and `RevokedAt`. This write is detached from the client request and bounded by `Config.DetachedWriteTimeout`, so a client that disconnects after the CA acted does not leave the certificate recorded as live.
6. A later request for the same certificate is answered with `alreadyRevoked`.

## What the revoker must do

**Return nil only after the revocation is durable in the CA.** The server treats nil as success and
records it.

**Deduplicate by operation ID.** A client that lost the response retries and the server calls
`Revoke` again with the same `OperationID`. The second call must succeed without a second CA
action. A CA that already knows the serial should treat the repeat as success.

**Choose the error type.** A returned `*Problem` is a final refusal. It is sent to the client
unchanged and the operation is discarded. Any other error is logged and answered with
`serverInternal`. The client may retry. The retry repeats the same operation and reason.

The revoker does not receive the account key or the client's reason for the request beyond the
reason code. If the CA needs to distinguish key compromise from a routine revocation, the reason
code carries it.

## After revocation

`Certificate.Revoked` and `RevokedAt` are visible to the host through the store. With
[Renewal information](renewal-information.md) enabled, `LifetimeRenewal` answers a revoked
certificate with a window from the revocation time to the time of the request, which tells clients
to renew at once.

A replacement certificate goes through a new order with fresh authorizations, as every order does.
