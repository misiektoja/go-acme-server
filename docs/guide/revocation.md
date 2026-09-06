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
* another valid account that holds a valid authorization for every identity the certificate asserts

For the third case the server collects every SAN and adds a common name the SANs do not already
cover, then asks the store's `AuthorizedFor` for the whole set. A wildcard authorization covers
the wildcard name. The account has to prove the names through ordinary orders first, since there
is no pre-authorization.

A certificate the server did not issue is refused with a `404` `malformed` problem. Reason codes
follow RFC 5280. `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded` and
`cessationOfOperation` are accepted. `certificateHold` and the CA reasons are refused with
`badRevocationReason`.

## The request

| Field | Meaning |
| --- | --- |
| `OperationID` | Stable for one certificate across every attempt. Committed before the first call |
| `Certificate`, `DER` | The parsed leaf and its encoding |
| `Reason` | The CRL reason code. A retry keeps the reason recorded on the first attempt |
| `AccountID` | The requesting account, empty when the certificate key signed the request |

## The sequence

1. The server checks the signature, the reason and the requester's authority.
2. It stores `RevocationOperationID`, `RevocationReason` and `RevocationRequestedAt` on the certificate. A concurrent request for the same certificate finds the record and continues the same operation.
3. It calls `Revoke`.
4. On success it stores `Revoked` and `RevokedAt`. This write is detached from the client request and bounded by `Config.DetachedWriteTimeout`, so a client that disconnects after the CA acted does not leave the certificate recorded as live.
5. A later request for the same certificate is answered with `alreadyRevoked`.

## What the revoker must do

**Return nil only after the revocation is durable in the CA.** The server treats nil as success and
records it.

**Deduplicate by operation ID.** A client that lost the response retries and the server calls
`Revoke` again with the same `OperationID`. The second call must succeed without a second CA
action. A CA that already knows the serial should treat the repeat as success.

**Choose the error type.** A returned `*Problem` is sent to the client unchanged. Any other error is
logged and answered with `serverInternal`. The client may retry.

The revoker does not receive the account key or the client's reason for the request beyond the
reason code. If the CA needs to distinguish key compromise from a routine revocation, the reason
code carries it.

## After revocation

`Certificate.Revoked` and `RevokedAt` are visible to the host through the store. With
[Renewal information](renewal-information.md) enabled, `LifetimeRenewal` answers a revoked
certificate with a window that opened at the revocation time, which tells clients to renew at once.

A replacement certificate goes through a new order with fresh authorizations, as every order does.
