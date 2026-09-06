# Errors

Clients receive problem documents of RFC 7807 with the ACME error types of RFC 8555 section 6.7
and RFC 9773. This page lists each type, its default HTTP status and what causes the server to
send it, so an operator can read a client log and know which side to look at.

## Building problems in host code

```go
acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier, "not authorized for this name").
	WithIdentifier(id)

acmeserver.Problemf(acmeserver.ErrorRateLimited, "at most %d orders per hour", limit).
	WithRetryAfter(time.Hour)

acmeserver.Compound("two identifiers were refused", first, second)
```

A `*Problem` returned from `Policy`, `IssuancePolicy`, `Revoker`, `Validator`,
`ExternalAccountKeys` or `RenewalAdvisor` reaches the client unchanged. Any other error from those
interfaces is logged and answered with `serverInternal`. `WithStatus` overrides the default HTTP
status. `AsProblem` extracts a problem from an error chain.

## Error types

| Type | Status | Sent when |
| --- | --- | --- |
| `accountDoesNotExist` | 400 | `onlyReturnExisting` was set and no account owns the key, or a `kid` names an account the store no longer has |
| `alreadyReplaced` | 409 | `replaces` names a certificate another order already claimed |
| `alreadyRevoked` | 400 | The certificate is already revoked |
| `badCSR` | 400 | The CSR signature, key, identifiers, common name or CA basic constraint do not match the order |
| `badNonce` | 400 | The nonce is unknown, expired or was already used. Clients retry with the fresh nonce in the response |
| `badPublicKey` | 400 | The account key type or size is not accepted |
| `badRevocationReason` | 400 | The reason code is `certificateHold` or a CA reason |
| `badSignatureAlgorithm` | 400 | The JWS `alg` is not accepted. The problem lists the supported algorithms |
| `compound` | 400 | Several subproblems, only from host policy |
| `dns` | 400 | The bundled resolver could not complete a lookup in a way that is unlikely to change |
| `externalAccountRequired` | 403 | `Meta.ExternalAccountRequired` is set and the request had no binding |
| `incorrectResponse` | 400 | The challenge proof did not match or the target refused. Final for that authorization |
| `invalidContact` | 400 | A contact is not a single bare `mailto` address |
| `malformed` | 400 | The request violates the protocol: wrong content type, bad JSON, wrong key mode, an unknown resource (404), a method the resource does not support (405) or a `replaces` value that names no certificate |
| `orderNotReady` | 403 | Finalization of an order that is not `ready` |
| `rateLimited` | 429 | Only from host policy |
| `rejectedIdentifier` | 400 | An identifier fails syntax checks, has no supported challenge type or is refused by host policy |
| `serverInternal` | 500 | A store, CA or policy failure, or an issuer result that failed the publication checks |
| `unauthorized` | 403 | The signed `url` does not match, the account is not valid, the requester may not revoke the certificate, an authorization expired before issuance or `replaces` names another account's certificate |
| `unsupportedContact` | 400 | A contact scheme other than `mailto` |
| `unsupportedIdentifier` | 400 | An `ip` or `TNAuthList` identifier while that feature is off, or an unknown identifier type |
| `userActionRequired` | 403 | The terms of service were not agreed |

`caa`, `connection`, `dnssec` and `tls` are defined for host validators and are not sent by the
bundled ones.

## Where an error shows up

| Place | Meaning |
| --- | --- |
| HTTP response | The request itself was refused. Nothing was stored |
| `Challenge.Error` and the authorization status | Validation failed. The order is invalid |
| `Order.Error` | Finalization or issuance failed, or an authorization became invalid |

[Troubleshooting](../operations/troubleshooting.md) maps the common ones to their causes.
