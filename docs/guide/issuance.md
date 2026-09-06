# Issuing certificates

The `Issuer` interface is where the host CA signs certificates. This page explains what the server
guarantees before it calls the issuer, what the issuer must guarantee in return and what happens to
the result.

```go
type Issuer interface {
	Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
}
```

## What the server does first

Finalization accepts a CSR only when it is self-signed with an accepted key that is not the
account key and requests exactly the identifiers of the order. The worker then records the dispatch
decision in the store before the first CA call: an `OperationID`, the validation evidence and the
earliest expiry among the order and its authorizations as the `Deadline`. An optional
[`IssuancePolicy`](#issuance-policy) runs before that record is written.

From this point every call for the order presents the same `OperationID`, whether it is the first
attempt, a retry after a timeout or a recovery from another worker after a crash.

## The request

| Field | Meaning |
| --- | --- |
| `OperationID` | Stable for one order across every attempt. Deduplicate on it |
| `AccountID`, `AccountURL`, `OrderID` | For audit records |
| `CSR`, `CSRDER` | The accepted request, already checked against the order |
| `Identifiers` | The normalized identifiers of the order |
| `NotBefore`, `NotAfter` | The requested validity. Zero means the CA decides. An authority token expiry narrows `NotAfter` |
| `Validations` | How each identifier was validated: challenge type, time and any CA grant |
| `Deadline` | After this time no new signing may start |
| `RecoveryOnly` | Set once the deadline has passed. Only an existing result may be returned |

## The result

Exactly one of these is set:

| Outcome | Fields | What the server does |
| --- | --- | --- |
| Issued | `Chain` and optionally `CAReference` | Checks the chain and publishes the certificate |
| Pending | `Pending` and `RetryAfter` | Asks again after `RetryAfter`, at least `WorkerConfig.PollInterval` later |
| Rejected | `Rejected` | Makes the order invalid with that problem |

An `error` return means the outcome is unknown. The worker reschedules the task and calls again
with the same `OperationID`. There is no attempt limit on this path, because the CA may already have
issued the certificate. Return an error only when you do not know what happened. Return the
recorded result or a `Rejected` problem when you do.

Use problem types clients understand. `ErrorRejectedIdentifier` for a name the CA will not issue
for, `ErrorBadCSR` for a request the CA cannot honor and `ErrorUnauthorized` for a deadline that
passed. `NewProblem` and `Problemf` build them.

## What the issuer must do

**Deduplicate by operation ID.** Store the result under `OperationID` before returning it and
return that stored result on every later call with the same ID. A CA that signs twice for one
order produces two valid certificates for one authorization.

**Enforce the deadline.** Do not start a new signing operation once `Deadline` has passed and never
when `RecoveryOnly` is set. Returning an existing result is always allowed.

**Stay inside the requested validity.** The CA may shorten the validity to its own policy. The
leaf's `NotBefore` must not be earlier than the requested one and its `NotAfter` must not be later.
The leaf must already be valid when it is returned unless the order asked for a future start.

**Match the request.** The leaf must carry the CSR's public key, exactly the order's identifiers
as SANs and no CA basic constraint unless an Authority Token granted one, see [Authority Token challenges](authority-tokens.md).

**Return the full chain.** `Chain` holds the DER leaf followed by the DER issuer chain in signing
order. Each element must be signed by the next one.

A minimal implementation over a database looks like this:

```go
func (ca *CA) Issue(ctx context.Context, req acmeserver.IssueRequest) (acmeserver.IssueResult, error) {
	if chain, ok, err := ca.lookup(ctx, req.OperationID); err != nil {
		return acmeserver.IssueResult{}, err // unknown outcome, the worker retries
	} else if ok {
		return acmeserver.IssueResult{Chain: chain}, nil
	}
	if req.RecoveryOnly || !req.Deadline.After(time.Now()) {
		return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorUnauthorized,
			"the signing deadline has passed")}, nil
	}
	chain, err := ca.sign(ctx, req)
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	// Record the result under the operation ID before returning it. If another worker recorded
	// one first, return that one instead.
	return acmeserver.IssueResult{Chain: ca.recordOrExisting(ctx, req.OperationID, chain)}, nil
}
```

## Publication checks

Before a chain reaches a client the server verifies that:

* the leaf public key equals the CSR public key
* the leaf is valid now and its `NotAfter` is after its `NotBefore`
* the leaf `NotBefore` is not earlier than the accepted order value and not in the future unless the order asked for it
* the leaf `NotAfter` does not exceed the requested value or the authority token expiry
* the leaf's SANs and, unless an authority list is the only identity, its common name equal the order identifiers
* the leaf's CA basic constraint matches what the authorizations granted, which is never for DNS and IP orders
* every chain element is signed by the following one

A chain that passes becomes a `Certificate` whose ID is the base64url SHA-256 digest of the leaf.
`CAReference` and `Validations` are stored with it for audit needs.

## Unpublished results

A chain that fails a check, arrives together with an error or with `Pending` or `Rejected`, or
whose leaf digest or renewal identifier collides with a stored certificate is never served. The
server stores the whole `IssueResult` in `Order.UnpublishedResult`, marks the order invalid with a
`serverInternal` problem and logs an error naming the order and operation.

The library does not revoke these certificates. The host must find orders with an unpublished
result and revoke or reconcile them in its CA. Add that query to your store and run it from a
scheduled job or an alert.

## Issuance policy

```go
type IssuancePolicy interface {
	AuthorizeIssuance(ctx context.Context, req IssueRequest) error
}
```

`Config.IssuancePolicy` runs once per order before the dispatch decision is stored, with the same
request the issuer would receive. It is the place for checks that need the accepted CSR or the
validation evidence, such as CAA-style rules, key policy or a final identifier check against a
current allow list. A returned `*Problem` makes the order invalid with that problem. Any other error
is retried up to `WorkerConfig.MaxAttempts` and then fails the order with `serverInternal`.

Policy that only needs the identifiers belongs in `Policy.NewOrder`, which refuses the order before
any validation work. See [Accounts and policy](accounts-and-policy.md).

## Recovery scenarios

| Situation | Behavior |
| --- | --- |
| Worker dies after `Issue` returned and before the result is stored | Another worker claims the task after the lease and calls `Issue` with the same `OperationID`. The issuer returns the recorded chain |
| CA times out | The worker retries with backoff and the same `OperationID`, without an attempt limit |
| Deadline passes while the outcome is unknown | The request carries `RecoveryOnly`. The issuer returns an existing result or `Rejected` |
| Account deactivated after finalization | Recovery of an existing CA operation continues, because the certificate may exist |
| Authorization invalidated between finalization and dispatch | `BeginIssuance` fails and the order becomes invalid without a CA call |
| Same CSR finalized twice | The second finalization is accepted without a second issuance |
