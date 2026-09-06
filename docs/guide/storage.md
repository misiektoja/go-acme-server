# Storage

The `Store` interface is how the server persists accounts, orders, authorizations, challenges,
certificates and background tasks. The host implements it over its own database. This page
describes the contract, the parts that are easy to get wrong and how to verify an implementation
with the `storetest` suite.

`memstore` is the in-memory implementation for tests and examples. It forgets everything when the
process exits and must not be used in production.

## The contract in one paragraph

Every method is atomic. Every method returns copies the caller owns. Every resource carries a
`Revision` that starts at 1 and increases on each successful update, and every update presents the
revision it read. Tasks carry a `Fence` that increases on every claim. Every completion
presents the fence it holds. The store returns `ErrNotFound`, `ErrConflict`, `ErrRevisionMismatch`
or `ErrAlreadyReplaced` for contract violations and any other error for backend failures. The
server retries or gives up based on that distinction, so a backend error must never be reported as
one of the contract errors.

## Interfaces

`Store` embeds four interfaces. Each is small enough to implement in a day over a relational
database.

| Interface | Methods | Notes |
| --- | --- | --- |
| `AccountStore` | `CreateAccount`, `Account`, `AccountByKey`, `UpdateAccount` | Account ID, key thumbprint and a non-empty `ExternalAccountClaim` are each unique |
| `OrderStore` | `CreateOrder`, `Order`, `OrderIDs`, `Authorization`, `UpdateAuthorization`, `AuthorizedFor`, `Challenge` | `CreateOrder` writes the order with all its authorizations and challenges |
| `CertificateStore` | `Certificate`, `CertificateByRenewalID`, `UpdateCertificate` | A non-empty `RenewalID` is unique |
| `WorkStore` | `AcceptChallenge`, `FinalizeOrder`, `BeginIssuance`, `ClaimTask`, `RescheduleTask`, `FinishTask`, `CompleteValidation`, `CompleteIssuance`, `PendingTasks` | Combines resource updates with task changes in one transaction |

The Go documentation on each method states its exact semantics. The sections below explain the
ones that carry the most weight.

## Revisions

`Create*` stores the resource with revision 1 and returns `ErrConflict` when any unique value is
already in use. `Update*` compares the stored revision with the one on the passed resource,
returns `ErrRevisionMismatch` when they differ and otherwise writes the resource and increments its
revision. The server reads the resource again and retries when it sees a mismatch, so the check
must be part of the same transaction as the write.

`UpdateAuthorization` has one extra duty. When the authorization reaches a terminal status, the
same operation marks its order invalid unless issuance was already dispatched. The `storetest`
suite checks this.

## Tasks, leases and fences

A `Task` names a challenge to validate or an order to issue. `AcceptChallenge` and `FinalizeOrder`
enqueue it in the same transaction that changes the resource, so a crash between the two cannot
leave an accepted challenge without work.

`ClaimTask` picks the runnable task with the earliest `RunAt`, sets `LeaseUntil`, increments
`Attempts` and `Fence` and returns it. A task is runnable when `RunAt` is not in the future and it
holds no lease past `now`. Two workers calling `ClaimTask` at the same time must never receive the
same task. Use a row lock, a compare-and-set or a serializable transaction, whichever your database
offers.

Every completion method receives the claimed task and must compare `task.Fence` with the stored
fence, returning `ErrRevisionMismatch` when another claim superseded it. That is what stops a worker
that lost its lease from committing a stale result.

`RescheduleTask` releases the lease and stores the new `RunAt`. `FinishTask` removes the task
without touching any resource. `PendingTasks` counts tasks that were runnable at or before a time
and hold no lease past it, which `Ready` uses to detect that no worker is active.

## Composite operations

| Method | Writes in one transaction |
| --- | --- |
| `CreateOrder` | The order, its authorizations, its challenges and, when `order.Replaces` is set, the `ReplacedByOrderID` of the predecessor certificate |
| `AcceptChallenge` | The challenge at its revision and the new validation task |
| `FinalizeOrder` | The order at its revision and the new issuance task |
| `BeginIssuance` | `order.Issuance` after checking the task fence and the revision and status of the order, the account and every authorization |
| `CompleteValidation` | The challenge, the authorization and the order at their revisions, and removes the task. The order revision advances even when its fields did not change |
| `CompleteIssuance` | The order at its revision, the certificate when one is passed, and removes the task. Returns `ErrConflict` when the certificate ID or a non-empty `RenewalID` is in use |

`BeginIssuance` is the durability point of issuance. It stores the decision to call the CA together
with the evidence and the deadline. It must fail with `ErrRevisionMismatch` if anything it was
given has changed since the worker read it.

## Replacement claims

With [Renewal information](renewal-information.md) enabled, an order may name the certificate it
replaces. `CreateOrder` then marks that certificate as replaced by the order in the same
transaction. It returns `ErrNotFound` when no certificate has that `RenewalID` and
`ErrAlreadyReplaced` when another order that is not invalid at `order.CreatedAt` already claimed
it. The second check needs the claiming order's status and expiry, so read the previous claimant
inside the transaction.

## Authorization lookup

`AuthorizedFor` reports whether an account holds a valid unexpired authorization for every
identifier in the list, read in one consistent snapshot. Revocation by an account other than the
issuer relies on it. A wildcard authorization covers the wildcard identifier and is stored with
`Wildcard` set and the base name in `Identifier`, so index authorizations by account, identifier
type, value and wildcard flag.

## Serialization

* `Account.Key` is a `crypto.PublicKey`. Store the PKIX DER from `x509.MarshalPKIXPublicKey` and parse it back with `x509.ParsePKIXPublicKey`. The `KeyThumbprint` is precomputed for you.
* `Order.Error`, `Challenge.Error` and `Order.UnpublishedResult` are structs with JSON tags. Storing them as JSON columns works.
* `Certificate.Chain` is a list of DER blobs. Keep the order.
* Structs may gain fields in later releases. A store that serializes whole resources as JSON must ignore fields it does not know. See [Compatibility policy](../reference/compatibility.md).
* Store times in UTC with at least second precision.

## Verify with storetest

```go
func TestStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T) acmeserver.Store {
		return openFreshStore(t)
	})
}
```

`storetest.Run` executes the contract suite. The `open` function must return an empty store for
every subtest. The suite covers revisions, uniqueness, copies, concurrent creation and claiming,
every composite operation, authorization scope, renewal lookups and replacement claims. It is the
same suite `memstore` runs. A store change in a new release comes with a `storetest` update,
so run it again when upgrading.

The suite does not measure durability. Add your own test that kills the process between
`BeginIssuance` and `CompleteIssuance` and confirms the task is reclaimed.

## A worked example

The interoperability module contains a SQLite adapter at `test/interop/sqlitestore`. It uses one
table per resource, a `revision` column checked in every `UPDATE ... WHERE revision = ?`,
`BEGIN IMMEDIATE` transactions for claims and maps SQLite lock conflicts to `ErrRevisionMismatch`.
It is test infrastructure without a migration or support contract, but it is a complete and
readable implementation of every method.
