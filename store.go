package acmeserver

import (
	"context"
	"errors"
	"time"
)

// Errors a Store returns for contract violations. Backend failures must use other errors.
var (
	ErrNotFound         = errors.New("acmeserver: resource not found")
	ErrConflict         = errors.New("acmeserver: resource already exists")
	ErrRevisionMismatch = errors.New("acmeserver: resource revision mismatch")
)

// Persists accounts. Every method is atomic and returns copies the caller owns.
type AccountStore interface {
	// Stores a new account with revision 1. It returns ErrConflict when the ID or key
	// thumbprint is already in use.
	CreateAccount(ctx context.Context, account *Account) error
	// Returns the account with the given ID or ErrNotFound.
	Account(ctx context.Context, id string) (*Account, error)
	// Returns the account whose key has the given thumbprint or ErrNotFound.
	AccountByKey(ctx context.Context, thumbprint string) (*Account, error)
	// Replaces the stored account when the revisions match and increments
	// account.Revision. It returns ErrRevisionMismatch, ErrNotFound or ErrConflict otherwise.
	UpdateAccount(ctx context.Context, account *Account) error
}

// Persists orders with their authorizations and challenges.
type OrderStore interface {
	// Stores an order together with its authorizations and challenges, all at revision 1.
	// It returns ErrConflict when any ID is already in use.
	CreateOrder(ctx context.Context, order *Order, authzs []*Authorization, challenges []*Challenge) error
	// Returns the order with the given ID or ErrNotFound.
	Order(ctx context.Context, id string) (*Order, error)
	// Returns up to limit order IDs of the account in creation order, starting after the
	// given ID. An empty after starts at the beginning.
	OrderIDs(ctx context.Context, accountID, after string, limit int) ([]string, error)
	// Returns the authorization with the given ID or ErrNotFound.
	Authorization(ctx context.Context, id string) (*Authorization, error)
	// Replaces the authorization and invalidates its order if authorization ends before issuance dispatch.
	UpdateAuthorization(ctx context.Context, authz *Authorization) error
	// Checks a valid account's unexpired authorizations for every identifier in one consistent read.
	AuthorizedFor(ctx context.Context, accountID string, identifiers []Identifier, now time.Time) (bool, error)
	// Returns the challenge with the given ID or ErrNotFound.
	Challenge(ctx context.Context, id string) (*Challenge, error)
}

// Persists issued certificates.
type CertificateStore interface {
	// Returns the certificate with the given ID or ErrNotFound.
	Certificate(ctx context.Context, id string) (*Certificate, error)
	// Replaces the stored certificate when the revisions match and increments cert.Revision.
	UpdateCertificate(ctx context.Context, cert *Certificate) error
}

// Persists background work together with the resource changes that create or finish it.
// Every task method that takes a claimed task checks task.Fence against the stored fence and
// returns ErrRevisionMismatch when another claim superseded it.
type WorkStore interface {
	// Stores the challenge when its revision matches and enqueues the task in the same
	// operation. It returns ErrConflict when the task ID is in use.
	AcceptChallenge(ctx context.Context, challenge *Challenge, task *Task) error
	// Stores the order when its revision matches and enqueues the task in the same operation.
	FinalizeOrder(ctx context.Context, order *Order, task *Task) error
	// Records the first dispatch after checking the task fence and every supplied resource revision and status.
	BeginIssuance(ctx context.Context, task *Task, order *Order, account *Account, authzs []*Authorization) error
	// Leases the runnable task with the earliest RunAt, increments its fence and attempts
	// and returns a copy. It returns ErrNotFound when no task is runnable at now.
	ClaimTask(ctx context.Context, now, leaseUntil time.Time) (*Task, error)
	// Releases the lease and stores task.RunAt for a later claim.
	RescheduleTask(ctx context.Context, task *Task) error
	// Removes the task without touching any resource.
	FinishTask(ctx context.Context, task *Task) error
	// Stores the challenge, authorization and order when every revision matches and removes the
	// task, all in one operation. The order revision advances even when its fields are unchanged.
	CompleteValidation(ctx context.Context, task *Task, challenge *Challenge, authz *Authorization, order *Order) error
	// Stores the order when its revision matches, creates the certificate when it is not nil
	// and removes the task, all in one operation. It returns ErrConflict when the certificate
	// ID is in use.
	CompleteIssuance(ctx context.Context, task *Task, order *Order, cert *Certificate) error
	// Counts tasks that were runnable at or before the given time and hold no lease past it.
	PendingTasks(ctx context.Context, before time.Time) (int, error)
}

// The persistence contract a host supplies. Operations must be free of side effects a retry
// would repeat.
type Store interface {
	AccountStore
	OrderStore
	CertificateStore
	WorkStore
}
