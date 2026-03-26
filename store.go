package acmeserver

import (
	"context"
	"errors"
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

// The persistence contract a host supplies. Operations must be free of side effects a retry
// would repeat.
type Store interface {
	AccountStore
}
