package acmeserver

import (
	"context"
	"sync"
)

// A minimal in-memory account store for white-box tests.
type testStore struct {
	mu       sync.Mutex
	accounts map[string]*Account
	byKey    map[string]string
}

// Returns an empty test store.
func newTestStore() *testStore {
	return &testStore{accounts: map[string]*Account{}, byKey: map[string]string{}}
}

// Stores a copy of account with revision 1.
func (s *testStore) CreateAccount(ctx context.Context, account *Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[account.ID]; ok {
		return ErrConflict
	}
	if _, ok := s.byKey[account.KeyThumbprint]; ok {
		return ErrConflict
	}
	account.Revision = 1
	stored := *account
	s.accounts[account.ID] = &stored
	s.byKey[account.KeyThumbprint] = account.ID
	return nil
}

// Returns a copy of the account with the given ID.
func (s *testStore) Account(ctx context.Context, id string) (*Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	account := *stored
	return &account, nil
}

// Returns a copy of the account owning the key thumbprint.
func (s *testStore) AccountByKey(ctx context.Context, thumbprint string) (*Account, error) {
	s.mu.Lock()
	id, ok := s.byKey[thumbprint]
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return s.Account(ctx, id)
}

// Replaces the stored account when the revision matches.
func (s *testStore) UpdateAccount(ctx context.Context, account *Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.accounts[account.ID]
	if !ok {
		return ErrNotFound
	}
	if stored.Revision != account.Revision {
		return ErrRevisionMismatch
	}
	account.Revision++
	updated := *account
	delete(s.byKey, stored.KeyThumbprint)
	s.accounts[account.ID] = &updated
	s.byKey[account.KeyThumbprint] = account.ID
	return nil
}
