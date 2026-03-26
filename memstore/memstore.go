// Package memstore provides an in-memory acmeserver.Store for tests and examples.
package memstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math/big"
	"slices"
	"sync"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// An in-memory Store. The zero value is not usable, call New.
type Store struct {
	mu           sync.RWMutex
	accounts     map[string]*acmeserver.Account
	accountByKey map[string]string
}

// Returns an empty Store.
func New() *Store {
	return &Store{accounts: make(map[string]*acmeserver.Account), accountByKey: make(map[string]string)}
}

// Stores a copy of the account with revision 1.
func (s *Store) CreateAccount(ctx context.Context, account *acmeserver.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if account.ID == "" || account.KeyThumbprint == "" {
		return errors.New("memstore: account needs an ID and a key thumbprint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[account.ID]; exists {
		return acmeserver.ErrConflict
	}
	if _, exists := s.accountByKey[account.KeyThumbprint]; exists {
		return acmeserver.ErrConflict
	}
	account.Revision = 1
	s.accounts[account.ID] = cloneAccount(account)
	s.accountByKey[account.KeyThumbprint] = account.ID
	return nil
}

// Returns a copy of the account with the given ID.
func (s *Store) Account(ctx context.Context, id string) (*acmeserver.Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	account, ok := s.accounts[id]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return cloneAccount(account), nil
}

// Returns a copy of the account whose key has the given thumbprint.
func (s *Store) AccountByKey(ctx context.Context, thumbprint string) (*acmeserver.Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.accountByKey[thumbprint]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return cloneAccount(s.accounts[id]), nil
}

// Replaces the stored account when the revision matches.
func (s *Store) UpdateAccount(ctx context.Context, account *acmeserver.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if account.KeyThumbprint == "" {
		return errors.New("memstore: account needs a key thumbprint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.accounts[account.ID]
	if !ok {
		return acmeserver.ErrNotFound
	}
	if stored.Revision != account.Revision {
		return acmeserver.ErrRevisionMismatch
	}
	if account.KeyThumbprint != stored.KeyThumbprint {
		if owner, exists := s.accountByKey[account.KeyThumbprint]; exists && owner != account.ID {
			return acmeserver.ErrConflict
		}
		delete(s.accountByKey, stored.KeyThumbprint)
		s.accountByKey[account.KeyThumbprint] = account.ID
	}
	account.Revision++
	s.accounts[account.ID] = cloneAccount(account)
	return nil
}

// Returns a copy that shares no mutable state with the original.
func cloneAccount(a *acmeserver.Account) *acmeserver.Account {
	c := *a
	c.Contact = slices.Clone(a.Contact)
	c.Key = clonePublicKey(a.Key)
	return &c
}

// Copies a public key so callers cannot mutate stored state through it.
func clonePublicKey(key crypto.PublicKey) crypto.PublicKey {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			return key
		}
		copied, err := ecdsa.ParseUncompressedPublicKey(k.Curve, point)
		if err != nil {
			return key
		}
		return copied
	case *rsa.PublicKey:
		return &rsa.PublicKey{N: new(big.Int).Set(k.N), E: k.E}
	case ed25519.PublicKey:
		return slices.Clone(k)
	default:
		return key
	}
}
