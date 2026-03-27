package acmeserver

import (
	"context"
	"errors"
)

// An Issuer that fails every call. Flow tests live in the external test package.
type stubIssuer struct{}

// Fails.
func (stubIssuer) Issue(context.Context, IssueRequest) (IssueResult, error) {
	return IssueResult{}, errors.New("stub issuer")
}

// A Revoker that fails every call.
type stubRevoker struct{}

// Fails.
func (stubRevoker) Revoke(context.Context, RevokeRequest) error { return errors.New("stub revoker") }

// A Validator that accepts every challenge.
type stubValidator struct{}

// Accepts.
func (stubValidator) Validate(context.Context, ValidationRequest) error { return nil }

// Returns a Config with stub dependencies over the given store and nonce manager.
func stubConfig(store Store, nonces NonceManager) Config {
	return Config{
		BaseURL:          testBaseURL,
		Store:            store,
		Nonces:           nonces,
		Issuer:           stubIssuer{},
		Revoker:          stubRevoker{},
		Validators:       map[ChallengeType]Validator{ChallengeHTTP01: stubValidator{}},
		ExternalAccounts: stubEABKeys{},
	}
}

// An ExternalAccountKeys that knows no key.
type stubEABKeys struct{}

// Reports every key as unknown.
func (stubEABKeys) MACKey(context.Context, string) ([]byte, error) { return nil, ErrNotFound }
