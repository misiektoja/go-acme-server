package acmeserver

import "context"

// Issues and consumes the single-use nonces that protect requests against replay.
type NonceManager interface {
	// Returns a fresh nonce in base64url form.
	Issue(ctx context.Context) (string, error)
	// Invalidates the nonce and reports whether it was valid. A nonce is valid exactly once.
	Consume(ctx context.Context, nonce string) (bool, error)
}
