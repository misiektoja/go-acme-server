package nonce_test

import (
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/nonce"
	"github.com/misiektoja/go-acme-server/noncetest"
)

// Runs the nonce manager contract against the single-process manager. It has no shared state, so
// RunShared does not apply.
func TestContract(t *testing.T) {
	noncetest.Run(t, func(*testing.T) acmeserver.NonceManager { return nonce.New(nonce.Options{}) })
}
