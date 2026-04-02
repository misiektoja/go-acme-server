package acmeserver_test

import (
	"encoding/base64"
	"net/http"
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Requires current proof of every identifier before another account can revoke a certificate.
func TestRevocationByAuthorizedAccount(t *testing.T) {
	f := newFlow(t, nil)
	f.runWorker()
	owner := f.newClient()
	owner.register()
	location, order := owner.newOrder("a.test", "b.test")
	owner.respondHTTP01(order)
	owner.waitOrder(location, statusReady)
	owner.finalize(order, newKey(t))
	valid := owner.waitOrder(location, statusValid)
	chain := parsePEMChain(t, owner.get(valid.Certificate, nil).Body.Bytes())
	payload := map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(chain[0].Raw)}
	other := f.newClient()
	other.register()
	location, proof := other.newOrder("a.test")
	other.respondHTTP01(proof)
	other.waitOrder(location, statusReady)
	assertProblem(t, other.post(baseURL+"revoke-cert", payload), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	location, proof = other.newOrder("b.test")
	other.respondHTTP01(proof)
	other.waitOrder(location, statusReady)
	if rec := other.post(baseURL+"revoke-cert", payload); rec.Code != http.StatusOK {
		t.Fatalf("authorized revocation = %d %s", rec.Code, rec.Body.String())
	}
	stored, err := f.store.Certificate(t.Context(), valid.Certificate[len(baseURL+"cert/"):])
	if err != nil || !stored.Revoked {
		t.Fatalf("revocation not persisted: %+v, %v", stored, err)
	}
	if len(f.revoker.requests) != 1 {
		t.Fatalf("revoker called %d times", len(f.revoker.requests))
	}
}
