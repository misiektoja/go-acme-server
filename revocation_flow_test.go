package acmeserver_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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

// Revokes a P-521 certificate with the certificate key, which can only sign with ES512.
func TestRevocationByP521CertificateKey(t *testing.T) {
	f := newFlow(t, nil)
	f.runWorker()
	owner := f.newClient()
	owner.register()
	location, order := owner.newOrder("p521.test")
	owner.respondHTTP01(order)
	owner.waitOrder(location, statusReady)
	certKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	owner.finalize(order, certKey)
	valid := owner.waitOrder(location, statusValid)
	chain := parsePEMChain(t, owner.get(valid.Certificate, nil).Body.Bytes())
	payload, err := json.Marshal(map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(chain[0].Raw)})
	if err != nil {
		t.Fatal(err)
	}
	url := baseURL + "revoke-cert"
	header := map[string]any{"nonce": owner.nonce(), "url": url, "jwk": publicJWK(t, &certKey.PublicKey)}
	if rec := owner.send(url, signECDSA(t, certKey, header, payload)); rec.Code != http.StatusOK {
		t.Fatalf("revocation with the certificate key = %d %s", rec.Code, rec.Body.String())
	}
	stored, err := f.store.Certificate(t.Context(), valid.Certificate[len(baseURL+"cert/"):])
	if err != nil || !stored.Revoked {
		t.Fatalf("revocation not persisted: %+v, %v", stored, err)
	}
}

// A revoker that drops the client connection as soon as the CA has acted.
type disconnectingRevoker struct {
	cancel context.CancelFunc
	calls  atomic.Int64
}

// Records the call and cancels the request context the way a client disconnect would.
func (v *disconnectingRevoker) Revoke(_ context.Context, _ acmeserver.RevokeRequest) error {
	v.calls.Add(1)
	v.cancel()
	return nil
}

// Records the revocation even when the client disconnects before the CA answer is stored.
func TestRevocationSurvivesAClientDisconnect(t *testing.T) {
	revoker := &disconnectingRevoker{}
	f := newFlow(t, func(cfg *acmeserver.Config) { cfg.Revoker = revoker })
	f.runWorker()
	owner := f.newClient()
	owner.register()
	location, order := owner.newOrder("gone.test")
	owner.respondHTTP01(order)
	owner.waitOrder(location, statusReady)
	owner.finalize(order, newKey(t))
	valid := owner.waitOrder(location, statusValid)
	chain := parsePEMChain(t, owner.get(valid.Certificate, nil).Body.Bytes())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	revoker.cancel = cancel
	url := baseURL + "revoke-cert"
	body := owner.signed(url, map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(chain[0].Raw)})
	r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/jose+json")
	if rec := f.do(r); rec.Code != http.StatusOK {
		t.Fatalf("revocation = %d %s", rec.Code, rec.Body.String())
	}
	if n := revoker.calls.Load(); n != 1 {
		t.Fatalf("revoker called %d times", n)
	}
	stored, err := f.store.Certificate(t.Context(), valid.Certificate[len(baseURL+"cert/"):])
	if err != nil || !stored.Revoked {
		t.Fatalf("revocation not persisted: %+v, %v", stored, err)
	}
}

// A store whose revocation write waits for its context, so only its deadline ends it.
type stallingRevocationStore struct {
	acmeserver.Store
}

// Blocks the write that marks a certificate revoked until its context ends.
func (s *stallingRevocationStore) UpdateCertificate(ctx context.Context, cert *acmeserver.Certificate) error {
	if !cert.Revoked {
		return s.Store.UpdateCertificate(ctx, cert)
	}
	<-ctx.Done()
	return ctx.Err()
}

// Bounds the detached revocation write with Config.DetachedWriteTimeout.
func TestRevocationWriteHonorsTheDetachedTimeout(t *testing.T) {
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Store = &stallingRevocationStore{Store: cfg.Store}
		cfg.DetachedWriteTimeout = 20 * time.Millisecond
	})
	f.runWorker()
	owner := f.newClient()
	owner.register()
	location, order := owner.newOrder("stall.test")
	owner.respondHTTP01(order)
	owner.waitOrder(location, statusReady)
	owner.finalize(order, newKey(t))
	valid := owner.waitOrder(location, statusValid)
	chain := parsePEMChain(t, owner.get(valid.Certificate, nil).Body.Bytes())
	payload := map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(chain[0].Raw)}
	start := time.Now()
	rec := owner.post(baseURL+"revoke-cert", payload)
	assertProblem(t, rec, http.StatusInternalServerError, acmeserver.ErrorServerInternal)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the revocation write took %v, so the configured timeout was not used", elapsed)
	}
}
