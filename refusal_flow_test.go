package acmeserver_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// A RefusalRecorder that remembers every refusal and can be scripted to fail.
type recordingRefusals struct {
	mu       sync.Mutex
	refusals []acmeserver.Refusal
	err      error
}

// Records the refusal and returns the scripted error.
func (r *recordingRefusals) RecordRefusal(_ context.Context, refusal acmeserver.Refusal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refusals = append(r.refusals, refusal)
	return r.err
}

// Returns the refusals recorded since the last call.
func (r *recordingRefusals) take() []acmeserver.Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	taken := r.refusals
	r.refusals = nil
	return taken
}

// Requires exactly one recorded refusal of the kind and problem type and returns it.
func requireRefusal(t *testing.T, r *recordingRefusals, kind acmeserver.RefusalKind, typ acmeserver.ErrorType) acmeserver.Refusal {
	t.Helper()
	got := r.take()
	if len(got) != 1 || got[0].Kind != kind || got[0].Problem == nil || got[0].Problem.Type != typ {
		t.Fatalf("refusals = %+v, want one %s refusal with %s", got, kind, typ)
	}
	return got[0]
}

// Issues a certificate for the names to a new account and returns the account and the DER leaf.
func issueFor(t *testing.T, f *flow, names ...string) (*client, []byte) {
	t.Helper()
	owner := f.newClient()
	owner.register()
	location, order := owner.newOrder(names...)
	owner.respondHTTP01(order)
	owner.waitOrder(location, statusReady)
	owner.finalize(order, newKey(t))
	valid := owner.waitOrder(location, statusValid)
	return owner, parsePEMChain(t, owner.get(valid.Certificate, nil).Body.Bytes())[0].Raw
}

// Reports every revocation refused after authentication with the requester, certificate, reason
// and problem, and leaves out server faults and the requests that succeed.
func TestRefusedRevocationsAreReported(t *testing.T) {
	refusals := &recordingRefusals{}
	f := newFlow(t, func(c *acmeserver.Config) { c.Refusals = refusals })
	f.runWorker()
	owner, leaf := issueFor(t, f, "refused.test")
	encoded := base64.RawURLEncoding.EncodeToString(leaf)
	if len(refusals.take()) != 0 {
		t.Fatal("issuance reported a refusal")
	}

	other := f.newClient()
	other.register()
	assertProblem(t, other.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded, "reason": 4}),
		http.StatusForbidden, acmeserver.ErrorUnauthorized)
	got := requireRefusal(t, refusals, acmeserver.RefusalRevocation, acmeserver.ErrorUnauthorized)
	if got.AccountID != other.kid[len(baseURL+"acct/"):] || !bytes.Equal(got.Certificate, leaf) || got.Reason != 4 ||
		got.OrderID != "" || got.CSR != nil {
		t.Fatalf("refusal of another account = %+v", got)
	}

	stranger := f.newClient()
	assertProblem(t, stranger.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded}),
		http.StatusForbidden, acmeserver.ErrorUnauthorized)
	if got := requireRefusal(t, refusals, acmeserver.RefusalRevocation, acmeserver.ErrorUnauthorized); got.AccountID != "" {
		t.Fatalf("refusal of a foreign key names account %q", got.AccountID)
	}

	rec := owner.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded, "reason": 6})
	assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorBadRevocationReason)
	if !strings.Contains(rec.Body.String(), "unspecified (0), keyCompromise (1), affiliationChanged (3), "+
		"superseded (4) and cessationOfOperation (5)") {
		t.Fatalf("bad reason detail does not name the allowed reasons: %s", rec.Body.String())
	}
	if got := requireRefusal(t, refusals, acmeserver.RefusalRevocation, acmeserver.ErrorBadRevocationReason); got.Reason != 6 {
		t.Fatalf("refused reason = %d", got.Reason)
	}

	assertProblem(t, owner.post(baseURL+"revoke-cert", map[string]any{"certificate": "AAAA"}),
		http.StatusBadRequest, acmeserver.ErrorMalformed)
	if got := requireRefusal(t, refusals, acmeserver.RefusalRevocation, acmeserver.ErrorMalformed); !bytes.Equal(got.Certificate, []byte{0, 0, 0}) {
		t.Fatalf("unparsable certificate = %x", got.Certificate)
	}

	f.revoker.err = acmeserver.NewProblem(acmeserver.ErrorUnauthorized, "the CA refused")
	assertProblem(t, owner.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded}),
		http.StatusForbidden, acmeserver.ErrorUnauthorized)
	if got := requireRefusal(t, refusals, acmeserver.RefusalRevocation, acmeserver.ErrorUnauthorized); got.Problem.Detail != "the CA refused" {
		t.Fatalf("revoker refusal = %+v", got.Problem)
	}

	f.revoker.err = errTransient
	assertProblem(t, owner.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded}),
		http.StatusInternalServerError, acmeserver.ErrorServerInternal)
	if got := refusals.take(); len(got) != 0 {
		t.Fatalf("a server fault was reported as a refusal: %+v", got)
	}

	f.revoker.err = nil
	if rec := owner.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded}); rec.Code != http.StatusOK {
		t.Fatalf("revocation = %d %s", rec.Code, rec.Body.String())
	}
	if got := refusals.take(); len(got) != 0 {
		t.Fatalf("a successful revocation was reported as a refusal: %+v", got)
	}
	assertProblem(t, owner.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded}),
		http.StatusBadRequest, acmeserver.ErrorAlreadyRevoked)
	requireRefusal(t, refusals, acmeserver.RefusalRevocation, acmeserver.ErrorAlreadyRevoked)
}

// Reports finalize requests refused after the order was found with the order, its identifiers and
// the CSR, and leaves out requests for another account's order.
func TestRefusedFinalizationsAreReported(t *testing.T) {
	refusals := &recordingRefusals{}
	f := newFlow(t, func(c *acmeserver.Config) { c.Refusals = refusals })
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("a.test", "b.test")
	orderID := location[len(baseURL+"order/"):]

	assertProblem(t, c.finalize(order, newKey(t)), http.StatusForbidden, acmeserver.ErrorOrderNotReady)
	got := requireRefusal(t, refusals, acmeserver.RefusalFinalize, acmeserver.ErrorOrderNotReady)
	if got.AccountID != c.kid[len(baseURL+"acct/"):] || got.OrderID != orderID || len(got.Identifiers) != 2 ||
		got.Identifiers[0].Value != "a.test" || len(got.CSR) == 0 || got.Certificate != nil {
		t.Fatalf("refusal of a pending order = %+v", got)
	}

	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	csr := makeCSR(t, newKey(t), []string{"a.test", "c.test"}, nil)
	assertProblem(t, c.finalizeCSR(order, csr), http.StatusBadRequest, acmeserver.ErrorBadCSR)
	if got := requireRefusal(t, refusals, acmeserver.RefusalFinalize, acmeserver.ErrorBadCSR); !bytes.Equal(got.CSR, csr) {
		t.Fatal("the refused CSR was not reported")
	}

	assertProblem(t, c.post(order.Finalize, map[string]string{"csr": "!"}), http.StatusBadRequest, acmeserver.ErrorMalformed)
	if got := requireRefusal(t, refusals, acmeserver.RefusalFinalize, acmeserver.ErrorMalformed); got.CSR != nil {
		t.Fatalf("an undecodable CSR was reported as %x", got.CSR)
	}

	other := f.newClient()
	other.register()
	assertProblem(t, other.finalize(order, newKey(t)), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	if got := refusals.take(); len(got) != 0 {
		t.Fatalf("a request for another account's order was reported: %+v", got)
	}

	if rec := c.finalize(order, newKey(t)); rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d %s", rec.Code, rec.Body.String())
	}
	c.waitOrder(location, statusValid)
	if got := refusals.take(); len(got) != 0 {
		t.Fatalf("a successful finalization was reported as a refusal: %+v", got)
	}
}

// Logs a refusal the recorder could not keep and still sends the client the same answer.
func TestRefusalRecorderFailureKeepsTheAnswer(t *testing.T) {
	refusals := &recordingRefusals{err: errors.New("audit log unavailable")}
	f := newFlow(t, func(c *acmeserver.Config) { c.Refusals = refusals })
	f.runWorker()
	owner, leaf := issueFor(t, f, "logged.test")
	assertProblem(t, owner.post(baseURL+"revoke-cert", map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(leaf), "reason": 2}),
		http.StatusBadRequest, acmeserver.ErrorBadRevocationReason)
	requireRefusal(t, refusals, acmeserver.RefusalRevocation, acmeserver.ErrorBadRevocationReason)
	if !strings.Contains(f.logs.String(), "refusal could not be recorded") || !strings.Contains(f.logs.String(), "audit log unavailable") {
		t.Fatalf("the recorder failure was not logged: %s", f.logs.String())
	}
}

// Accepts the configured privilegeWithdrawn reason, passes it to the Revoker and names it among
// the allowed reasons when another is refused.
func TestConfiguredRevocationReasons(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.RevocationReasons = []int{0, 1, 3, 4, 5, 9} })
	f.runWorker()
	owner, leaf := issueFor(t, f, "withdrawn.test")
	encoded := base64.RawURLEncoding.EncodeToString(leaf)
	rec := owner.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded, "reason": 10})
	assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorBadRevocationReason)
	if !strings.Contains(rec.Body.String(), "cessationOfOperation (5) and privilegeWithdrawn (9)") {
		t.Fatalf("bad reason detail = %s", rec.Body.String())
	}
	if rec := owner.post(baseURL+"revoke-cert", map[string]any{"certificate": encoded, "reason": 9}); rec.Code != http.StatusOK {
		t.Fatalf("privilegeWithdrawn revocation = %d %s", rec.Code, rec.Body.String())
	}
	if len(f.revoker.requests) != 1 || f.revoker.requests[0].Reason != 9 {
		t.Fatalf("revoker requests = %+v", f.revoker.requests)
	}
}
