package acmeserver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// A Limiter that remembers every request and answers with a scripted decision.
type scriptedLimiter struct {
	mu       sync.Mutex
	requests []acmeserver.LimitRequest
	decide   func(acmeserver.LimitRequest) error
}

// Records the request and returns the scripted decision.
func (l *scriptedLimiter) Allow(_ context.Context, req acmeserver.LimitRequest) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests = append(l.requests, req)
	if l.decide == nil {
		return nil
	}
	return l.decide(req)
}

// Returns the requests of one kind asked since they were last taken.
func (l *scriptedLimiter) take(kind acmeserver.LimitKind) []acmeserver.LimitRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	var taken, kept []acmeserver.LimitRequest
	for _, req := range l.requests {
		if req.Kind == kind {
			taken = append(taken, req)
		} else {
			kept = append(kept, req)
		}
	}
	l.requests = kept
	return taken
}

// Sets the scripted decision.
func (l *scriptedLimiter) script(decide func(acmeserver.LimitRequest) error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.decide = decide
}

// Asks the limiter about nonces, new accounts and new orders with the client address, the
// account, the normalized identifiers and a checked replaces member.
func TestLimiterIsAskedAboutNoncesAccountsAndOrders(t *testing.T) {
	limits := &scriptedLimiter{}
	f := newFlow(t, func(c *acmeserver.Config) {
		c.Limits = limits
		c.RenewalInfo = acmeserver.LifetimeRenewal{}
	})
	f.runWorker()
	client := netip.MustParseAddr("192.0.2.1")

	c := f.newClient()
	kid := c.register()
	nonces := limits.take(acmeserver.LimitNewNonce)
	if len(nonces) != 1 || nonces[0].Client != client || nonces[0].Account != nil {
		t.Fatalf("nonce requests = %+v", nonces)
	}
	accounts := limits.take(acmeserver.LimitNewAccount)
	if len(accounts) != 1 || accounts[0].Client != client || accounts[0].Account == nil ||
		!strings.HasSuffix(kid, "/"+accounts[0].Account.ID) || len(accounts[0].Account.Contact) != 1 {
		t.Fatalf("account requests = %+v", accounts)
	}
	existing := c.postRaw(baseURL+"new-account", []byte(`{"termsOfServiceAgreed":true}`), true)
	if existing.Code != http.StatusOK || len(limits.take(acmeserver.LimitNewAccount)) != 0 {
		t.Fatalf("lookup of an existing account = %d, asked the limiter", existing.Code)
	}

	leaf := c.issue("A.Test")
	orders := limits.take(acmeserver.LimitNewOrder)
	want := []acmeserver.Identifier{{Type: acmeserver.IdentifierDNS, Value: "a.test"}}
	if len(orders) != 1 || orders[0].Client != client || orders[0].Account == nil || orders[0].Account.ID != accounts[0].Account.ID ||
		len(orders[0].Identifiers) != 1 || orders[0].Identifiers[0] != want[0] || orders[0].Replaces != "" {
		t.Fatalf("order requests = %+v", orders)
	}
	id := ariID(t, leaf)
	if rec := c.replacingOrder(id, "a.test"); rec.Code != http.StatusCreated {
		t.Fatalf("replacing order = %d %s", rec.Code, rec.Body.String())
	}
	if orders := limits.take(acmeserver.LimitNewOrder); len(orders) != 1 || orders[0].Replaces != id {
		t.Fatalf("replacing order requests = %+v", orders)
	}
	// An order refused before the limiter is asked does not count.
	assertProblem(t, c.replacingOrder("unknown.serial", "a.test"), http.StatusBadRequest, acmeserver.ErrorMalformed)
	if orders := limits.take(acmeserver.LimitNewOrder); len(orders) != 0 {
		t.Fatalf("refused order asked the limiter: %+v", orders)
	}
}

// Sends the limiter's problem with Retry-After. A refused newNonce request gets no nonce, while
// refused account and order requests get one as every ACME error does.
func TestLimiterRefusalsReachTheClient(t *testing.T) {
	limits := &scriptedLimiter{}
	f := newFlow(t, func(c *acmeserver.Config) { c.Limits = limits })
	c := f.newClient()
	limited := func(kind acmeserver.LimitKind) func(acmeserver.LimitRequest) error {
		return func(req acmeserver.LimitRequest) error {
			if req.Kind != kind {
				return nil
			}
			return acmeserver.NewProblem(acmeserver.ErrorRateLimited, "too many requests").WithRetryAfter(2500 * time.Millisecond)
		}
	}
	assertLimited := func(rec *httptest.ResponseRecorder, nonce bool) {
		t.Helper()
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "3" {
			t.Fatalf("limited answer = %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
		}
		if got := rec.Header().Get("Replay-Nonce") != ""; got != nonce {
			t.Fatalf("limited answer carries a nonce: %v", got)
		}
	}

	limits.script(limited(acmeserver.LimitNewNonce))
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		assertLimited(f.do(httptest.NewRequest(method, baseURL+"new-nonce", nil)), false)
	}
	limits.script(limited(acmeserver.LimitNewAccount))
	rec := c.post(baseURL+"new-account", map[string]any{"termsOfServiceAgreed": true})
	assertLimited(rec, true)
	assertProblem(t, rec, http.StatusTooManyRequests, acmeserver.ErrorRateLimited)
	assertProblem(t, c.post(baseURL+"new-account", map[string]any{"onlyReturnExisting": true}),
		http.StatusBadRequest, acmeserver.ErrorAccountDoesNotExist)

	limits.script(nil)
	c.register()
	limits.script(limited(acmeserver.LimitNewOrder))
	rec = c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "a.test"}}})
	assertLimited(rec, true)
	var orders struct {
		Orders []string `json:"orders"`
	}
	var account struct {
		Orders string `json:"orders"`
	}
	c.get(c.kid, &account)
	c.get(account.Orders, &orders)
	if len(orders.Orders) != 0 {
		t.Fatalf("a refused order was stored: %v", orders.Orders)
	}
}

// Answers serverInternal and logs the cause when the limiter fails with an error that is not a
// problem.
func TestLimiterFailureIsServerInternal(t *testing.T) {
	limits := &scriptedLimiter{}
	limits.script(func(acmeserver.LimitRequest) error { return errors.New("limit store unavailable") })
	f := newFlow(t, func(c *acmeserver.Config) { c.Limits = limits })
	assertProblem(t, f.do(httptest.NewRequest(http.MethodGet, baseURL+"new-nonce", nil)),
		http.StatusInternalServerError, acmeserver.ErrorServerInternal)
	if !strings.Contains(f.logs.String(), "rate limit check failed") || !strings.Contains(f.logs.String(), "limit store unavailable") {
		t.Fatalf("logs = %s", f.logs.String())
	}
}

// Takes the client address from RemoteAddr, unmaps IPv4-mapped addresses and ignores forwarded
// headers.
func TestLimiterClientAddress(t *testing.T) {
	limits := &scriptedLimiter{}
	f := newFlow(t, func(c *acmeserver.Config) { c.Limits = limits })
	for remote, want := range map[string]netip.Addr{
		"[::ffff:198.51.100.7]:443": netip.MustParseAddr("198.51.100.7"),
		"[2001:db8::1]:443":         netip.MustParseAddr("2001:db8::1"),
		"203.0.113.9":               netip.MustParseAddr("203.0.113.9"),
		"@":                         {},
	} {
		r := httptest.NewRequest(http.MethodHead, baseURL+"new-nonce", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "192.0.2.200")
		r.Header.Set("Forwarded", "for=192.0.2.200")
		if rec := f.do(r); rec.Code != http.StatusOK {
			t.Fatalf("new-nonce from %q = %d", remote, rec.Code)
		}
		if got := limits.take(acmeserver.LimitNewNonce); len(got) != 1 || got[0].Client != want {
			t.Errorf("client of %q = %+v, want %v", remote, got, want)
		}
	}
}
