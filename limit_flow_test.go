package acmeserver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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

// Asks the limiter about challenge responses with the client address, the account, the identifier
// of the authorization as the order named it and the validations already in progress. A repeated
// response to a challenge that is already processing starts nothing and is not asked about.
func TestLimiterIsAskedAboutChallengeResponses(t *testing.T) {
	limits := &scriptedLimiter{}
	f := newFlow(t, func(c *acmeserver.Config) { c.Limits = limits })
	client := netip.MustParseAddr("192.0.2.1")
	c := f.newClient()
	c.register()
	// No worker runs, so every accepted validation stays in progress and counts for the next.
	_, order := c.newOrder("a.test", "*.b.test")
	var authz authzBody
	for i, want := range []acmeserver.Identifier{
		{Type: acmeserver.IdentifierDNS, Value: "a.test"},
		{Type: acmeserver.IdentifierDNS, Value: "*.b.test"},
	} {
		c.get(order.Authorizations[i], &authz)
		if rec := c.post(authz.Challenges[0].URL, map[string]any{}); rec.Code != http.StatusOK {
			t.Fatalf("response for %s = %d %s", want.Value, rec.Code, rec.Body.String())
		}
		responses := limits.take(acmeserver.LimitChallengeResponse)
		if len(responses) != 1 || responses[0].Client != client || responses[0].Account == nil ||
			responses[0].Account.ID != accountID(c) || len(responses[0].Identifiers) != 1 ||
			responses[0].Identifiers[0] != want || responses[0].PendingValidations != i {
			t.Fatalf("challenge response requests for %s = %+v", want.Value, responses)
		}
	}
	if rec := c.post(authz.Challenges[0].URL, map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("repeated response = %d %s", rec.Code, rec.Body.String())
	}
	if responses := limits.take(acmeserver.LimitChallengeResponse); len(responses) != 0 {
		t.Fatalf("a repeated response asked the limiter: %+v", responses)
	}
}

// Sends the limiter's problem with Retry-After. A refused newNonce request gets no nonce, while
// refused account and order requests get one as every ACME error does.
func TestLimiterRefusalsReachTheClient(t *testing.T) {
	limits := &scriptedLimiter{}
	f := newFlow(t, func(c *acmeserver.Config) { c.Limits = limits })
	c := f.newClient()
	assertLimited := func(rec *httptest.ResponseRecorder, nonce bool) {
		t.Helper()
		assertRefused(t, rec, nonce)
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

	limits.script(nil)
	_, order := c.newOrder("a.test")
	limits.script(limited(acmeserver.LimitChallengeResponse))
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	rec = c.post(authz.Challenges[0].URL, map[string]any{})
	assertLimited(rec, true)
	assertProblem(t, rec, http.StatusTooManyRequests, acmeserver.ErrorRateLimited)
	c.get(order.Authorizations[0], &authz)
	if authz.Challenges[0].Status != statusPending {
		t.Fatalf("challenge after a refused response is %q, want pending", authz.Challenges[0].Status)
	}
	if n, err := f.store.AccountValidations(t.Context(), accountID(c)); err != nil || n != 0 {
		t.Fatalf("a refused response enqueued a validation: %d, %v", n, err)
	}
}

// Returns the ID of the client's account from its URL.
func accountID(c *client) string {
	return strings.TrimPrefix(c.kid, baseURL+"acct/")
}

// Returns a scripted decision that refuses one kind with a 2.5 second Retry-After.
func limited(kind acmeserver.LimitKind) func(acmeserver.LimitRequest) error {
	return func(req acmeserver.LimitRequest) error {
		if req.Kind != kind {
			return nil
		}
		return acmeserver.NewProblem(acmeserver.ErrorRateLimited, "too many requests").WithRetryAfter(2500 * time.Millisecond)
	}
}

// Checks the answer to a request the limiter refused and whether it carries a nonce.
func assertRefused(t *testing.T, rec *httptest.ResponseRecorder, nonce bool) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "3" {
		t.Fatalf("limited answer = %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if got := rec.Header().Get("Replay-Nonce") != ""; got != nonce {
		t.Fatalf("limited answer carries a nonce: %v", got)
	}
}

// Asks the newNonce limiter before an error answer to a request that spent no nonce and omits
// the nonce when refused. A refused badNonce answer becomes the limiter's problem, since RFC 8555
// requires a nonce on badNonce. A request that spent its nonce gets its replacement without asking.
func TestErrorAnswersAskTheNonceLimiter(t *testing.T) {
	limits := &scriptedLimiter{}
	f := newFlow(t, func(c *acmeserver.Config) { c.Limits = limits })
	client := netip.MustParseAddr("192.0.2.1")
	c := f.newClient()
	c.register()
	newOrder := baseURL + "new-order"
	plain := func(method, url, contentType string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, url, strings.NewReader("{"))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		return f.do(r)
	}
	unspent := []struct {
		name   string
		send   func() *httptest.ResponseRecorder
		status int
		typ    acmeserver.ErrorType
	}{
		{"unknown resource", func() *httptest.ResponseRecorder { return plain(http.MethodGet, baseURL+"nothing", "") },
			http.StatusNotFound, acmeserver.ErrorMalformed},
		{"wrong method", func() *httptest.ResponseRecorder { return plain(http.MethodGet, newOrder, "") },
			http.StatusMethodNotAllowed, acmeserver.ErrorMalformed},
		{"wrong content type", func() *httptest.ResponseRecorder { return plain(http.MethodPost, newOrder, "text/plain") },
			http.StatusUnsupportedMediaType, acmeserver.ErrorMalformed},
		{"unparsable JWS", func() *httptest.ResponseRecorder { return plain(http.MethodPost, newOrder, "application/jose+json") },
			http.StatusBadRequest, acmeserver.ErrorMalformed},
		{"bad nonce", func() *httptest.ResponseRecorder {
			return c.send(newOrder, signECDSA(t, c.key, map[string]any{"nonce": "stale", "url": newOrder, "kid": c.kid}, []byte("{}")))
		}, http.StatusBadRequest, acmeserver.ErrorBadNonce},
	}
	spent := func() *httptest.ResponseRecorder {
		return c.send(newOrder, c.signed(newOrder, map[string]any{"identifiers": []map[string]string{}}))
	}

	limits.take(acmeserver.LimitNewNonce)
	for _, tc := range unspent {
		rec := tc.send()
		assertProblem(t, rec, tc.status, tc.typ)
		if rec.Header().Get("Replay-Nonce") == "" {
			t.Fatalf("%s: allowed answer carries no nonce", tc.name)
		}
		if asked := limits.take(acmeserver.LimitNewNonce); len(asked) != 1 || asked[0].Client != client || asked[0].Account != nil {
			t.Fatalf("%s: nonce requests = %+v", tc.name, asked)
		}
	}
	signed := c.signed(newOrder, map[string]any{"identifiers": []map[string]string{}})
	limits.take(acmeserver.LimitNewNonce)
	rec := spent()
	assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorMalformed)
	if rec.Header().Get("Replay-Nonce") == "" {
		t.Fatal("a failed signed request got no replacement nonce")
	}
	if asked := limits.take(acmeserver.LimitNewNonce); len(asked) != 1 {
		t.Fatalf("a failed signed request asked beyond its own newNonce: %+v", asked)
	}

	limits.script(limited(acmeserver.LimitNewNonce))
	for _, tc := range unspent {
		rec := tc.send()
		if tc.typ == acmeserver.ErrorBadNonce {
			assertRefused(t, rec, false)
			assertProblem(t, rec, http.StatusTooManyRequests, acmeserver.ErrorRateLimited)
			continue
		}
		assertProblem(t, rec, tc.status, tc.typ)
		if rec.Header().Get("Replay-Nonce") != "" || rec.Header().Get("Retry-After") != "" {
			t.Fatalf("%s: refused answer carries a nonce or Retry-After", tc.name)
		}
	}
	rec = c.send(newOrder, signed)
	assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorMalformed)
	if rec.Header().Get("Replay-Nonce") == "" {
		t.Fatal("a failed signed request got no replacement nonce while newNonce was refused")
	}
}

// Counts renewal lookups that reach the store.
type renewalCountingStore struct {
	acmeserver.Store
	lookups atomic.Int32
}

// Counts the lookup and forwards it.
func (s *renewalCountingStore) CertificateByRenewalID(ctx context.Context, id string) (*acmeserver.Certificate, error) {
	s.lookups.Add(1)
	return s.Store.CertificateByRenewalID(ctx, id)
}

// Asks the limiter about renewalInfo lookups with the client address before the store is read. A
// refused request gets the limiter's problem and no nonce. A malformed identifier is not asked about.
func TestLimiterIsAskedAboutRenewalInfo(t *testing.T) {
	limits := &scriptedLimiter{}
	store := &renewalCountingStore{}
	f := newFlow(t, func(c *acmeserver.Config) {
		c.Limits = limits
		c.RenewalInfo = acmeserver.LifetimeRenewal{}
		store.Store = c.Store
		c.Store = store
	})
	f.runWorker()
	client := netip.MustParseAddr("192.0.2.1")
	c := f.newClient()
	c.register()
	id := ariID(t, c.issue("a.test"))
	if asked := limits.take(acmeserver.LimitRenewalInfo); len(asked) != 0 {
		t.Fatalf("issuance asked about renewal information: %+v", asked)
	}

	if rec := f.renewalInfo(id); rec.Code != http.StatusOK {
		t.Fatalf("renewal-info = %d %s", rec.Code, rec.Body.String())
	}
	if asked := limits.take(acmeserver.LimitRenewalInfo); len(asked) != 1 || asked[0].Client != client || asked[0].Account != nil {
		t.Fatalf("renewal-info requests = %+v", asked)
	}
	assertProblem(t, f.renewalInfo("no-dot"), http.StatusNotFound, acmeserver.ErrorMalformed)
	if asked := limits.take(acmeserver.LimitRenewalInfo); len(asked) != 0 {
		t.Fatalf("a malformed identifier asked the limiter: %+v", asked)
	}
	if n := store.lookups.Load(); n != 1 {
		t.Fatalf("store lookups = %d, want 1", n)
	}

	limits.take(acmeserver.LimitNewNonce)
	limits.script(limited(acmeserver.LimitRenewalInfo))
	rec := f.renewalInfo(id)
	assertRefused(t, rec, false)
	assertProblem(t, rec, http.StatusTooManyRequests, acmeserver.ErrorRateLimited)
	if n := store.lookups.Load(); n != 1 {
		t.Fatalf("a refused request reached the store: %d lookups", n)
	}
	if asked := limits.take(acmeserver.LimitNewNonce); len(asked) != 0 {
		t.Fatalf("a refused renewal-info request asked about a nonce: %+v", asked)
	}
}

// Refuses a challenge response once the account has MaxPendingValidations validations waiting or
// running, with a Retry-After of the task timeout. It accepts the response again once they finish.
// Other accounts are not affected.
func TestChallengeResponsesAreBoundedPerAccount(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.MaxPendingValidations = 2 })
	// No worker runs yet, so accepted validations stay waiting and count against the bound.
	c := f.newClient()
	c.register()
	location, order := c.newOrder("a.test", "b.test", "c.test")
	var urls []string
	for _, authzURL := range order.Authorizations {
		var authz authzBody
		c.get(authzURL, &authz)
		for _, ch := range authz.Challenges {
			if ch.Type == typeHTTP01 {
				urls = append(urls, ch.URL)
			}
		}
	}
	for _, url := range urls[:2] {
		if rec := c.post(url, map[string]any{}); rec.Code != http.StatusOK {
			t.Fatalf("response within the bound = %d %s", rec.Code, rec.Body.String())
		}
	}
	rec := c.post(urls[2], map[string]any{})
	assertProblem(t, rec, http.StatusTooManyRequests, acmeserver.ErrorRateLimited)
	if rec.Header().Get("Retry-After") != "1" || rec.Header().Get("Replay-Nonce") == "" {
		t.Fatalf("refused response headers = %v", rec.Header())
	}
	if n, _ := f.store.AccountValidations(t.Context(), accountID(c)); n != 2 {
		t.Fatalf("validations after the refusal = %d, want 2", n)
	}
	other := f.newClient()
	other.register()
	_, otherOrder := other.newOrder("d.test")
	other.respondHTTP01(otherOrder)

	f.runWorker()
	waitFor(t, "earlier validations to finish", func() bool {
		n, _ := f.store.AccountValidations(t.Context(), accountID(c))
		return n == 0
	})
	if rec := c.post(urls[2], map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("response after the earlier validations finished = %d %s", rec.Code, rec.Body.String())
	}
	c.waitOrder(location, statusReady)
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
