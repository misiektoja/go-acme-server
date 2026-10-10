package acmeserver_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// A store whose first challenge acceptance reports a revision mismatch, optionally after a competing
// response for the same challenge was stored.
type racingAcceptStore struct {
	acmeserver.Store
	competitor bool
	calls      atomic.Int64
}

// Fails the first acceptance with ErrRevisionMismatch and passes later ones through.
func (s *racingAcceptStore) AcceptChallenge(ctx context.Context, challenge *acmeserver.Challenge, task *acmeserver.Task) error {
	if s.calls.Add(1) > 1 {
		return s.Store.AcceptChallenge(ctx, challenge, task)
	}
	if s.competitor {
		won, competing := *challenge, *task
		competing.ID += "-competitor"
		if err := s.Store.AcceptChallenge(ctx, &won, &competing); err != nil {
			return err
		}
	}
	return acmeserver.ErrRevisionMismatch
}

// Returns the http-01 challenge of the order's first authorization.
func (c *client) firstHTTP01(order orderBody) challengeBody {
	c.f.t.Helper()
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	for _, ch := range authz.Challenges {
		if ch.Type == typeHTTP01 {
			return ch
		}
	}
	c.f.t.Fatalf("no http-01 challenge in %+v", authz)
	return challengeBody{}
}

// Answers a response that lost the race to a concurrent one with the challenge the winner stored.
func TestChallengeResponseLosingARace(t *testing.T) {
	store := &racingAcceptStore{competitor: true}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		store.Store = cfg.Store
		cfg.Store = store
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("race.test")
	ch := c.firstHTTP01(order)
	rec := c.post(ch.URL, map[string]any{})
	var answered challengeBody
	decode(t, rec, &answered)
	if rec.Code != http.StatusOK || answered.Status == "pending" {
		t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
	}
	c.waitOrder(location, statusReady)
}

// Refuses a response the store did not record instead of answering with the pending challenge.
func TestChallengeResponseNotStored(t *testing.T) {
	store := &racingAcceptStore{}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		store.Store = cfg.Store
		cfg.Store = store
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("lost.test")
	ch := c.firstHTTP01(order)
	assertProblem(t, c.post(ch.URL, map[string]any{}), http.StatusInternalServerError, acmeserver.ErrorServerInternal)
	if !strings.Contains(f.logs.String(), "challenge update failed") {
		t.Fatalf("the lost response was not logged: %s", f.logs.String())
	}
	var current challengeBody
	c.get(ch.URL, &current)
	if current.Status != "pending" {
		t.Fatalf("challenge after the refused response = %+v", current)
	}
	// The client can respond again once the store records the response.
	if rec := c.post(ch.URL, map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("second challenge response = %d %s", rec.Code, rec.Body.String())
	}
	c.waitOrder(location, statusReady)
}
