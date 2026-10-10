package acmeserver_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// A validator that reports each call and accepts the response once released.
type gateValidator struct {
	entered chan acmeserver.ChallengeType
	release chan struct{}
}

// Signals entry and waits for the release or the end of the task phase.
func (g gateValidator) Validate(ctx context.Context, req acmeserver.ValidationRequest) error {
	g.entered <- req.Challenge.Type
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Waits for n validator calls to start.
func (g gateValidator) wait(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-g.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("validation did not start")
		}
	}
}

// Settles both challenges of an authorization when their validations finish at the same time.
func TestConcurrentValidationsSettleEveryChallenge(t *testing.T) {
	gate := gateValidator{entered: make(chan acmeserver.ChallengeType, 2), release: make(chan struct{})}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Validators = map[acmeserver.ChallengeType]acmeserver.Validator{
			acmeserver.ChallengeHTTP01: gate,
			acmeserver.ChallengeDNS01:  gate,
		}
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("race.test")
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	if len(authz.Challenges) != 2 {
		t.Fatalf("authorization = %+v", authz)
	}
	for _, ch := range authz.Challenges {
		if rec := c.post(ch.URL, map[string]any{}); rec.Code != http.StatusOK {
			t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
		}
	}
	gate.wait(t, 2)
	close(gate.release)
	c.waitOrder(location, statusReady)
	// A valid authorization lists only the challenge that proved it, so each one is read directly.
	settled := make([]challengeBody, len(authz.Challenges))
	waitFor(t, "every challenge to settle", func() bool {
		for i, ch := range authz.Challenges {
			c.get(ch.URL, &settled[i])
			if settled[i].Status == statusProcessing {
				return false
			}
		}
		return true
	})
	// The first commit proves the authorization and the other challenge settles as invalid.
	valid := 0
	for _, ch := range settled {
		switch {
		case ch.Status == statusValid:
			valid++
		case ch.Status != statusInvalid || ch.Error == nil || ch.Error.Type != acmeserver.ErrorMalformed:
			t.Fatalf("challenge after the race = %+v", ch)
		}
	}
	c.get(order.Authorizations[0], &authz)
	if authz.Status != statusValid || valid != 1 {
		t.Fatalf("authorization after the race = %+v, challenges %+v", authz, settled)
	}
}

// Settles a challenge whose authorization was deactivated while its validation ran.
func TestDeactivationDuringValidationSettlesTheChallenge(t *testing.T) {
	gate := gateValidator{entered: make(chan acmeserver.ChallengeType, 1), release: make(chan struct{})}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Validators = map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: gate}
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("deactivated.test")
	ch := c.firstHTTP01(order)
	if rec := c.post(ch.URL, map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
	}
	gate.wait(t, 1)
	if rec := c.post(order.Authorizations[0], map[string]any{"status": "deactivated"}); rec.Code != http.StatusOK {
		t.Fatalf("deactivate = %d %s", rec.Code, rec.Body.String())
	}
	close(gate.release)
	var current challengeBody
	waitFor(t, "the challenge to settle", func() bool {
		c.get(ch.URL, &current)
		return current.Status != statusProcessing
	})
	if current.Status != statusInvalid || current.Error == nil || !strings.Contains(current.Error.Detail, "deactivated") {
		t.Fatalf("challenge after deactivation = %+v", current)
	}
	c.waitOrder(location, statusInvalid)
}
