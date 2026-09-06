package acmeserver_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Worker settings that let a host call exhaust the task timeout well within a test.
func exhaustingWorkers() acmeserver.WorkerConfig {
	return acmeserver.WorkerConfig{
		Concurrency:  1,
		PollInterval: 2 * time.Millisecond,
		Lease:        40 * time.Millisecond,
		TaskTimeout:  20 * time.Millisecond,
		MaxAttempts:  3,
		RetryDelay:   time.Millisecond,
		StaleAfter:   time.Second,
	}
}

// A Validator that answers only once its context is done, like a destination that never replies.
type stallingValidator struct{ calls atomic.Int64 }

// Blocks until the deadline passes and reports a retryable transport failure.
func (v *stallingValidator) Validate(ctx context.Context, _ acmeserver.ValidationRequest) error {
	v.calls.Add(1)
	<-ctx.Done()
	return errors.New("validation transport failure")
}

// Requires a validator that consumes its whole deadline to stop at the attempt limit rather than
// being retried forever because the commit shared the exhausted deadline.
func TestValidationStopsAtTheAttemptLimitAfterTimeouts(t *testing.T) {
	validator := &stallingValidator{}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Validators = map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: validator}
		cfg.Workers = exhaustingWorkers()
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	orderURL, order := c.newOrder("stalled.test")
	c.respondHTTP01(order)
	order = c.waitOrder(orderURL, statusInvalid)
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	if authz.Status != statusInvalid || authz.Challenges[0].Status != statusInvalid {
		t.Fatalf("authorization is %q with challenge %q, want both invalid", authz.Status, authz.Challenges[0].Status)
	}
	if calls := validator.calls.Load(); calls != 3 {
		t.Fatalf("validator ran %d times, want the MaxAttempts limit of 3", calls)
	}
	if f.ca.callCount() != 0 {
		t.Fatal("the CA was called for an order whose validation failed")
	}
}

// An Issuer that refuses the order only once its context is done.
type stallingIssuer struct{ calls atomic.Int64 }

// Blocks until the deadline passes and then refuses the order for good.
func (i *stallingIssuer) Issue(ctx context.Context, _ acmeserver.IssueRequest) (acmeserver.IssueResult, error) {
	i.calls.Add(1)
	<-ctx.Done()
	return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier,
		"the CA refuses this name")}, nil
}

// Requires a definitive refusal that arrives after the task timeout to be recorded once, rather
// than leaving the order processing and asking the CA again.
func TestIssuanceRefusalIsRecordedAfterTimeouts(t *testing.T) {
	issuer := &stallingIssuer{}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Issuer = issuer
		cfg.Workers = exhaustingWorkers()
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	orderURL, order := c.newOrder("refused.test")
	c.respondHTTP01(order)
	order = c.waitOrder(orderURL, statusReady)
	if rec := c.finalize(order, newKey(t)); rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d %s", rec.Code, rec.Body.String())
	}
	order = c.waitOrder(orderURL, statusInvalid)
	if order.Error == nil || order.Error.Type != acmeserver.ErrorRejectedIdentifier {
		t.Fatalf("order error = %v, want the refusal from the CA", order.Error)
	}
	if calls := issuer.calls.Load(); calls != 1 {
		t.Fatalf("the CA was asked %d times after a final refusal, want 1", calls)
	}
}
