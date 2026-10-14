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

// A Validator whose destination never accepts a connection.
type refusingValidator struct{}

// Reports a retryable connection failure.
func (refusingValidator) Validate(context.Context, acmeserver.ValidationRequest) error {
	return acmeserver.Retryable(acmeserver.NewProblem(acmeserver.ErrorConnection, "connection refused"),
		errors.New("dial tcp: connection refused"))
}

// Requires the problem a retryable failure names, rather than serverInternal, once the attempts
// run out.
func TestRetryableValidationReportsItsProblem(t *testing.T) {
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Validators = map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: refusingValidator{}}
		cfg.Workers = exhaustingWorkers()
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	orderURL, order := c.newOrder("refused.test")
	c.respondHTTP01(order)
	order = c.waitOrder(orderURL, statusInvalid)
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	if problem := authz.Challenges[0].Error; problem == nil || problem.Type != acmeserver.ErrorConnection {
		t.Fatalf("challenge error = %+v, want a connection problem", problem)
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

// A store whose account lookups by the worker outlast their deadline, as a store that ignores its
// context would, and which records the lease end of the latest claim.
type slowAccountStore struct {
	acmeserver.Store
	delay      time.Duration
	leaseUntil atomic.Int64
}

// Records the lease end the worker asked for.
func (s *slowAccountStore) ClaimTask(ctx context.Context, now, leaseUntil time.Time) (*acmeserver.Task, error) {
	task, err := s.Store.ClaimTask(ctx, now, leaseUntil)
	if err == nil {
		s.leaseUntil.Store(leaseUntil.UnixNano())
	}
	return task, err
}

// Delays lookups made under a deadline and completes them regardless of it.
func (s *slowAccountStore) Account(ctx context.Context, id string) (*acmeserver.Account, error) {
	if _, ok := ctx.Deadline(); ok {
		time.Sleep(s.delay)
		ctx = context.WithoutCancel(ctx)
	}
	return s.Store.Account(ctx, id)
}

// A Validator that records the deadline of its context and the lease of the run calling it.
type deadlineValidator struct {
	store              *slowAccountStore
	deadline, leaseEnd atomic.Int64
}

// Records the deadline and accepts the response.
func (v *deadlineValidator) Validate(ctx context.Context, _ acmeserver.ValidationRequest) error {
	deadline, _ := ctx.Deadline()
	v.deadline.Store(deadline.UnixNano())
	v.leaseEnd.Store(v.store.leaseUntil.Load())
	return nil
}

// Requires a host call to end with the lease when earlier phases of the run were slow, so it cannot
// overlap a run that claims the task once the lease has expired.
func TestTaskRunEndsWithItsLease(t *testing.T) {
	store := &slowAccountStore{delay: 150 * time.Millisecond}
	validator := &deadlineValidator{store: store}
	f := newFlow(t, func(c *acmeserver.Config) {
		store.Store = c.Store
		c.Store = store
		c.Validators = map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: validator}
		c.Workers = exhaustingWorkers()
		c.Workers.Lease, c.Workers.TaskTimeout = 200*time.Millisecond, 100*time.Millisecond
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("lease.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	deadline, leaseEnd := time.Unix(0, validator.deadline.Load()), time.Unix(0, validator.leaseEnd.Load())
	if validator.deadline.Load() == 0 || deadline.After(leaseEnd) {
		t.Fatalf("validator deadline %s is after the lease end %s", deadline.Format(time.StampMicro), leaseEnd.Format(time.StampMicro))
	}
}

// A Validator that refuses the first connection and passes a later attempt once the test releases it.
type flakyValidator struct {
	calls   atomic.Int64
	release chan struct{}
}

// Fails the first attempt with a retryable connection problem and waits for the release after that.
func (v *flakyValidator) Validate(ctx context.Context, _ acmeserver.ValidationRequest) error {
	if v.calls.Add(1) == 1 {
		return acmeserver.Retryable(acmeserver.NewProblem(acmeserver.ErrorConnection, "connection refused"),
			errors.New("dial tcp: connection refused"))
	}
	select {
	case <-v.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Requires the error of a failed attempt on a challenge that stays processing, as RFC 8555
// section 8.2 asks, and its removal once a later attempt succeeds.
func TestRetriedValidationShowsTheFailedAttempt(t *testing.T) {
	validator := &flakyValidator{release: make(chan struct{})}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Validators = map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: validator}
		cfg.Workers = acmeserver.WorkerConfig{
			Concurrency:  1,
			PollInterval: 2 * time.Millisecond,
			Lease:        20 * time.Second,
			TaskTimeout:  10 * time.Second,
			MaxAttempts:  3,
			RetryDelay:   time.Millisecond,
			StaleAfter:   time.Minute,
		}
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	orderURL, order := c.newOrder("flaky.test")
	c.respondHTTP01(order)
	waitFor(t, "the second validation attempt", func() bool { return validator.calls.Load() >= 2 })
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	if ch := authz.Challenges[0]; ch.Status != statusProcessing || ch.Error == nil || ch.Error.Type != acmeserver.ErrorConnection {
		t.Fatalf("challenge during the retry = %q with error %+v, want processing with a connection problem", ch.Status, ch.Error)
	}
	close(validator.release)
	c.waitOrder(orderURL, statusReady)
	var done authzBody
	c.get(order.Authorizations[0], &done)
	if ch := done.Challenges[0]; ch.Status != statusValid || ch.Error != nil {
		t.Fatalf("challenge after the retry = %q with error %+v, want valid without an error", ch.Status, ch.Error)
	}
}
