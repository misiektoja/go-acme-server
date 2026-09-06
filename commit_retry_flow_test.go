package acmeserver_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// A store whose fenced commits fail a scripted number of times before they settle.
type flakyCommitStore struct {
	acmeserver.Store
	validations atomic.Int64
	issuances   atomic.Int64
}

// Fails while the validation budget lasts.
func (s *flakyCommitStore) CompleteValidation(ctx context.Context, task *acmeserver.Task, challenge *acmeserver.Challenge,
	authz *acmeserver.Authorization, order *acmeserver.Order) error {
	if s.validations.Add(-1) >= 0 {
		return errors.New("store unavailable")
	}
	return s.Store.CompleteValidation(ctx, task, challenge, authz, order)
}

// Fails while the issuance budget lasts.
func (s *flakyCommitStore) CompleteIssuance(ctx context.Context, task *acmeserver.Task, order *acmeserver.Order,
	cert *acmeserver.Certificate) error {
	if s.issuances.Add(-1) >= 0 {
		return errors.New("store unavailable")
	}
	return s.Store.CompleteIssuance(ctx, task, order, cert)
}

// Builds a flow whose commits fail the given number of times, under a lease far longer than the
// test may wait, so any progress proves the worker released the task instead of holding it.
func newFlakyCommitFlow(t *testing.T, validations, issuances int64) *flow {
	t.Helper()
	flaky := &flakyCommitStore{}
	flaky.validations.Store(validations)
	flaky.issuances.Store(issuances)
	return newFlow(t, func(cfg *acmeserver.Config) {
		flaky.Store = cfg.Store
		cfg.Store = flaky
		cfg.Workers.Lease = time.Minute
	})
}

// Retries a validation whose result could not be stored instead of waiting out the lease.
func TestValidationRetriesAfterACommitFailure(t *testing.T) {
	f := newFlakyCommitFlow(t, 1, 0)
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("flaky.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
}

// Recovers the same certificate after an issuance commit failure instead of waiting out the lease.
func TestIssuanceRetriesAfterACommitFailure(t *testing.T) {
	f := newFlakyCommitFlow(t, 0, 1)
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("flaky.test")
	c.respondHTTP01(order)
	order = c.waitOrder(location, statusReady)
	c.finalize(order, newKey(t))
	c.waitOrder(location, statusValid)
	if n := f.ca.callCount(); n != 2 {
		t.Fatalf("the CA was called %d times, want one dispatch and one recovery", n)
	}
}
