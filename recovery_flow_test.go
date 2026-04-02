package acmeserver_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Supplies a synchronized clock for expiration races.
type flowClock struct {
	mu  sync.Mutex
	now time.Time
}

// Returns the controlled current time.
func (c *flowClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advances the controlled clock.
func (c *flowClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Refuses a publication once and changes authorization state before recovery.
type interruptedPublication struct {
	acmeserver.Store
	clock *flowClock
	once  sync.Once
}

// Simulates a lost store commit after issuance and account deactivation before the retry.
func (s *interruptedPublication) CompleteIssuance(ctx context.Context, task *acmeserver.Task, order *acmeserver.Order, cert *acmeserver.Certificate) error {
	interrupt := false
	if cert != nil {
		s.once.Do(func() {
			interrupt = true
			account, err := s.Account(ctx, order.AccountID)
			if err != nil {
				return
			}
			account.Status = acmeserver.AccountDeactivated
			if err := s.UpdateAccount(ctx, account); err != nil {
				return
			}
			s.clock.advance(2 * time.Minute)
		})
	}
	if interrupt {
		return errTransient
	}
	return s.Store.CompleteIssuance(ctx, task, order, cert)
}

// Recovers an issued result after its first publication failed and authorization subsequently ended.
func TestRecoverAfterAccountDeactivationAndExpiry(t *testing.T) {
	clock := &flowClock{now: time.Now()}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Clock = clock
		cfg.OrderLifetime = time.Minute
		cfg.Store = &interruptedPublication{Store: cfg.Store, clock: clock}
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("recover.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	if rec := c.finalize(order, newKey(t)); rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d", rec.Code)
	}
	id := strings.TrimPrefix(location, baseURL+"order/")
	waitFor(t, "recovered publication", func() bool {
		stored, err := f.store.Order(t.Context(), id)
		return err == nil && stored.Status == acmeserver.OrderValid
	})
	f.ca.mu.Lock()
	defer f.ca.mu.Unlock()
	if len(f.ca.issued) != 1 || len(f.ca.calls) != 2 {
		t.Fatalf("issued %d certificates across %d calls", len(f.ca.issued), len(f.ca.calls))
	}
	first, recovered := f.ca.calls[0], f.ca.calls[1]
	if !recovered.RecoveryOnly || first.RecoveryOnly || first.OperationID != recovered.OperationID ||
		!first.Deadline.Equal(recovered.Deadline) {
		t.Fatal("recovery did not preserve the original operation and deadline")
	}
}

// Rejects a proof whose validation finishes after the authorization deadline.
func TestValidationCannotExtendExpiredAuthorization(t *testing.T) {
	clock := &flowClock{now: time.Now()}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Clock = clock
		cfg.OrderLifetime = time.Minute
	})
	f.validator.script(func(acmeserver.ValidationRequest, int) error {
		clock.advance(2 * time.Minute)
		return nil
	})
	c := f.newClient()
	c.register()
	_, order := c.newOrder("late.test")
	c.respondHTTP01(order)
	f.runWorker()
	var a authzBody
	waitFor(t, "terminal authorization", func() bool {
		c.get(order.Authorizations[0], &a)
		return a.Status == statusInvalid
	})
	if len(a.Challenges) == 0 || a.Challenges[0].Status != statusInvalid {
		t.Fatal("expired proof was accepted")
	}
}

// Invalidates a ready order immediately when its authorization is deactivated.
func TestDeactivationInvalidatesReadyOrder(t *testing.T) {
	f := newFlow(t, nil)
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("deactivate.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	rec := c.post(order.Authorizations[0], map[string]string{"status": "deactivated"})
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate = %d", rec.Code)
	}
	var invalid orderBody
	c.get(location, &invalid)
	if invalid.Status != statusInvalid {
		t.Fatalf("order status = %s", invalid.Status)
	}
	stored, err := f.store.Order(t.Context(), strings.TrimPrefix(location, baseURL+"order/"))
	if err != nil || stored.Status != acmeserver.OrderInvalid {
		t.Fatalf("stored order = %+v, %v", stored, err)
	}
	assertProblem(t, c.finalize(order, newKey(t)), http.StatusForbidden, acmeserver.ErrorOrderNotReady)
	if f.ca.callCount() != 0 {
		t.Fatal("deactivated order reached issuer")
	}
}

// Retains an unacceptable chain and CA reference without exposing a successful order.
func TestUnpublishedResultIsDurable(t *testing.T) {
	f := newFlow(t, nil)
	f.ca.fixedChain = [][]byte{[]byte("invalid DER")}
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("retain.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	c.finalize(order, newKey(t))
	invalid := c.waitOrder(location, statusInvalid)
	stored, err := f.store.Order(t.Context(), strings.TrimPrefix(location, baseURL+"order/"))
	if err != nil || stored.UnpublishedResult == nil || string(stored.UnpublishedResult.Chain[0]) != "invalid DER" ||
		stored.Issuance == nil || invalid.Certificate != "" {
		t.Fatalf("unpublished result missing: %+v, %v", stored, err)
	}
	stored.UnpublishedResult.Chain[0][0] = 'x'
	again, err := f.store.Order(t.Context(), stored.ID)
	if err != nil || string(again.UnpublishedResult.Chain[0]) != "invalid DER" {
		t.Fatal("reconciliation data aliases a caller copy")
	}
}
