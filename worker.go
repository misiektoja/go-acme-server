package acmeserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Processes persisted validation and issuance work until ctx is canceled. Without a worker in this
// process or another process on the same store, challenges and orders never progress.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("acmeserver: Run is already active")
	}
	defer s.running.Store(false)
	slots := make(chan struct{}, s.workers.Concurrency)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return nil
		case slots <- struct{}{}:
		}
		now := s.clock.Now()
		task, err := s.store.ClaimTask(ctx, now, now.Add(s.workers.Lease))
		if err == nil {
			wg.Go(func() {
				defer func() { <-slots }()
				s.process(ctx, task)
			})
			continue
		}
		<-slots
		if !errors.Is(err, ErrNotFound) && ctx.Err() == nil {
			s.logError(ctx, "task claim failed", err)
		}
		timer := time.NewTimer(s.workers.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-s.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// Reports whether accepted work is being picked up. It returns an error when tasks have waited
// longer than WorkerConfig.StaleAfter without a claim, which means no Run is active.
func (s *Server) Ready(ctx context.Context) error {
	n, err := s.store.PendingTasks(ctx, s.clock.Now().Add(-s.workers.StaleAfter))
	if err != nil {
		return fmt.Errorf("acmeserver: pending task count: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("acmeserver: %d tasks have waited longer than %s for a worker, Run is not active", n,
			s.workers.StaleAfter)
	}
	return nil
}

// Wakes an in-process Run and warns when none is active.
func (s *Server) workAccepted(ctx context.Context) {
	select {
	case s.wake <- struct{}{}:
	default:
	}
	if !s.running.Load() && !s.workers.External {
		s.log.LogAttrs(ctx, slog.LevelWarn, "work accepted while Run is not active in this process")
	}
}

// Runs one claimed task, detached from the Run context so a shutdown does not interrupt work that
// is already in flight. Every phase of the run takes its own deadline from taskPhase.
func (s *Server) process(ctx context.Context, task *Task) {
	base := context.WithoutCancel(ctx)
	switch task.Kind {
	case TaskValidate:
		s.runValidation(base, task)
	case TaskIssue:
		s.runIssuance(base, task)
	default:
		s.logError(base, "unknown task kind dropped", errors.New(string(task.Kind)), slog.String("task", task.ID))
		s.finishTask(base, task)
	}
}

// Returns a context for one phase of a task run, bounded by WorkerConfig.TaskTimeout. A validator
// or issuer call and the store operations that record its outcome never share a deadline, so a host
// call that uses all of its budget still leaves the worker able to commit the result.
func (s *Server) taskPhase(base context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(base, s.workers.TaskTimeout)
}

// Validates a challenge and records the result on the challenge, its authorization and its order.
func (s *Server) runValidation(base context.Context, task *Task) {
	ch, authz, account, ok := s.validationTargets(base, task)
	if !ok {
		return
	}
	now := s.clock.Now()
	if status := effectiveAuthzStatus(authz, now); status != AuthorizationPending {
		ch.Status = ChallengeInvalid
		ch.Error = Problemf(ErrorMalformed, "authorization was %s before validation", string(status))
		s.completeValidation(base, task, ch, authz)
		return
	}
	// RFC 8555 section 7.3.6 leaves no pending work behind a closed account, so a deactivated
	// subscriber never has a proof fetched from its infrastructure.
	if account.Status != AccountValid {
		ch.Status = ChallengeInvalid
		ch.Error = NewProblem(ErrorUnauthorized, "account is no longer valid")
		authz.Status = AuthorizationInvalid
		s.completeValidation(base, task, ch, authz)
		return
	}
	validator, found := s.validators[ch.Type]
	if !found {
		ch.Status = ChallengeInvalid
		ch.Error = NewProblem(ErrorServerInternal, "no validator is configured for this challenge type")
		authz.Status = AuthorizationInvalid
		s.completeValidation(base, task, ch, authz)
		return
	}
	req := ValidationRequest{
		Challenge:            *ch,
		Identifier:           authz.Identifier,
		Wildcard:             authz.Wildcard,
		KeyAuthorization:     ch.Token + "." + ch.KeyThumbprint,
		AccountKeyThumbprint: ch.KeyThumbprint,
		AuthorityToken:       ch.AuthorityToken,
	}
	grant, err := s.validate(base, validator, req)
	now = s.clock.Now()
	if !authz.Expires.After(now) {
		err = NewProblem(ErrorUnauthorized, "authorization expired during validation")
	}
	if err == nil {
		ch.Status = ChallengeValid
		ch.Validated = now
		ch.Error = nil
		authz.Status = AuthorizationValid
		authz.Expires = now.Add(s.authzLifetime)
		authz.CACertificate = grant.CACertificate
		authz.GrantExpires = grant.Expires
		s.completeValidation(base, task, ch, authz)
		return
	}
	p, terminal := AsProblem(err)
	if !terminal {
		if task.Attempts < s.workers.MaxAttempts && authz.Expires.After(now) {
			s.log.LogAttrs(base, slog.LevelWarn, "validation will be retried", slog.String("challenge", ch.ID),
				slog.Int("attempt", task.Attempts), slog.Any("error", err))
			s.reschedule(base, task, now)
			return
		}
		s.logError(base, "validation gave up", err, slog.String("challenge", ch.ID), slog.Int("attempts", task.Attempts))
		p = NewProblem(ErrorServerInternal, "validation could not be completed")
	}
	ch.Status = ChallengeInvalid
	ch.Error = p
	authz.Status = AuthorizationInvalid
	s.completeValidation(base, task, ch, authz)
}

// Loads the challenge, authorization and account of a validation task and reports whether a proof
// is still needed.
func (s *Server) validationTargets(base context.Context, task *Task) (*Challenge, *Authorization, *Account, bool) {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	ch, err := s.store.Challenge(ctx, task.TargetID)
	if err != nil {
		s.dropOnNotFound(base, task, err, "challenge")
		return nil, nil, nil, false
	}
	if ch.Status != ChallengeProcessing {
		s.finishTask(base, task)
		return nil, nil, nil, false
	}
	authz, err := s.store.Authorization(ctx, ch.AuthorizationID)
	if err != nil {
		s.dropOnNotFound(base, task, err, "authorization")
		return nil, nil, nil, false
	}
	account, err := s.store.Account(ctx, ch.AccountID)
	if err != nil {
		s.dropOnNotFound(base, task, err, "account")
		return nil, nil, nil, false
	}
	return ch, authz, account, true
}

// Runs a validator under its own task timeout and reports what the response authorizes.
func (s *Server) validate(base context.Context, v Validator, req ValidationRequest) (ValidationGrant, error) {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	if granting, ok := v.(GrantingValidator); ok {
		return granting.ValidateGrant(ctx, req)
	}
	return ValidationGrant{}, v.Validate(ctx, req)
}

// Commits a validation result, deriving the order status from every authorization. A concurrent
// change to the order or authorization is reloaded and retried, and a commit that does not settle
// releases the task for a later attempt instead of holding its lease.
func (s *Server) completeValidation(base context.Context, task *Task, ch *Challenge, authz *Authorization) {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	for range 3 {
		order, err := s.store.Order(ctx, authz.OrderID)
		if err != nil {
			s.dropOnNotFound(base, task, err, "order")
			return
		}
		status, err := s.deriveOrderStatus(ctx, order, authz)
		if err != nil {
			s.logError(base, "order status derivation failed", err, slog.String("order", order.ID))
			s.reschedule(base, task, s.clock.Now())
			return
		}
		if order.Status == OrderPending && status != OrderPending {
			order.Status = status
		}
		err = s.store.CompleteValidation(ctx, task, ch, authz, order)
		if err == nil {
			return
		}
		if !errors.Is(err, ErrRevisionMismatch) {
			s.logError(base, "validation result could not be stored", err, slog.String("challenge", ch.ID))
			s.reschedule(base, task, s.clock.Now())
			return
		}
		current, err := s.store.Authorization(ctx, authz.ID)
		if err != nil {
			s.dropOnNotFound(base, task, err, "authorization")
			return
		}
		if current.Status != AuthorizationPending {
			s.finishTask(base, task)
			return
		}
		authz.Revision = current.Revision
	}
	s.logError(base, "validation result could not be stored after repeated conflicts", ErrRevisionMismatch,
		slog.String("challenge", ch.ID))
	s.reschedule(base, task, s.clock.Now())
}

// Returns the order status implied by its authorizations, with updated standing in for its
// stored copy.
func (s *Server) deriveOrderStatus(ctx context.Context, order *Order, updated *Authorization) (OrderStatus, error) {
	now := s.clock.Now()
	if !order.Expires.After(now) {
		return OrderInvalid, nil
	}
	allValid := true
	for _, id := range order.AuthorizationIDs {
		var status AuthorizationStatus
		if updated != nil && id == updated.ID {
			status = effectiveAuthzStatus(updated, now)
		} else {
			authz, err := s.store.Authorization(ctx, id)
			if err != nil {
				return "", err
			}
			status = effectiveAuthzStatus(authz, now)
		}
		if status == AuthorizationInvalid || status == AuthorizationExpired || status == AuthorizationDeactivated ||
			status == AuthorizationRevoked {
			return OrderInvalid, nil
		}
		if status != AuthorizationValid {
			allValid = false
		}
	}
	if allValid {
		return OrderReady, nil
	}
	return OrderPending, nil
}

// Releases the task for a later attempt with exponential backoff.
func (s *Server) reschedule(base context.Context, task *Task, now time.Time) {
	delay := s.workers.RetryDelay
	for i := 1; i < task.Attempts && delay < 32*s.workers.RetryDelay; i++ {
		delay *= 2
	}
	task.RunAt = now.Add(delay)
	s.storeReschedule(base, task)
}

// Stores a rescheduled task and logs failures.
func (s *Server) storeReschedule(base context.Context, task *Task) {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	if err := s.store.RescheduleTask(ctx, task); err != nil {
		s.logError(base, "task reschedule failed", err, slog.String("task", task.ID))
	}
}

// Removes a task that has nothing left to do.
func (s *Server) finishTask(base context.Context, task *Task) {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	if err := s.store.FinishTask(ctx, task); err != nil && !errors.Is(err, ErrNotFound) {
		s.logError(base, "task removal failed", err, slog.String("task", task.ID))
	}
}

// Drops a task whose target vanished and releases one whose lookup failed for another reason, so a
// store that is briefly unavailable costs a backoff instead of the remainder of the lease.
func (s *Server) dropOnNotFound(base context.Context, task *Task, err error, resource string) {
	if errors.Is(err, ErrNotFound) {
		s.log.LogAttrs(base, slog.LevelWarn, resource+" of a task no longer exists", slog.String("task", task.ID))
		s.finishTask(base, task)
		return
	}
	s.logError(base, resource+" lookup failed", err, slog.String("task", task.ID))
	s.reschedule(base, task, s.clock.Now())
}
