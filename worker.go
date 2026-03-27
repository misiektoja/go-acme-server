package acmeserver

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
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

// Runs one claimed task with the task timeout, detached from the Run context.
func (s *Server) process(ctx context.Context, task *Task) {
	taskCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.workers.TaskTimeout)
	defer cancel()
	switch task.Kind {
	case TaskValidate:
		s.runValidation(taskCtx, task)
	case TaskIssue:
		s.runIssuance(taskCtx, task)
	default:
		s.logError(taskCtx, "unknown task kind dropped", errors.New(string(task.Kind)), slog.String("task", task.ID))
		s.finishTask(taskCtx, task)
	}
}

// Validates a challenge and records the result on the challenge, its authorization and its order.
func (s *Server) runValidation(ctx context.Context, task *Task) {
	ch, err := s.store.Challenge(ctx, task.TargetID)
	if err != nil {
		s.dropOnNotFound(ctx, task, err, "challenge")
		return
	}
	if ch.Status != ChallengeProcessing {
		s.finishTask(ctx, task)
		return
	}
	authz, err := s.store.Authorization(ctx, ch.AuthorizationID)
	if err != nil {
		s.dropOnNotFound(ctx, task, err, "authorization")
		return
	}
	now := s.clock.Now()
	if status := effectiveAuthzStatus(authz, now); status != AuthorizationPending {
		ch.Status = ChallengeInvalid
		ch.Error = Problemf(ErrorMalformed, "authorization was %s before validation", string(status))
		s.completeValidation(ctx, task, ch, authz)
		return
	}
	validator, ok := s.validators[ch.Type]
	if !ok {
		ch.Status = ChallengeInvalid
		ch.Error = NewProblem(ErrorServerInternal, "no validator is configured for this challenge type")
		authz.Status = AuthorizationInvalid
		s.completeValidation(ctx, task, ch, authz)
		return
	}
	req := ValidationRequest{
		Challenge:            *ch,
		Identifier:           authz.Identifier,
		Wildcard:             authz.Wildcard,
		KeyAuthorization:     ch.Token + "." + ch.KeyThumbprint,
		AccountKeyThumbprint: ch.KeyThumbprint,
	}
	err = validator.Validate(ctx, req)
	if err == nil {
		ch.Status = ChallengeValid
		ch.Validated = now
		ch.Error = nil
		authz.Status = AuthorizationValid
		authz.Expires = now.Add(s.authzLifetime)
		s.completeValidation(ctx, task, ch, authz)
		return
	}
	p, terminal := AsProblem(err)
	if !terminal {
		if task.Attempts < s.workers.MaxAttempts && authz.Expires.After(now) {
			s.log.LogAttrs(ctx, slog.LevelWarn, "validation will be retried", slog.String("challenge", ch.ID),
				slog.Int("attempt", task.Attempts), slog.Any("error", err))
			s.reschedule(ctx, task, now)
			return
		}
		s.logError(ctx, "validation gave up", err, slog.String("challenge", ch.ID), slog.Int("attempts", task.Attempts))
		p = NewProblem(ErrorServerInternal, "validation could not be completed")
	}
	ch.Status = ChallengeInvalid
	ch.Error = p
	authz.Status = AuthorizationInvalid
	s.completeValidation(ctx, task, ch, authz)
}

// Commits a validation result, deriving the order status from every authorization. A concurrent
// change to the order or authorization is reloaded and retried.
func (s *Server) completeValidation(ctx context.Context, task *Task, ch *Challenge, authz *Authorization) {
	for range 3 {
		order, err := s.store.Order(ctx, authz.OrderID)
		if err != nil {
			s.dropOnNotFound(ctx, task, err, "order")
			return
		}
		status, err := s.deriveOrderStatus(ctx, order, authz)
		if err != nil {
			s.logError(ctx, "order status derivation failed", err, slog.String("order", order.ID))
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
			s.logError(ctx, "validation result could not be stored", err, slog.String("challenge", ch.ID))
			return
		}
		current, err := s.store.Authorization(ctx, authz.ID)
		if err != nil {
			s.dropOnNotFound(ctx, task, err, "authorization")
			return
		}
		if current.Status != AuthorizationPending {
			s.finishTask(ctx, task)
			return
		}
		authz.Revision = current.Revision
	}
	s.logError(ctx, "validation result abandoned after repeated conflicts", ErrRevisionMismatch,
		slog.String("challenge", ch.ID))
}

// Returns the order status implied by its authorizations, with updated standing in for its
// stored copy.
func (s *Server) deriveOrderStatus(ctx context.Context, order *Order, updated *Authorization) (OrderStatus, error) {
	now := s.clock.Now()
	allValid := true
	for _, id := range order.AuthorizationIDs {
		var status AuthorizationStatus
		if id == updated.ID {
			status = updated.Status
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

// Issues the certificate for a processing order and records the result.
func (s *Server) runIssuance(ctx context.Context, task *Task) {
	order, err := s.store.Order(ctx, task.TargetID)
	if err != nil {
		s.dropOnNotFound(ctx, task, err, "order")
		return
	}
	if order.Status != OrderProcessing {
		s.finishTask(ctx, task)
		return
	}
	now := s.clock.Now()
	account, err := s.store.Account(ctx, order.AccountID)
	if err != nil {
		s.dropOnNotFound(ctx, task, err, "account")
		return
	}
	if account.Status != AccountValid {
		s.failOrder(ctx, task, order, Problemf(ErrorUnauthorized, "account is %s", string(account.Status)))
		return
	}
	validations, p, err := s.collectValidations(ctx, order, now)
	if err != nil {
		s.dropOnNotFound(ctx, task, err, "authorization")
		return
	}
	if p != nil {
		s.failOrder(ctx, task, order, p)
		return
	}
	csr, err := x509.ParseCertificateRequest(order.CSR)
	if err != nil {
		s.failOrder(ctx, task, order, NewProblem(ErrorServerInternal, "stored CSR could not be parsed"))
		return
	}
	result, err := s.issuer.Issue(ctx, IssueRequest{
		OperationID: task.ID,
		AccountID:   order.AccountID,
		OrderID:     order.ID,
		CSR:         csr,
		CSRDER:      order.CSR,
		Identifiers: order.Identifiers,
		NotBefore:   order.NotBefore,
		NotAfter:    order.NotAfter,
		Validations: validations,
		Deadline:    order.Expires,
	})
	switch {
	case err != nil && task.Attempts < s.workers.MaxAttempts && order.Expires.After(now):
		s.log.LogAttrs(ctx, slog.LevelWarn, "issuance will be retried", slog.String("order", order.ID),
			slog.String("operation", task.ID), slog.Int("attempt", task.Attempts), slog.Any("error", err))
		s.reschedule(ctx, task, now)
		return
	case err != nil:
		s.logError(ctx, "issuance gave up", err, slog.String("order", order.ID), slog.String("operation", task.ID))
		s.failOrder(ctx, task, order, NewProblem(ErrorServerInternal, "issuance failed"))
		return
	case result.Rejected != nil:
		s.failOrder(ctx, task, order, result.Rejected)
		return
	case result.Pending:
		retryAt := now.Add(max(result.RetryAfter, s.workers.PollInterval))
		if !retryAt.Before(order.Expires) {
			s.failOrder(ctx, task, order, NewProblem(ErrorServerInternal, "issuance did not complete before the order expired"))
			return
		}
		task.RunAt = retryAt
		s.storeReschedule(ctx, task)
		return
	}
	leaf, err := checkChain(result.Chain, csr, order, now)
	if err != nil {
		s.logError(ctx, "issuer returned an unacceptable certificate", err, slog.String("order", order.ID),
			slog.String("operation", task.ID))
		s.failOrder(ctx, task, order, NewProblem(ErrorServerInternal, "issuer returned an unacceptable certificate"))
		return
	}
	cert := &Certificate{
		ID:          certificateID(result.Chain[0]),
		AccountID:   order.AccountID,
		OrderID:     order.ID,
		Chain:       result.Chain,
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Validations: validations,
		CreatedAt:   now,
	}
	s.publishCertificate(ctx, task, order, cert)
}

// Returns the validation evidence of every authorization or a problem when one is not valid.
func (s *Server) collectValidations(ctx context.Context, order *Order, now time.Time) ([]Validation, *Problem, error) {
	validations := make([]Validation, 0, len(order.AuthorizationIDs))
	for _, id := range order.AuthorizationIDs {
		authz, err := s.store.Authorization(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if status := effectiveAuthzStatus(authz, now); status != AuthorizationValid {
			return nil, Problemf(ErrorUnauthorized, "authorization for %s is %s", authz.Identifier.String(), string(status)), nil
		}
		v := Validation{Identifier: authz.Identifier}
		if authz.Wildcard {
			v.Identifier.Value = "*." + v.Identifier.Value
		}
		for _, chID := range authz.ChallengeIDs {
			ch, err := s.store.Challenge(ctx, chID)
			if err != nil {
				return nil, nil, err
			}
			if ch.Status == ChallengeValid {
				v.Type, v.Validated = ch.Type, ch.Validated
				break
			}
		}
		validations = append(validations, v)
	}
	return validations, nil, nil
}

// Checks that the chain the issuer returned matches the CSR and the order.
func checkChain(chain [][]byte, csr *x509.CertificateRequest, order *Order, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty chain")
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("chain element %d: %w", i, err)
		}
		certs[i] = cert
	}
	leaf := certs[0]
	leafKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("leaf key: %w", err)
	}
	csrKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("CSR key: %w", err)
	}
	if string(leafKey) != string(csrKey) {
		return nil, errors.New("leaf public key does not match the CSR")
	}
	if !leaf.NotAfter.After(now) {
		return nil, errors.New("leaf certificate is already expired")
	}
	var names []Identifier
	for _, name := range leaf.DNSNames {
		names = append(names, Identifier{Type: IdentifierDNS, Value: name})
	}
	for _, ip := range leaf.IPAddresses {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, errors.New("leaf IP SAN is invalid")
		}
		names = append(names, Identifier{Type: IdentifierIP, Value: addr.Unmap().String()})
	}
	normalized, err := NormalizeIdentifiers(names)
	if err != nil || !sameIdentifiers(normalized, order.Identifiers) {
		return nil, errors.New("leaf identifiers do not match the order")
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("chain element %d is not signed by element %d: %w", i, i+1, err)
		}
	}
	return leaf, nil
}

// Records an issued certificate with the valid order. A certificate that this order already
// published is accepted as the recovered result of an earlier attempt.
func (s *Server) publishCertificate(ctx context.Context, task *Task, order *Order, cert *Certificate) {
	order.Status = OrderValid
	order.CertificateID = cert.ID
	order.Error = nil
	err := s.store.CompleteIssuance(ctx, task, order, cert)
	if errors.Is(err, ErrConflict) {
		existing, lookupErr := s.store.Certificate(ctx, cert.ID)
		if lookupErr == nil && existing.OrderID == order.ID {
			err = s.store.CompleteIssuance(ctx, task, order, nil)
		} else {
			s.logError(ctx, "issuer returned a certificate that another order already published", err,
				slog.String("order", order.ID), slog.String("certificate", cert.ID))
			s.failOrder(ctx, task, order, NewProblem(ErrorServerInternal, "issuer returned a duplicate certificate"))
			return
		}
	}
	s.handleIssuanceCommit(ctx, order, err)
}

// Records a failed issuance on the order.
func (s *Server) failOrder(ctx context.Context, task *Task, order *Order, p *Problem) {
	order.Status = OrderInvalid
	order.Error = p
	s.handleIssuanceCommit(ctx, order, s.store.CompleteIssuance(ctx, task, order, nil))
}

// Logs a failed issuance commit. A revision mismatch means the order left processing elsewhere.
func (s *Server) handleIssuanceCommit(ctx context.Context, order *Order, err error) {
	switch {
	case err == nil:
	case errors.Is(err, ErrRevisionMismatch):
		s.log.LogAttrs(ctx, slog.LevelWarn, "issuance result superseded by a concurrent change",
			slog.String("order", order.ID))
	default:
		s.logError(ctx, "issuance result could not be stored", err, slog.String("order", order.ID))
	}
}

// Releases the task for a later attempt with exponential backoff.
func (s *Server) reschedule(ctx context.Context, task *Task, now time.Time) {
	delay := s.workers.RetryDelay
	for i := 1; i < task.Attempts && delay < 32*s.workers.RetryDelay; i++ {
		delay *= 2
	}
	task.RunAt = now.Add(delay)
	s.storeReschedule(ctx, task)
}

// Stores a rescheduled task and logs failures.
func (s *Server) storeReschedule(ctx context.Context, task *Task) {
	if err := s.store.RescheduleTask(ctx, task); err != nil {
		s.logError(ctx, "task reschedule failed", err, slog.String("task", task.ID))
	}
}

// Removes a task that has nothing left to do.
func (s *Server) finishTask(ctx context.Context, task *Task) {
	if err := s.store.FinishTask(ctx, task); err != nil && !errors.Is(err, ErrNotFound) {
		s.logError(ctx, "task removal failed", err, slog.String("task", task.ID))
	}
}

// Drops a task whose target vanished and logs any other lookup failure.
func (s *Server) dropOnNotFound(ctx context.Context, task *Task, err error, resource string) {
	if errors.Is(err, ErrNotFound) {
		s.log.LogAttrs(ctx, slog.LevelWarn, resource+" of a task no longer exists", slog.String("task", task.ID))
		s.finishTask(ctx, task)
		return
	}
	s.logError(ctx, resource+" lookup failed", err, slog.String("task", task.ID))
}
