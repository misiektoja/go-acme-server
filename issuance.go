package acmeserver

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"slices"
	"time"
)

// Dispatches an authorized order or recovers its existing CA operation.
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
	if order.Issuance == nil && !s.beginIssuance(ctx, task, order) {
		return
	}
	req, err := s.issueRequest(order)
	if err != nil {
		s.logError(ctx, "persisted issuance request is invalid", err, slog.String("order", order.ID))
		s.reschedule(ctx, task, s.clock.Now())
		return
	}
	result, err := s.issuer.Issue(ctx, req)
	now := s.clock.Now()
	if len(result.Chain) > 0 {
		s.recordIssuedResult(ctx, task, order, req.CSR, result, now, err)
		return
	}
	switch {
	case err != nil:
		s.logError(ctx, "issuance outcome remains unresolved", err, slog.String("operation", task.ID))
		s.reschedule(ctx, task, now)
	case result.Rejected != nil && !result.Pending:
		s.failOrder(ctx, task, order, result.Rejected)
	case result.Pending && result.Rejected == nil:
		task.RunAt = now.Add(max(result.RetryAfter, s.workers.PollInterval))
		s.storeReschedule(ctx, task)
	default:
		s.logError(ctx, "issuer returned an ambiguous outcome", errors.New("missing or conflicting outcome"),
			slog.String("operation", task.ID))
		s.reschedule(ctx, task, now)
	}
}

// Commits the first authorization decision before any external CA operation.
func (s *Server) beginIssuance(ctx context.Context, task *Task, order *Order) bool {
	now := s.clock.Now()
	if !order.Expires.After(now) {
		s.failOrder(ctx, task, order, NewProblem(ErrorUnauthorized, "order expired before issuance dispatch"))
		return false
	}
	account, err := s.store.Account(ctx, order.AccountID)
	if err != nil {
		s.dropOnNotFound(ctx, task, err, "account")
		return false
	}
	if account.Status != AccountValid {
		s.failOrder(ctx, task, order, NewProblem(ErrorUnauthorized, "account is no longer valid"))
		return false
	}
	authzs, state, p, err := s.issuanceAuthorization(ctx, task.ID, order, now)
	if err != nil {
		s.dropOnNotFound(ctx, task, err, "authorization")
		return false
	}
	if p != nil {
		s.failOrder(ctx, task, order, p)
		return false
	}
	order.Issuance = state
	if !s.checkIssuancePolicy(ctx, task, order) {
		return false
	}
	if !state.Deadline.After(s.clock.Now()) {
		order.Issuance = nil
		s.failOrder(ctx, task, order, NewProblem(ErrorUnauthorized, "authorization expired before issuance dispatch"))
		return false
	}
	err = s.store.BeginIssuance(ctx, task, order, account, authzs)
	if err != nil {
		if !errors.Is(err, ErrRevisionMismatch) {
			s.logError(ctx, "issuance dispatch could not be recorded", err, slog.String("order", order.ID))
		}
		s.reschedule(ctx, task, s.clock.Now())
		return false
	}
	return true
}

// Collects the authorization revisions, evidence and earliest deadline for one dispatch.
func (s *Server) issuanceAuthorization(ctx context.Context, operationID string, order *Order, now time.Time) ([]*Authorization, *IssuanceState, *Problem, error) {
	state := &IssuanceState{OperationID: operationID, AuthorizedAt: now, Deadline: order.Expires}
	authzs := make([]*Authorization, 0, len(order.AuthorizationIDs))
	for _, id := range order.AuthorizationIDs {
		a, err := s.store.Authorization(ctx, id)
		if err != nil {
			return nil, nil, nil, err
		}
		if effectiveAuthzStatus(a, now) != AuthorizationValid {
			return nil, nil, NewProblem(ErrorUnauthorized, "an order authorization is no longer valid"), nil
		}
		v, err := s.validationEvidence(ctx, a)
		if err != nil {
			return nil, nil, nil, err
		}
		authzs = append(authzs, a)
		state.Validations = append(state.Validations, v)
		if a.Expires.Before(state.Deadline) {
			state.Deadline = a.Expires
		}
	}
	return authzs, state, nil, nil
}

// Loads the successful challenge that authorized an identifier.
func (s *Server) validationEvidence(ctx context.Context, a *Authorization) (Validation, error) {
	v := Validation{Identifier: a.Identifier, CACertificate: a.CACertificate}
	if a.Wildcard {
		v.Identifier.Value = "*." + v.Identifier.Value
	}
	for _, id := range a.ChallengeIDs {
		ch, err := s.store.Challenge(ctx, id)
		if err != nil {
			return Validation{}, err
		}
		if ch.Status == ChallengeValid {
			v.Type, v.Validated = ch.Type, ch.Validated
			return v, nil
		}
	}
	return Validation{}, errors.New("valid authorization has no successful challenge")
}

// Builds an owned request from the immutable accepted CSR and persisted authorization decision.
func (s *Server) issueRequest(order *Order) (IssueRequest, error) {
	der := slices.Clone(order.CSR)
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return IssueRequest{}, err
	}
	state := order.Issuance
	return IssueRequest{
		OperationID: state.OperationID, AccountID: order.AccountID, AccountURL: s.accountURL(order.AccountID),
		OrderID: order.ID, CSR: csr, CSRDER: der, Identifiers: slices.Clone(order.Identifiers),
		NotBefore: order.NotBefore, NotAfter: order.NotAfter, Validations: slices.Clone(state.Validations),
		Deadline: state.Deadline, RecoveryOnly: !state.Deadline.After(s.clock.Now()),
	}, nil
}

// Applies current host policy before persisting a dispatch decision.
func (s *Server) checkIssuancePolicy(ctx context.Context, task *Task, order *Order) bool {
	req, err := s.issueRequest(order)
	if err == nil && s.issuancePolicy != nil {
		err = s.issuancePolicy.AuthorizeIssuance(ctx, req)
	}
	if err == nil {
		return true
	}
	order.Issuance = nil
	if p, ok := AsProblem(err); ok {
		s.failOrder(ctx, task, order, p)
	} else if task.Attempts < s.workers.MaxAttempts {
		s.logError(ctx, "issuance policy will be retried", err)
		s.reschedule(ctx, task, s.clock.Now())
	} else {
		s.failOrder(ctx, task, order, NewProblem(ErrorServerInternal, "issuance policy could not be evaluated"))
	}
	return false
}

// Retains every returned chain and publishes only an unambiguous acceptable result.
func (s *Server) recordIssuedResult(ctx context.Context, task *Task, order *Order, csr *x509.CertificateRequest, result IssueResult, now time.Time, issueErr error) {
	leaf, err := checkChain(result.Chain, csr, order, now)
	if err != nil || issueErr != nil || result.Pending || result.Rejected != nil {
		order.UnpublishedResult = &result
		s.log.LogAttrs(ctx, slog.LevelError, "issuer returned an unacceptable certificate", slog.String("order", order.ID),
			slog.String("operation", task.ID))
		s.failOrder(ctx, task, order, NewProblem(ErrorServerInternal, "issuer returned an unacceptable certificate"))
		return
	}
	cert := &Certificate{
		ID: certificateID(result.Chain[0]), AccountID: order.AccountID, OrderID: order.ID,
		CAReference: result.CAReference, Chain: result.Chain, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		Validations: order.Issuance.Validations, CreatedAt: now,
	}
	order.Status, order.CertificateID, order.Error = OrderValid, cert.ID, nil
	err = s.store.CompleteIssuance(ctx, task, order, cert)
	if errors.Is(err, ErrConflict) {
		order.UnpublishedResult = &result
		order.CertificateID = ""
		s.failOrder(ctx, task, order, NewProblem(ErrorServerInternal, "issuer returned a duplicate certificate"))
		return
	}
	s.handleIssuanceCommit(ctx, order, err)
}

// Records a definitive refusal without discarding any retained CA result.
func (s *Server) failOrder(ctx context.Context, task *Task, order *Order, p *Problem) {
	order.Status = OrderInvalid
	order.Error = p
	s.handleIssuanceCommit(ctx, order, s.store.CompleteIssuance(ctx, task, order, nil))
}

// Reports a failed fenced commit while leaving persisted work available for recovery.
func (s *Server) handleIssuanceCommit(ctx context.Context, order *Order, err error) {
	if err != nil {
		s.logError(ctx, "issuance result could not be stored", err, slog.String("order", order.ID))
	}
}
