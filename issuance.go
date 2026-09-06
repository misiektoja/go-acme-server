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
func (s *Server) runIssuance(base context.Context, task *Task) {
	order, ok := s.issuanceOrder(base, task)
	if !ok {
		return
	}
	if order.Issuance == nil && !s.beginIssuance(base, task, order) {
		return
	}
	req, err := s.issueRequest(order)
	if err != nil {
		s.logError(base, "persisted issuance request is invalid", err, slog.String("order", order.ID))
		s.reschedule(base, task, s.clock.Now())
		return
	}
	result, err := s.issue(base, req)
	now := s.clock.Now()
	if len(result.Chain) > 0 {
		s.recordIssuedResult(base, task, order, req.CSR, result, now, err)
		return
	}
	switch {
	case err != nil:
		s.logError(base, "issuance outcome remains unresolved", err, slog.String("operation", task.ID))
		s.reschedule(base, task, now)
	case result.Rejected != nil && !result.Pending:
		s.failOrder(base, task, order, result.Rejected)
	case result.Pending && result.Rejected == nil:
		task.RunAt = now.Add(max(result.RetryAfter, s.workers.PollInterval))
		s.storeReschedule(base, task)
	default:
		s.logError(base, "issuer returned an ambiguous outcome", errors.New("missing or conflicting outcome"),
			slog.String("operation", task.ID))
		s.reschedule(base, task, now)
	}
}

// Loads the order of an issuance task and reports whether it still needs the CA.
func (s *Server) issuanceOrder(base context.Context, task *Task) (*Order, bool) {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	order, err := s.store.Order(ctx, task.TargetID)
	if err != nil {
		s.dropOnNotFound(base, task, err, "order")
		return nil, false
	}
	if order.Status != OrderProcessing {
		s.finishTask(base, task)
		return nil, false
	}
	return order, true
}

// Calls the issuer under its own task timeout.
func (s *Server) issue(base context.Context, req IssueRequest) (IssueResult, error) {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	return s.issuer.Issue(ctx, req)
}

// Commits the first authorization decision before any external CA operation.
func (s *Server) beginIssuance(base context.Context, task *Task, order *Order) bool {
	authzs, account, ok := s.dispatchSnapshot(base, task, order)
	if !ok {
		return false
	}
	if !s.checkIssuancePolicy(base, task, order) {
		return false
	}
	if !order.Issuance.Deadline.After(s.clock.Now()) {
		order.Issuance = nil
		s.failOrder(base, task, order, NewProblem(ErrorUnauthorized, "authorization expired before issuance dispatch"))
		return false
	}
	return s.storeDispatch(base, task, order, account, authzs)
}

// Reads the account and authorizations one dispatch rests on and sets the issuance state it proposes.
func (s *Server) dispatchSnapshot(base context.Context, task *Task, order *Order) ([]*Authorization, *Account, bool) {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	now := s.clock.Now()
	if !order.Expires.After(now) {
		s.failOrder(base, task, order, NewProblem(ErrorUnauthorized, "order expired before issuance dispatch"))
		return nil, nil, false
	}
	account, err := s.store.Account(ctx, order.AccountID)
	if err != nil {
		s.dropOnNotFound(base, task, err, "account")
		return nil, nil, false
	}
	if account.Status != AccountValid {
		s.failOrder(base, task, order, NewProblem(ErrorUnauthorized, "account is no longer valid"))
		return nil, nil, false
	}
	authzs, state, p, err := s.issuanceAuthorization(ctx, task.ID, order, now)
	if err != nil {
		s.dropOnNotFound(base, task, err, "authorization")
		return nil, nil, false
	}
	if p != nil {
		s.failOrder(base, task, order, p)
		return nil, nil, false
	}
	order.Issuance = state
	return authzs, account, true
}

// Records the dispatch decision and releases the task when the checked snapshot no longer holds.
func (s *Server) storeDispatch(base context.Context, task *Task, order *Order, account *Account, authzs []*Authorization) bool {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	err := s.store.BeginIssuance(ctx, task, order, account, authzs)
	if err == nil {
		return true
	}
	if !errors.Is(err, ErrRevisionMismatch) {
		s.logError(base, "issuance dispatch could not be recorded", err, slog.String("order", order.ID))
	}
	s.reschedule(base, task, s.clock.Now())
	return false
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
	v := Validation{Identifier: a.Identifier, CACertificate: a.CACertificate, GrantExpires: a.GrantExpires}
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
		NotBefore: order.NotBefore, NotAfter: issuedNotAfter(order), Validations: slices.Clone(state.Validations),
		Deadline: state.Deadline, RecoveryOnly: !state.Deadline.After(s.clock.Now()),
	}, nil
}

// Returns the notAfter an issuance asks the CA for: the accepted order value narrowed by an
// authority token expiry, or that expiry alone when the order left the validity to the CA. A zero
// time means nothing bounds the certificate. Publication checks the issued leaf against the same
// value, so a certificate clamped to the token is accepted.
func issuedNotAfter(order *Order) time.Time {
	notAfter := order.NotAfter
	var bound time.Time
	if order.Issuance != nil {
		bound = grantExpiry(order.Issuance.Validations)
	}
	if !bound.IsZero() && (notAfter.IsZero() || notAfter.After(bound)) {
		return bound
	}
	return notAfter
}

// Returns the earliest grant expiry among the validations, or zero when none is bounded.
func grantExpiry(validations []Validation) time.Time {
	var bound time.Time
	for _, v := range validations {
		if !v.GrantExpires.IsZero() && (bound.IsZero() || v.GrantExpires.Before(bound)) {
			bound = v.GrantExpires
		}
	}
	return bound
}

// Applies current host policy before persisting a dispatch decision.
func (s *Server) checkIssuancePolicy(base context.Context, task *Task, order *Order) bool {
	req, err := s.issueRequest(order)
	if err == nil && s.issuancePolicy != nil {
		err = s.authorizeIssuance(base, req)
	}
	if err == nil {
		return true
	}
	order.Issuance = nil
	if p, ok := AsProblem(err); ok {
		s.failOrder(base, task, order, p)
	} else if task.Attempts < s.workers.MaxAttempts {
		s.logError(base, "issuance policy will be retried", err)
		s.reschedule(base, task, s.clock.Now())
	} else {
		s.failOrder(base, task, order, NewProblem(ErrorServerInternal, "issuance policy could not be evaluated"))
	}
	return false
}

// Runs the issuance policy under its own task timeout.
func (s *Server) authorizeIssuance(base context.Context, req IssueRequest) error {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	return s.issuancePolicy.AuthorizeIssuance(ctx, req)
}

// Retains every returned chain and publishes only an unambiguous acceptable result.
func (s *Server) recordIssuedResult(base context.Context, task *Task, order *Order, csr *x509.CertificateRequest, result IssueResult, now time.Time, issueErr error) {
	leaf, err := checkChain(result.Chain, csr, order, now)
	if err != nil || issueErr != nil || result.Pending || result.Rejected != nil {
		order.UnpublishedResult = &result
		s.log.LogAttrs(base, slog.LevelError, "issuer returned an unacceptable certificate", slog.String("order", order.ID),
			slog.String("operation", task.ID))
		s.failOrder(base, task, order, NewProblem(ErrorServerInternal, "issuer returned an unacceptable certificate"))
		return
	}
	cert := &Certificate{
		ID: certificateID(result.Chain[0]), AccountID: order.AccountID, OrderID: order.ID,
		CAReference: result.CAReference, Chain: result.Chain, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		RenewalID: renewalID(leaf), Validations: order.Issuance.Validations, CreatedAt: now,
	}
	order.Status, order.CertificateID, order.Error = OrderValid, cert.ID, nil
	err = s.completeIssuance(base, task, order, cert)
	if errors.Is(err, ErrConflict) {
		order.UnpublishedResult = &result
		order.CertificateID = ""
		s.failOrder(base, task, order, NewProblem(ErrorServerInternal, "issuer returned a duplicate certificate"))
		return
	}
	s.handleIssuanceCommit(base, order, err)
}

// Records a definitive refusal without discarding any retained CA result.
func (s *Server) failOrder(base context.Context, task *Task, order *Order, p *Problem) {
	order.Status = OrderInvalid
	order.Error = p
	s.handleIssuanceCommit(base, order, s.completeIssuance(base, task, order, nil))
}

// Stores an issuance outcome under its own task timeout.
func (s *Server) completeIssuance(base context.Context, task *Task, order *Order, cert *Certificate) error {
	ctx, cancel := s.taskPhase(base)
	defer cancel()
	return s.store.CompleteIssuance(ctx, task, order, cert)
}

// Reports a failed fenced commit while leaving persisted work available for recovery.
func (s *Server) handleIssuanceCommit(ctx context.Context, order *Order, err error) {
	if err != nil {
		s.logError(ctx, "issuance result could not be stored", err, slog.String("order", order.ID))
	}
}
