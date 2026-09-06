package acmeserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
)

// The finalize payload of RFC 8555 section 7.4.
type finalizeJSON struct {
	CSR string `json:"csr"`
}

// Accepts a CSR for a ready order and enqueues issuance, see RFC 8555 section 7.4.
func (s *Server) serveFinalize(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	req, order, p := s.readOwnedOrder(r, id, orderPathPrefix+id+"/finalize")
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	var payload finalizeJSON
	if p := decodePayload(req.Payload, &payload); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(payload.CSR)
	if err != nil || len(der) == 0 {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "csr is not valid base64url"))
		return
	}
	now := s.clock.Now()
	status := effectiveOrderStatus(order, now)
	switch {
	case status == OrderReady:
	case (status == OrderProcessing || status == OrderValid) && bytes.Equal(order.CSR, der):
		s.writeOrder(ctx, w, http.StatusOK, order, now)
		return
	case status == OrderProcessing || status == OrderValid:
		s.writeProblem(ctx, w, NewProblem(ErrorOrderNotReady, "order was already finalized with a different CSR"))
		return
	default:
		s.writeProblem(ctx, w, Problemf(ErrorOrderNotReady, "order is %s", string(status)))
		return
	}
	csr, p := checkCSR(der, order, req.Account)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	if p := s.checkCAGrants(ctx, order, csr); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	taskID, err := newID()
	if err != nil {
		s.logError(ctx, "identifier generation failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "finalization failed"))
		return
	}
	order.Status = OrderProcessing
	order.CSR = der
	task := &Task{ID: taskID, Kind: TaskIssue, TargetID: order.ID, AccountID: order.AccountID, RunAt: now, CreatedAt: now}
	err = s.store.FinalizeOrder(ctx, order, task)
	switch {
	case err == nil:
		s.workAccepted(ctx)
	case errors.Is(err, ErrRevisionMismatch):
		current, lookupErr := s.store.Order(ctx, order.ID)
		if lookupErr != nil || !bytes.Equal(current.CSR, der) {
			s.writeProblem(ctx, w, NewProblem(ErrorOrderNotReady, "order changed concurrently, retry the request"))
			return
		}
		order = current
	default:
		s.logError(ctx, "finalization failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "finalization failed"))
		return
	}
	s.writeOrder(ctx, w, http.StatusOK, order, now)
}

// Requires every authorization of the order to have granted exactly what the request asks for,
// see RFC 9448 section 6 step 9. A network challenge grants nothing, so a request for a CA
// certificate needs a granting challenge behind every identifier, and a grant that one identifier
// received cannot be dropped by requesting an end-entity certificate alongside other identifiers.
func (s *Server) checkCAGrants(ctx context.Context, order *Order, csr *x509.CertificateRequest) *Problem {
	requested, err := csrCACertificate(csr.Extensions)
	if err != nil {
		return NewProblem(ErrorBadCSR, "CSR basic constraints could not be read")
	}
	for _, id := range order.AuthorizationIDs {
		authz, err := s.store.Authorization(ctx, id)
		if err != nil {
			return s.storeProblem(ctx, err, "authorization")
		}
		if authz.CACertificate != requested {
			return NewProblem(ErrorBadCSR, "CSR CA basic constraint does not match the granted authorization")
		}
	}
	return nil
}
