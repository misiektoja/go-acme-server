package acmeserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/misiektoja/go-acme-server/internal/jws"
)

// The CRL reason codes clients may request, see RFC 5280 section 5.3.1. Hold and CA reasons
// are refused.
var allowedRevocationReasons = []int{0, 1, 3, 4, 5}

// The revokeCert payload of RFC 8555 section 7.6.
type revokeJSON struct {
	Certificate string `json:"certificate"`
	Reason      *int   `json:"reason"`
}

// Revokes a certificate on proof from its account or its key, see RFC 8555 section 7.6.
func (s *Server) serveRevokeCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, p := s.readSignedRequest(r, resourceRevokeCert, keyModeEither)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	var payload revokeJSON
	if p := decodePayload(req.Payload, &payload); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(payload.Certificate)
	if err != nil || len(der) == 0 {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "certificate is not valid base64url"))
		return
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "certificate could not be parsed"))
		return
	}
	reason := 0
	if payload.Reason != nil {
		reason = *payload.Reason
	}
	if !slices.Contains(allowedRevocationReasons, reason) {
		s.writeProblem(ctx, w, Problemf(ErrorBadRevocationReason, "revocation reason %d is not allowed", reason))
		return
	}
	cert, err := s.store.Certificate(ctx, certificateID(der))
	if err != nil || len(cert.Chain) == 0 || !bytes.Equal(cert.Chain[0], der) {
		if err != nil && !errors.Is(err, ErrNotFound) {
			s.writeProblem(ctx, w, s.storeProblem(ctx, err, "certificate"))
			return
		}
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "certificate was not issued by this server").
			WithStatus(http.StatusNotFound))
		return
	}
	if p := s.authorizeRevocation(ctx, req, cert, leaf); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	cert, p = s.beginRevocation(ctx, cert, reason)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	revokeReq := RevokeRequest{OperationID: cert.RevocationOperationID, Certificate: leaf, DER: der,
		Reason: cert.RevocationReason}
	if req.Account != nil {
		revokeReq.AccountID = req.Account.ID
	}
	if err := s.revoker.Revoke(ctx, revokeReq); err != nil {
		if p, ok := AsProblem(err); ok {
			s.abandonRevocation(ctx, cert)
			s.writeProblem(ctx, w, p)
			return
		}
		s.logError(ctx, "revocation failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "revocation failed"))
		return
	}
	if p := s.recordRevocation(ctx, cert); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	s.setCommonHeaders(w)
	s.addNonce(ctx, w)
	w.WriteHeader(http.StatusOK)
}

// Accepts the issuing account, an account authorized for every identifier or the certificate key.
// A network function certificate leaves out the second way, because 3GPP TS 33.310 clause J.4
// limits its revocation to the enrolling client and the holder of the certificate key.
func (s *Server) authorizeRevocation(ctx context.Context, req *signedRequest, cert *Certificate, leaf *x509.Certificate) *Problem {
	if req.Account != nil {
		if req.Account.ID == cert.AccountID {
			return nil
		}
		ids, err := revocationIdentifiers(leaf)
		if err != nil {
			return NewProblem(ErrorUnauthorized, "certificate identifiers cannot be authorized")
		}
		if slices.ContainsFunc(ids, func(id Identifier) bool { return id.Type == IdentifierNfInstanceID }) {
			return NewProblem(ErrorUnauthorized, "a network function certificate is revoked by the enrolling account "+
				"or with the certificate key")
		}
		allowed, err := s.store.AuthorizedFor(ctx, req.Account.ID, ids, s.clock.Now())
		if err != nil {
			return s.storeProblem(ctx, err, "authorization")
		}
		if allowed {
			return nil
		}
		return NewProblem(ErrorUnauthorized, "the signing account is not authorized for every certificate identifier")
	}
	signer, err := jws.Thumbprint(req.Key)
	if err != nil {
		return NewProblem(ErrorBadPublicKey, "signing key cannot be thumbprinted")
	}
	certKey, err := jws.Thumbprint(leaf.PublicKey)
	if err != nil || signer != certKey {
		return NewProblem(ErrorUnauthorized, "the signing key is not the certificate key")
	}
	return nil
}

// Commits the operation ID and reason before the CA call. A retry after an uncertain answer and a
// concurrent request both continue the recorded operation instead of starting another.
func (s *Server) beginRevocation(ctx context.Context, cert *Certificate, reason int) (*Certificate, *Problem) {
	for range 2 {
		switch {
		case cert.Revoked:
			return nil, NewProblem(ErrorAlreadyRevoked, "certificate is already revoked")
		case cert.RevocationOperationID != "":
			return cert, nil
		}
		id, err := newID()
		if err != nil {
			s.logError(ctx, "identifier generation failed", err)
			return nil, NewProblem(ErrorServerInternal, "revocation could not be recorded")
		}
		cert.RevocationOperationID, cert.RevocationReason, cert.RevocationRequestedAt = id, reason, s.clock.Now()
		err = s.store.UpdateCertificate(ctx, cert)
		if err == nil {
			return cert, nil
		}
		if !errors.Is(err, ErrRevisionMismatch) {
			s.logError(ctx, "revocation record failed", err)
			return nil, NewProblem(ErrorServerInternal, "revocation could not be recorded")
		}
		if cert, err = s.store.Certificate(ctx, cert.ID); err != nil {
			return nil, s.storeProblem(ctx, err, "certificate")
		}
	}
	return nil, NewProblem(ErrorServerInternal, "revocation could not be recorded")
}

// Stores the revocation, detached from the client request because the CA has already acted and a
// disconnect must not leave the certificate recorded as live. A concurrent revocation of the same
// certificate is treated as success.
func (s *Server) recordRevocation(parent context.Context, cert *Certificate) *Problem {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.detachedWrite)
	defer cancel()
	operationID, reason, requestedAt := cert.RevocationOperationID, cert.RevocationReason, cert.RevocationRequestedAt
	var err error
	// A concurrent request refused by the CA may have cleared the record while this call succeeded,
	// so the accepted operation is written over the current version once.
	for range 2 {
		cert.Revoked = true
		cert.RevokedAt = s.clock.Now()
		cert.RevocationOperationID, cert.RevocationReason, cert.RevocationRequestedAt = operationID, reason, requestedAt
		if err = s.store.UpdateCertificate(ctx, cert); !errors.Is(err, ErrRevisionMismatch) {
			break
		}
		current, lookupErr := s.store.Certificate(ctx, cert.ID)
		if lookupErr != nil {
			err = lookupErr
			break
		}
		if current.Revoked {
			return nil
		}
		cert = current
	}
	if err != nil {
		s.logError(ctx, "revocation record failed", err)
		return NewProblem(ErrorServerInternal, "revocation could not be recorded")
	}
	return nil
}

// Clears the recorded operation after the CA refused it with a problem, so the next request starts
// a new operation with its own reason. The write is detached so a disconnect cannot keep the
// refused operation. A concurrent change to the certificate is left in place.
func (s *Server) abandonRevocation(parent context.Context, cert *Certificate) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.detachedWrite)
	defer cancel()
	cert.RevocationOperationID, cert.RevocationReason, cert.RevocationRequestedAt = "", 0, time.Time{}
	if err := s.store.UpdateCertificate(ctx, cert); err != nil && !errors.Is(err, ErrRevisionMismatch) {
		s.logError(ctx, "refused revocation could not be cleared", err)
	}
}
