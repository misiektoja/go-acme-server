package acmeserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"

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
	if cert.Revoked {
		s.writeProblem(ctx, w, NewProblem(ErrorAlreadyRevoked, "certificate is already revoked"))
		return
	}
	revokeReq := RevokeRequest{Certificate: leaf, DER: der, Reason: reason}
	if req.Account != nil {
		revokeReq.AccountID = req.Account.ID
	}
	if err := s.revoker.Revoke(ctx, revokeReq); err != nil {
		if p, ok := AsProblem(err); ok {
			s.writeProblem(ctx, w, p)
			return
		}
		s.logError(ctx, "revocation failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "revocation failed"))
		return
	}
	if p := s.recordRevocation(r, cert, reason); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	s.setCommonHeaders(w)
	s.addNonce(ctx, w)
	w.WriteHeader(http.StatusOK)
}

// Accepts the issuing account, an account authorized for every identifier or the certificate key.
func (s *Server) authorizeRevocation(ctx context.Context, req *signedRequest, cert *Certificate, leaf *x509.Certificate) *Problem {
	if req.Account != nil {
		if req.Account.ID == cert.AccountID {
			return nil
		}
		ids, err := certificateIdentifiers(leaf)
		if err != nil {
			return NewProblem(ErrorUnauthorized, "certificate identifiers cannot be authorized")
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

// Stores the revocation. A concurrent revocation of the same certificate is treated as success.
func (s *Server) recordRevocation(r *http.Request, cert *Certificate, reason int) *Problem {
	ctx := r.Context()
	cert.Revoked = true
	cert.RevokedAt = s.clock.Now()
	cert.RevocationReason = reason
	err := s.store.UpdateCertificate(ctx, cert)
	if errors.Is(err, ErrRevisionMismatch) {
		current, lookupErr := s.store.Certificate(ctx, cert.ID)
		if lookupErr == nil && current.Revoked {
			return nil
		}
	}
	if err != nil {
		s.logError(ctx, "revocation record failed", err)
		return NewProblem(ErrorServerInternal, "revocation could not be recorded")
	}
	return nil
}
