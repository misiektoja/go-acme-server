package acmeserver

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/misiektoja/go-acme-server/internal/jws"
)

// Verifies an external account binding and returns its key identifier, see RFC 8555 section
// 7.3.4. The binding must be signed with the MAC key of its kid over the account key.
func (s *Server) verifyExternalAccountBinding(ctx context.Context, accountThumbprint string,
	raw json.RawMessage) (string, *Problem) {
	if s.eabKeys == nil {
		return "", NewProblem(ErrorMalformed, "external account bindings are not accepted")
	}
	msg, err := jws.ParseMAC(raw)
	if err != nil {
		p := problemFromJWS(err)
		if p.Type == ErrorBadSignatureAlgorithm {
			p.Algorithms = append([]string(nil), jws.MACAlgorithms...)
			return "", p
		}
		return "", NewProblem(ErrorMalformed, "externalAccountBinding: "+p.Detail)
	}
	if msg.Header.URL != s.resourceURL(resourceNewAccount) {
		return "", NewProblem(ErrorMalformed, "externalAccountBinding url does not match the request URL")
	}
	key, err := s.eabKeys.MACKey(ctx, msg.Header.KeyID)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", NewProblem(ErrorUnauthorized, "external account key is unknown")
	case err != nil:
		s.logError(ctx, "external account key lookup failed", err)
		return "", NewProblem(ErrorServerInternal, "external account key lookup failed")
	}
	if err := msg.VerifyMAC(key); err != nil {
		return "", NewProblem(ErrorUnauthorized, "externalAccountBinding signature verification failed")
	}
	boundKey, err := jws.ParseJWK(msg.Payload)
	if err != nil {
		return "", NewProblem(ErrorMalformed, "externalAccountBinding payload: "+err.Error())
	}
	boundThumbprint, err := jws.Thumbprint(boundKey)
	if err != nil || boundThumbprint != accountThumbprint {
		return "", NewProblem(ErrorMalformed, "externalAccountBinding payload is not the account key")
	}
	return msg.Header.KeyID, nil
}
