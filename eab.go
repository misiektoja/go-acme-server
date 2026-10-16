package acmeserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

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
	if errors.Is(err, ErrNotFound) {
		return "", NewProblem(ErrorUnauthorized, "external account key is unknown")
	}
	if p := s.hostProblem(ctx, err, "external account key lookup"); p != nil {
		return "", p
	}
	if err := msg.VerifyMAC(key); err != nil {
		if jerr, ok := errors.AsType[*jws.Error](err); ok && jerr.Code == jws.CodeBadSignatureAlgorithm {
			return "", s.shortMACKeyProblem(ctx, msg.Header.KeyID, key, jerr)
		}
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

// Refuses a binding whose algorithm needs a longer MAC key than the host holds. The problem lists
// the HMAC algorithms the key allows. A key too short for any of them is the host's mistake, so
// it is logged and the client is told to ask for a new key.
func (s *Server) shortMACKeyProblem(ctx context.Context, keyID string, key []byte, cause *jws.Error) *Problem {
	usable := jws.MACAlgorithmsFor(len(key))
	if len(usable) == 0 {
		s.log.LogAttrs(ctx, slog.LevelError, "external account key is shorter than 256 bits",
			slog.String("kid", keyID), slog.Int("bits", len(key)*8))
		return NewProblem(ErrorUnauthorized,
			"external account key is too short for any HMAC algorithm. Ask the server operator for a new key")
	}
	p := NewProblem(ErrorBadSignatureAlgorithm, "externalAccountBinding: "+cause.Detail)
	p.Algorithms = usable
	return p
}
