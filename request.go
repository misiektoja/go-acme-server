package acmeserver

import (
	"crypto"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/misiektoja/go-acme-server/internal/jws"
)

// States how a POST resource identifies the signing key, see RFC 8555 section 6.2.
type keyMode int

// Key modes.
const (
	// Requires kid naming an existing account.
	keyModeAccount keyMode = iota
	// Requires jwk, as newAccount does.
	keyModeEmbedded
	// Accepts jwk or kid, as revokeCert does.
	keyModeEither
)

// Bounds the opaque resource IDs that appear in URLs.
const maxIDLength = 64

// A verified ACME POST with its nonce consumed and signature checked.
type signedRequest struct {
	// The authenticated account, or nil for an embedded key.
	Account *Account
	// The key that produced the signature.
	Key crypto.PublicKey
	// The decoded payload. It is empty for POST-as-GET.
	Payload []byte
}

// Validates a POST body against RFC 8555 section 6. rel is the path below the base URL.
func (s *Server) readSignedRequest(r *http.Request, rel string, mode keyMode) (*signedRequest, *Problem) {
	ctx := r.Context()
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != contentTypeJOSE {
		return nil, NewProblem(ErrorMalformed, "Content-Type must be "+contentTypeJOSE).
			WithStatus(http.StatusUnsupportedMediaType)
	}
	body, p := s.readBody(r)
	if p != nil {
		return nil, p
	}
	msg, err := jws.Parse(body)
	if err != nil {
		return nil, problemFromJWS(err)
	}
	valid, err := s.nonces.Consume(ctx, msg.Header.Nonce)
	if err != nil {
		s.log.LogAttrs(ctx, slog.LevelError, "nonce lookup failed", slog.Any("error", err))
		return nil, NewProblem(ErrorServerInternal, "nonce lookup failed")
	}
	if !valid {
		return nil, NewProblem(ErrorBadNonce, "JWS nonce is unknown or was already used")
	}
	if msg.Header.URL != s.resourceURL(rel) {
		return nil, NewProblem(ErrorUnauthorized, "JWS url does not match the request URL")
	}
	req := &signedRequest{Payload: msg.Payload}
	if msg.Header.Key != nil {
		if mode == keyModeAccount {
			return nil, NewProblem(ErrorMalformed, "this resource requires kid, not an embedded jwk")
		}
		req.Key = msg.Header.Key
	} else {
		if mode == keyModeEmbedded {
			return nil, NewProblem(ErrorMalformed, "this resource requires an embedded jwk, not kid")
		}
		account, p := s.lookupAccount(r, msg.Header.KeyID)
		if p != nil {
			return nil, p
		}
		req.Account, req.Key = account, account.Key
	}
	if err := msg.Verify(req.Key); err != nil {
		return nil, problemFromJWS(err)
	}
	return req, nil
}

// Reads at most maxBody bytes and rejects longer bodies.
func (s *Server) readBody(r *http.Request) ([]byte, *Problem) {
	if r.Body == nil {
		return nil, NewProblem(ErrorMalformed, "request has no body")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody+1))
	if err != nil {
		return nil, NewProblem(ErrorMalformed, "request body could not be read")
	}
	if int64(len(body)) > s.maxBody {
		return nil, Problemf(ErrorMalformed, "request body exceeds %d bytes", s.maxBody).
			WithStatus(http.StatusRequestEntityTooLarge)
	}
	return body, nil
}

// Resolves a kid to a valid account of this server.
func (s *Server) lookupAccount(r *http.Request, kid string) (*Account, *Problem) {
	id, ok := s.accountIDFromURL(kid)
	if !ok {
		return nil, NewProblem(ErrorMalformed, "JWS kid is not an account URL of this server")
	}
	account, err := s.store.Account(r.Context(), id)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, NewProblem(ErrorAccountDoesNotExist, "account does not exist")
	case err != nil:
		s.log.LogAttrs(r.Context(), slog.LevelError, "account lookup failed",
			slog.String("account", id), slog.Any("error", err))
		return nil, NewProblem(ErrorServerInternal, "account lookup failed")
	}
	if account.Status != AccountValid {
		return nil, Problemf(ErrorUnauthorized, "account is %s", string(account.Status))
	}
	return account, nil
}

// Extracts the account ID from an account URL of this server.
func (s *Server) accountIDFromURL(u string) (string, bool) {
	id, ok := strings.CutPrefix(u, s.resourceURL(accountPathPrefix))
	if !ok || !validID(id) {
		return "", false
	}
	return id, true
}

// Reports whether s is a well formed opaque resource ID.
func validID(s string) bool {
	if s == "" || len(s) > maxIDLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// Maps a JWS rejection to the ACME problem the client receives.
func problemFromJWS(err error) *Problem {
	var jwsErr *jws.Error
	if !errors.As(err, &jwsErr) {
		return NewProblem(ErrorMalformed, "invalid JWS")
	}
	switch jwsErr.Code {
	case jws.CodeBadNonce:
		return NewProblem(ErrorBadNonce, jwsErr.Detail)
	case jws.CodeBadSignatureAlgorithm:
		p := NewProblem(ErrorBadSignatureAlgorithm, jwsErr.Detail)
		p.Algorithms = append([]string(nil), jws.Algorithms...)
		return p
	case jws.CodeBadPublicKey:
		return NewProblem(ErrorBadPublicKey, jwsErr.Detail)
	case jws.CodeBadSignature:
		return NewProblem(ErrorUnauthorized, jwsErr.Detail)
	case jws.CodeMalformed:
		return NewProblem(ErrorMalformed, jwsErr.Detail)
	}
	return NewProblem(ErrorMalformed, jwsErr.Detail)
}
