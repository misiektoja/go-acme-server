package acmeserver

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/misiektoja/go-acme-server/internal/jws"
)

// The seconds clients should wait before polling a processing order again.
const processingRetryAfter = 3

// The account object of RFC 8555 section 7.1.2.
type accountJSON struct {
	Status               AccountStatus `json:"status"`
	Contact              []string      `json:"contact,omitempty"`
	TermsOfServiceAgreed bool          `json:"termsOfServiceAgreed,omitempty"`
	Orders               string        `json:"orders"`
}

// The order object of RFC 8555 section 7.1.3.
type orderJSON struct {
	Status         OrderStatus  `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Error          *Problem     `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Replaces       string       `json:"replaces,omitempty"`
}

// The authorization object of RFC 8555 section 7.1.4.
type authorizationJSON struct {
	Identifier Identifier          `json:"identifier"`
	Status     AuthorizationStatus `json:"status"`
	Expires    string              `json:"expires,omitempty"`
	Challenges []challengeJSON     `json:"challenges"`
	Wildcard   bool                `json:"wildcard,omitempty"`
}

// The challenge object of RFC 8555 section 7.1.5 with the tkauth-01 members of RFC 9447
// section 3.
type challengeJSON struct {
	Type   ChallengeType   `json:"type"`
	URL    string          `json:"url"`
	Status ChallengeStatus `json:"status"`
	Token  string          `json:"token"`
	// The Authority Token subtype, always atc on a tkauth-01 challenge.
	TKAuthType string `json:"tkauth-type,omitempty"`
	// Where a client may obtain the Authority Token, when the server names one.
	TokenAuthority string   `json:"token-authority,omitempty"`
	Validated      string   `json:"validated,omitempty"`
	Error          *Problem `json:"error,omitempty"`
}

// Returns the wire form of an account.
func (s *Server) accountView(account *Account) accountJSON {
	return accountJSON{
		Status:               account.Status,
		Contact:              account.Contact,
		TermsOfServiceAgreed: account.TermsOfServiceAgreed,
		Orders:               s.accountURL(account.ID) + "/orders",
	}
}

// Returns the wire form of an order at the given time.
func (s *Server) orderView(order *Order, now time.Time) orderJSON {
	view := orderJSON{
		Status:      effectiveOrderStatus(order, now),
		Expires:     formatTime(order.Expires),
		Identifiers: order.Identifiers,
		NotBefore:   formatTime(order.NotBefore),
		NotAfter:    formatTime(order.NotAfter),
		Error:       order.Error,
		Finalize:    s.resourceURL(orderPathPrefix + order.ID + "/finalize"),
		Replaces:    order.Replaces,
	}
	view.Authorizations = make([]string, len(order.AuthorizationIDs))
	for i, id := range order.AuthorizationIDs {
		view.Authorizations[i] = s.resourceURL(authzPathPrefix + id)
	}
	if order.CertificateID != "" && view.Status == OrderValid {
		view.Certificate = s.resourceURL(certPathPrefix + order.CertificateID)
	}
	return view
}

// Returns the wire form of an authorization. A valid authorization lists only the challenge that
// validated it.
func (s *Server) authorizationView(authz *Authorization, challenges []*Challenge, now time.Time) authorizationJSON {
	status := effectiveAuthzStatus(authz, now)
	view := authorizationJSON{
		Identifier: authz.Identifier,
		Status:     status,
		Expires:    formatTime(authz.Expires),
		Wildcard:   authz.Wildcard,
		Challenges: make([]challengeJSON, 0, len(challenges)),
	}
	for _, ch := range challenges {
		if status == AuthorizationValid && ch.Status != ChallengeValid {
			continue
		}
		view.Challenges = append(view.Challenges, s.challengeView(ch))
	}
	return view
}

// Returns the wire form of a challenge.
func (s *Server) challengeView(ch *Challenge) challengeJSON {
	view := challengeJSON{
		Type:      ch.Type,
		URL:       s.resourceURL(challengePathPrefix + ch.ID),
		Status:    ch.Status,
		Token:     ch.Token,
		Validated: formatTime(ch.Validated),
		Error:     ch.Error,
	}
	if ch.Type == ChallengeTKAuth01 {
		view.TKAuthType = TKAuthTypeATC
		view.TokenAuthority = s.tokenAuthority
	}
	return view
}

// Returns the status clients see at now.
func effectiveOrderStatus(order *Order, now time.Time) OrderStatus { return order.StatusAt(now) }

// Returns the status clients see, treating an expired pending or valid authorization as expired.
func effectiveAuthzStatus(authz *Authorization, now time.Time) AuthorizationStatus {
	if (authz.Status == AuthorizationPending || authz.Status == AuthorizationValid) && !authz.Expires.After(now) {
		return AuthorizationExpired
	}
	return authz.Status
}

// Returns the RFC 3339 UTC form of t, or an empty string for the zero time.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Returns the URL of an account resource.
func (s *Server) accountURL(id string) string { return s.resourceURL(accountPathPrefix + id) }

// Writes a JSON resource with the common headers and a fresh nonce.
func (s *Server) writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	s.setCommonHeaders(w)
	s.addNonce(ctx, w)
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	s.writeBody(w, v)
}

// Writes an order with its URL in Location and asks processing clients to poll later. Every order
// response names the order because the Go crypto/acme client reads the URL it polls after
// finalization from that header.
func (s *Server) writeOrder(ctx context.Context, w http.ResponseWriter, status int, order *Order, now time.Time) {
	w.Header().Set("Location", s.resourceURL(orderPathPrefix+order.ID))
	view := s.orderView(order, now)
	if view.Status == OrderProcessing {
		w.Header().Set("Retry-After", strconv.Itoa(processingRetryAfter))
	}
	s.writeJSON(ctx, w, status, view)
}

// Writes a challenge and asks clients to poll a processing one later, see RFC 8555 section 7.5.1.
func (s *Server) writeChallenge(ctx context.Context, w http.ResponseWriter, ch *Challenge) {
	if ch.Status == ChallengeProcessing {
		w.Header().Set("Retry-After", strconv.Itoa(processingRetryAfter))
	}
	s.writeJSON(ctx, w, http.StatusOK, s.challengeView(ch))
}

// Decodes a request payload into v with the strict JSON rules.
func decodePayload(payload []byte, v any) *Problem {
	if err := jws.UnmarshalStrict(payload, v); err != nil {
		return NewProblem(ErrorMalformed, "request payload: "+err.Error())
	}
	return nil
}

// Rejects a request that carries a payload where POST-as-GET is required.
func requireEmptyPayload(req *signedRequest) *Problem {
	if len(req.Payload) != 0 {
		return NewProblem(ErrorMalformed, "this resource only accepts POST-as-GET requests")
	}
	return nil
}

// Returns a problem for a store failure, logging backend errors.
func (s *Server) storeProblem(ctx context.Context, err error, resource string) *Problem {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrNotFound) {
		return notFound()
	}
	s.logError(ctx, resource+" lookup failed", err)
	return NewProblem(ErrorServerInternal, resource+" lookup failed")
}
