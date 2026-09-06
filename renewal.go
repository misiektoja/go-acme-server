package acmeserver

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"
)

// The renewalInfo object of RFC 9773 section 4.2 with the Retry-After the response carries.
type RenewalInfo struct {
	// The window in which the client should renew. End must be later than Start.
	Start time.Time
	End   time.Time
	// An optional page explaining the window.
	ExplanationURL string
	// How long clients wait before asking again. Zero means DefaultRenewalRetryAfter.
	RetryAfter time.Duration
}

// Suggests when a certificate should be renewed, see RFC 9773. Setting Config.RenewalInfo
// advertises the renewalInfo resource and accepts replaces on new orders.
type RenewalAdvisor interface {
	RenewalInfo(ctx context.Context, cert *Certificate) (RenewalInfo, error)
}

// The Retry-After of renewalInfo responses when the advisor sets none.
const DefaultRenewalRetryAfter = 6 * time.Hour

// A RenewalAdvisor that places the window at fixed fractions of the certificate lifetime and
// asks for immediate renewal of revoked certificates.
type LifetimeRenewal struct {
	// Fractions of the lifetime at which the window starts and ends. Zero values mean two
	// thirds and five sixths.
	Start float64
	End   float64
	// Copied into every response.
	ExplanationURL string
	RetryAfter     time.Duration
}

// Returns the window for the certificate. A revoked certificate gets a window that opened at
// its revocation, so clients renew at once.
func (l LifetimeRenewal) RenewalInfo(_ context.Context, cert *Certificate) (RenewalInfo, error) {
	info := RenewalInfo{ExplanationURL: l.ExplanationURL, RetryAfter: l.RetryAfter}
	if cert.Revoked {
		info.Start, info.End = cert.RevokedAt, cert.RevokedAt.Add(time.Minute)
		return info, nil
	}
	start, end := l.Start, l.End
	if start == 0 {
		start = 2.0 / 3
	}
	if end == 0 {
		end = 5.0 / 6
	}
	if start < 0 || end <= start || end > 1 {
		return RenewalInfo{}, errors.New("acmeserver: LifetimeRenewal needs 0 <= Start < End <= 1")
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	info.Start = cert.NotBefore.Add(time.Duration(float64(lifetime) * start)).Truncate(time.Second)
	info.End = cert.NotBefore.Add(time.Duration(float64(lifetime) * end)).Truncate(time.Second)
	return info, nil
}

// The renewalInfo object clients receive.
type renewalInfoJSON struct {
	SuggestedWindow struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} `json:"suggestedWindow"`
	ExplanationURL string `json:"explanationURL,omitempty"`
}

// Answers the unauthenticated renewalInfo GET of RFC 9773 section 4.1.
func (s *Server) serveRenewalInfo(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeMethodNotAllowed(ctx, w, http.MethodGet, http.MethodHead)
		return
	}
	if s.renewal == nil || !validRenewalID(id) {
		s.writeProblem(ctx, w, notFound())
		return
	}
	cert, err := s.store.CertificateByRenewalID(ctx, id)
	if err != nil {
		s.writeProblem(ctx, w, s.storeProblem(ctx, err, "certificate"))
		return
	}
	info, err := s.renewal.RenewalInfo(ctx, cert)
	if err == nil && !info.End.After(info.Start) {
		err = errors.New("acmeserver: renewal window end is not after its start")
	}
	if err != nil {
		s.logError(ctx, "renewal information failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "renewal information unavailable"))
		return
	}
	if info.RetryAfter <= 0 {
		info.RetryAfter = DefaultRenewalRetryAfter
	}
	var body renewalInfoJSON
	body.SuggestedWindow.Start, body.SuggestedWindow.End = formatTime(info.Start), formatTime(info.End)
	body.ExplanationURL = info.ExplanationURL
	s.setCommonHeaders(w)
	w.Header().Set("Retry-After", strconv.FormatInt(int64(info.RetryAfter.Round(time.Second).Seconds()), 10))
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	s.writeBody(w, body)
}

// Checks a replaces value against the stored predecessor, see RFC 9773 section 5, and returns
// the identifier to store.
func (s *Server) checkReplaces(ctx context.Context, account *Account, identifiers []Identifier, replaces string) (string, *Problem) {
	if replaces == "" || s.renewal == nil {
		return "", nil
	}
	if !validRenewalID(replaces) {
		return "", NewProblem(ErrorMalformed, "replaces is not a certificate identifier")
	}
	cert, err := s.store.CertificateByRenewalID(ctx, replaces)
	if errors.Is(err, ErrNotFound) {
		return "", NewProblem(ErrorMalformed, "replaces names an unknown certificate")
	}
	if err != nil {
		return "", s.storeProblem(ctx, err, "certificate")
	}
	if cert.AccountID != account.ID {
		return "", NewProblem(ErrorUnauthorized, "replaces names a certificate of another account")
	}
	if !sharesIdentifier(cert.Validations, identifiers) {
		return "", NewProblem(ErrorMalformed, "the order shares no identifier with the certificate it replaces")
	}
	return replaces, nil
}

// Reports whether any validated identifier of the predecessor appears in the new order.
func sharesIdentifier(validations []Validation, identifiers []Identifier) bool {
	for _, v := range validations {
		if slices.Contains(identifiers, v.Identifier) {
			return true
		}
	}
	return false
}

// Maps a CreateOrder failure of a replacing order to its problem.
func replacementProblem(err error) *Problem {
	switch {
	case errors.Is(err, ErrAlreadyReplaced):
		return NewProblem(ErrorAlreadyReplaced, "the certificate is already being replaced by another order")
	case errors.Is(err, ErrNotFound):
		return NewProblem(ErrorMalformed, "replaces names an unknown certificate")
	}
	return nil
}
