package acmeserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Prefixes every ACME error type in a problem document.
const ProblemNamespace = "urn:ietf:params:acme:error:"

// Names an ACME error without its URN namespace.
type ErrorType string

// Error types registered by RFC 8555 section 6.7 and RFC 9773 section 5.
const (
	ErrorAccountDoesNotExist     ErrorType = "accountDoesNotExist"
	ErrorAlreadyReplaced         ErrorType = "alreadyReplaced"
	ErrorAlreadyRevoked          ErrorType = "alreadyRevoked"
	ErrorBadCSR                  ErrorType = "badCSR"
	ErrorBadNonce                ErrorType = "badNonce"
	ErrorBadPublicKey            ErrorType = "badPublicKey"
	ErrorBadRevocationReason     ErrorType = "badRevocationReason"
	ErrorBadSignatureAlgorithm   ErrorType = "badSignatureAlgorithm"
	ErrorCAA                     ErrorType = "caa"
	ErrorCompound                ErrorType = "compound"
	ErrorConnection              ErrorType = "connection"
	ErrorDNS                     ErrorType = "dns"
	ErrorDNSSEC                  ErrorType = "dnssec"
	ErrorExternalAccountRequired ErrorType = "externalAccountRequired"
	ErrorIncorrectResponse       ErrorType = "incorrectResponse"
	ErrorInvalidContact          ErrorType = "invalidContact"
	ErrorMalformed               ErrorType = "malformed"
	ErrorOrderNotReady           ErrorType = "orderNotReady"
	ErrorRateLimited             ErrorType = "rateLimited"
	ErrorRejectedIdentifier      ErrorType = "rejectedIdentifier"
	ErrorServerInternal          ErrorType = "serverInternal"
	ErrorTLS                     ErrorType = "tls"
	ErrorUnauthorized            ErrorType = "unauthorized"
	ErrorUnsupportedContact      ErrorType = "unsupportedContact"
	ErrorUnsupportedIdentifier   ErrorType = "unsupportedIdentifier"
	ErrorUserActionRequired      ErrorType = "userActionRequired"
)

// Returns the fully qualified problem type.
func (t ErrorType) URN() string { return ProblemNamespace + string(t) }

// The HTTP status a problem of each type uses unless it sets its own.
var defaultStatus = map[ErrorType]int{
	ErrorAccountDoesNotExist:     http.StatusBadRequest,
	ErrorAlreadyReplaced:         http.StatusConflict,
	ErrorAlreadyRevoked:          http.StatusBadRequest,
	ErrorBadCSR:                  http.StatusBadRequest,
	ErrorBadNonce:                http.StatusBadRequest,
	ErrorBadPublicKey:            http.StatusBadRequest,
	ErrorBadRevocationReason:     http.StatusBadRequest,
	ErrorBadSignatureAlgorithm:   http.StatusBadRequest,
	ErrorCAA:                     http.StatusForbidden,
	ErrorCompound:                http.StatusBadRequest,
	ErrorConnection:              http.StatusBadRequest,
	ErrorDNS:                     http.StatusBadRequest,
	ErrorDNSSEC:                  http.StatusBadRequest,
	ErrorExternalAccountRequired: http.StatusForbidden,
	ErrorIncorrectResponse:       http.StatusBadRequest,
	ErrorInvalidContact:          http.StatusBadRequest,
	ErrorMalformed:               http.StatusBadRequest,
	ErrorOrderNotReady:           http.StatusForbidden,
	ErrorRateLimited:             http.StatusTooManyRequests,
	ErrorRejectedIdentifier:      http.StatusBadRequest,
	ErrorServerInternal:          http.StatusInternalServerError,
	ErrorTLS:                     http.StatusBadRequest,
	ErrorUnauthorized:            http.StatusForbidden,
	ErrorUnsupportedContact:      http.StatusBadRequest,
	ErrorUnsupportedIdentifier:   http.StatusBadRequest,
	ErrorUserActionRequired:      http.StatusForbidden,
}

// An ACME problem document, see RFC 7807 and RFC 8555 section 6.7. It implements error.
type Problem struct {
	Type   ErrorType
	Detail string
	// Overrides the default HTTP status of the type when it is not zero.
	Status int
	// Names the identifier a subproblem refers to.
	Identifier  *Identifier
	Subproblems []*Problem
	// Lists the supported signature algorithms in a badSignatureAlgorithm problem.
	Algorithms []string
	// Sets the Retry-After header. It is not serialized.
	RetryAfter time.Duration
}

// Returns a problem of the given type with the default HTTP status of that type.
func NewProblem(t ErrorType, detail string) *Problem { return &Problem{Type: t, Detail: detail} }

// Returns a problem whose detail is formatted from the arguments.
func Problemf(t ErrorType, format string, args ...any) *Problem {
	return &Problem{Type: t, Detail: fmt.Sprintf(format, args...)}
}

// Returns a compound problem that carries the given subproblems.
func Compound(detail string, subproblems ...*Problem) *Problem {
	return &Problem{Type: ErrorCompound, Detail: detail, Subproblems: subproblems}
}

// Returns the fully qualified type followed by the detail.
func (p *Problem) Error() string {
	if p.Detail == "" {
		return p.Type.URN()
	}
	return p.Type.URN() + ": " + p.Detail
}

// Returns the status the problem is written with.
func (p *Problem) HTTPStatus() int {
	if p.Status != 0 {
		return p.Status
	}
	if status, ok := defaultStatus[p.Type]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// Returns a copy that overrides the HTTP status.
func (p *Problem) WithStatus(status int) *Problem {
	c := *p
	c.Status = status
	return &c
}

// Returns a copy that names the affected identifier.
func (p *Problem) WithIdentifier(id Identifier) *Problem {
	c := *p
	c.Identifier = &id
	return &c
}

// Returns a copy that asks the client to wait before retrying.
func (p *Problem) WithRetryAfter(d time.Duration) *Problem {
	c := *p
	c.RetryAfter = d
	return &c
}

// The wire form of a top-level problem document.
type problemJSON struct {
	Type        string            `json:"type"`
	Detail      string            `json:"detail,omitempty"`
	Status      int               `json:"status,omitempty"`
	Identifier  *Identifier       `json:"identifier,omitempty"`
	Subproblems []*subproblemJSON `json:"subproblems,omitempty"`
	Algorithms  []string          `json:"algorithms,omitempty"`
}

// The wire form of an entry in the subproblems array, which carries no status.
type subproblemJSON struct {
	Type       string      `json:"type"`
	Detail     string      `json:"detail,omitempty"`
	Identifier *Identifier `json:"identifier,omitempty"`
}

// Writes the problem document with fully qualified types.
func (p *Problem) MarshalJSON() ([]byte, error) {
	out := problemJSON{
		Type:       p.Type.URN(),
		Detail:     p.Detail,
		Status:     p.HTTPStatus(),
		Identifier: p.Identifier,
		Algorithms: p.Algorithms,
	}
	for _, sub := range p.Subproblems {
		if sub == nil {
			continue
		}
		out.Subproblems = append(out.Subproblems, &subproblemJSON{
			Type:       sub.Type.URN(),
			Detail:     sub.Detail,
			Identifier: sub.Identifier,
		})
	}
	return json.Marshal(out)
}

// Reads a problem document and strips the ACME namespace from its types.
func (p *Problem) UnmarshalJSON(data []byte) error {
	var in struct {
		Type        string      `json:"type"`
		Detail      string      `json:"detail"`
		Status      int         `json:"status"`
		Identifier  *Identifier `json:"identifier"`
		Subproblems []*Problem  `json:"subproblems"`
		Algorithms  []string    `json:"algorithms"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	*p = Problem{
		Type:        ErrorType(strings.TrimPrefix(in.Type, ProblemNamespace)),
		Detail:      in.Detail,
		Status:      in.Status,
		Identifier:  in.Identifier,
		Subproblems: in.Subproblems,
		Algorithms:  in.Algorithms,
	}
	return nil
}

// Returns the Problem in the error chain of err, if there is one.
func AsProblem(err error) (*Problem, bool) {
	var p *Problem
	if errors.As(err, &p) {
		return p, true
	}
	return nil, false
}
