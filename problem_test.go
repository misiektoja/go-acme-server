package acmeserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestErrorTypeURN(t *testing.T) {
	if got := ErrorBadNonce.URN(); got != "urn:ietf:params:acme:error:badNonce" {
		t.Fatalf("URN() = %q", got)
	}
}

func TestProblemDefaultStatus(t *testing.T) {
	cases := map[ErrorType]int{
		ErrorMalformed:           http.StatusBadRequest,
		ErrorBadNonce:            http.StatusBadRequest,
		ErrorUnauthorized:        http.StatusForbidden,
		ErrorOrderNotReady:       http.StatusForbidden,
		ErrorRateLimited:         http.StatusTooManyRequests,
		ErrorAlreadyReplaced:     http.StatusConflict,
		ErrorServerInternal:      http.StatusInternalServerError,
		ErrorAccountDoesNotExist: http.StatusBadRequest,
		ErrorType("unknown"):     http.StatusInternalServerError,
	}
	for typ, want := range cases {
		if got := NewProblem(typ, "").HTTPStatus(); got != want {
			t.Errorf("%s: HTTPStatus() = %d, want %d", typ, got, want)
		}
	}
	if got := NewProblem(ErrorMalformed, "").WithStatus(http.StatusNotFound).HTTPStatus(); got != http.StatusNotFound {
		t.Fatalf("WithStatus: HTTPStatus() = %d", got)
	}
}

func TestProblemError(t *testing.T) {
	if got := NewProblem(ErrorMalformed, "bad").Error(); got != "urn:ietf:params:acme:error:malformed: bad" {
		t.Fatalf("Error() = %q", got)
	}
	if got := NewProblem(ErrorMalformed, "").Error(); got != "urn:ietf:params:acme:error:malformed" {
		t.Fatalf("Error() without detail = %q", got)
	}
	if got := Problemf(ErrorRateLimited, "retry in %d s", 5).Detail; got != "retry in 5 s" {
		t.Fatalf("Problemf detail = %q", got)
	}
}

func TestProblemMarshalJSON(t *testing.T) {
	id := Identifier{Type: IdentifierDNS, Value: "example.com"}
	p := Compound("two identifiers were rejected",
		NewProblem(ErrorRejectedIdentifier, "first").WithIdentifier(id),
		nil,
		NewProblem(ErrorCAA, "second"),
	)
	p.Algorithms = []string{"ES256"}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got["type"] != "urn:ietf:params:acme:error:compound" || got["status"] != float64(400) {
		t.Fatalf("top level = %v", got)
	}
	subs, ok := got["subproblems"].([]any)
	if !ok || len(subs) != 2 {
		t.Fatalf("subproblems = %v", got["subproblems"])
	}
	first, ok := subs[0].(map[string]any)
	if !ok {
		t.Fatalf("first subproblem = %v", subs[0])
	}
	if first["type"] != "urn:ietf:params:acme:error:rejectedIdentifier" || first["detail"] != "first" {
		t.Fatalf("first subproblem = %v", first)
	}
	if _, hasStatus := first["status"]; hasStatus {
		t.Fatalf("subproblem carries a status: %v", first)
	}
	ident, ok := first["identifier"].(map[string]any)
	if !ok || ident["type"] != "dns" || ident["value"] != "example.com" {
		t.Fatalf("subproblem identifier = %v", first["identifier"])
	}
	if algs, ok := got["algorithms"].([]any); !ok || len(algs) != 1 || algs[0] != "ES256" {
		t.Fatalf("algorithms = %v", got["algorithms"])
	}
}

func TestProblemMarshalOmitsEmptyMembers(t *testing.T) {
	raw, err := json.Marshal(NewProblem(ErrorBadNonce, "stale"))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale","status":400}`
	if string(raw) != want {
		t.Fatalf("Marshal = %s, want %s", raw, want)
	}
}

func TestProblemUnmarshalJSON(t *testing.T) {
	raw := `{"type":"urn:ietf:params:acme:error:compound","detail":"d","status":400,` +
		`"subproblems":[{"type":"urn:ietf:params:acme:error:dns","detail":"s","identifier":{"type":"dns","value":"a.test"}}]}`
	var p Problem
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if p.Type != ErrorCompound || p.Detail != "d" || p.Status != 400 || len(p.Subproblems) != 1 {
		t.Fatalf("Unmarshal = %+v", p)
	}
	sub := p.Subproblems[0]
	if sub.Type != ErrorDNS || sub.Identifier == nil || sub.Identifier.Value != "a.test" {
		t.Fatalf("subproblem = %+v", sub)
	}
}

func TestProblemCopies(t *testing.T) {
	base := NewProblem(ErrorMalformed, "base")
	withRetry := base.WithRetryAfter(3 * time.Second)
	withID := base.WithIdentifier(Identifier{Type: IdentifierIP, Value: "192.0.2.1"})
	if base.RetryAfter != 0 || base.Identifier != nil || base.Status != 0 {
		t.Fatalf("With* mutated the original: %+v", base)
	}
	if withRetry.RetryAfter != 3*time.Second || withID.Identifier.Value != "192.0.2.1" {
		t.Fatalf("copies missing changes: %+v %+v", withRetry, withID)
	}
}

func TestAsProblem(t *testing.T) {
	p := NewProblem(ErrorServerInternal, "boom")
	wrapped := fmt.Errorf("handler: %w", p)
	got, ok := AsProblem(wrapped)
	if !ok || got != p {
		t.Fatalf("AsProblem(wrapped) = %v, %v", got, ok)
	}
	if _, ok := AsProblem(errors.New("plain")); ok {
		t.Fatal("AsProblem(plain) reported a problem")
	}
}
