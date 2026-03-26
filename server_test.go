package acmeserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-acme-server/nonce"
)

// The base URL every test server uses.
const testBaseURL = "https://acme.example/acme/"

// Returns a server over a test store and a nonce manager.
func newTestServer(t *testing.T, meta DirectoryMeta) (*Server, *testStore, *nonce.Manager) {
	t.Helper()
	store := newTestStore()
	nonces := nonce.New(nonce.Options{})
	s, err := New(Config{BaseURL: testBaseURL, Store: store, Nonces: nonces, Meta: meta})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, store, nonces
}

func TestNewValidatesConfig(t *testing.T) {
	store, nonces := newTestStore(), nonce.New(nonce.Options{})
	cases := map[string]Config{
		"missing store":        {BaseURL: testBaseURL, Nonces: nonces},
		"missing nonces":       {BaseURL: testBaseURL, Store: store},
		"missing base url":     {Store: store, Nonces: nonces},
		"relative base url":    {BaseURL: "/acme/", Store: store, Nonces: nonces},
		"http base url":        {BaseURL: "http://acme.example/acme/", Store: store, Nonces: nonces},
		"ftp base url":         {BaseURL: "ftp://acme.example/acme/", Store: store, Nonces: nonces},
		"query in base url":    {BaseURL: "https://acme.example/acme/?x=1", Store: store, Nonces: nonces},
		"fragment in base url": {BaseURL: "https://acme.example/acme/#x", Store: store, Nonces: nonces},
		"user in base url":     {BaseURL: "https://user@acme.example/acme/", Store: store, Nonces: nonces},
		"escaped path":         {BaseURL: "https://acme.example/ac%2Fme/", Store: store, Nonces: nonces},
		"negative body limit":  {BaseURL: testBaseURL, Store: store, Nonces: nonces, MaxRequestBody: -1},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatal("New accepted an invalid config")
			}
		})
	}
	s, err := New(Config{BaseURL: "https://acme.example/acme", Store: store, Nonces: nonces})
	if err != nil || s.baseURL != testBaseURL || s.basePath != "/acme/" {
		t.Fatalf("New without trailing slash = %+v, %v", s, err)
	}
	if s.maxBody != DefaultMaxRequestBody || s.clock == nil || s.log == nil {
		t.Fatalf("defaults not applied: %+v", s)
	}
	if _, err := New(Config{BaseURL: "http://localhost:8080/", AllowInsecureBaseURL: true, Store: store, Nonces: nonces}); err != nil {
		t.Fatalf("New with AllowInsecureBaseURL: %v", err)
	}
}

func TestDirectory(t *testing.T) {
	s, _, _ := newTestServer(t, DirectoryMeta{})
	rec := do(s, httptest.NewRequest(http.MethodGet, testBaseURL+"directory", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != contentTypeJSON {
		t.Fatalf("GET directory = %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	var dir map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatalf("directory body: %v", err)
	}
	if dir["newNonce"] != testBaseURL+"new-nonce" {
		t.Fatalf("newNonce = %v", dir["newNonce"])
	}
	if _, ok := dir["meta"]; ok {
		t.Fatalf("meta present without configuration: %v", dir["meta"])
	}
	if rec := do(s, httptest.NewRequest(http.MethodHead, testBaseURL+"directory", nil)); rec.Code != http.StatusOK {
		t.Fatalf("HEAD directory = %d", rec.Code)
	}
	rec = do(s, httptest.NewRequest(http.MethodPost, testBaseURL+"directory", nil))
	assertProblem(t, rec, http.StatusMethodNotAllowed, ErrorMalformed)
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
}

func TestDirectoryMeta(t *testing.T) {
	meta := DirectoryMeta{
		TermsOfService:          "https://acme.example/terms",
		Website:                 "https://acme.example",
		CAAIdentities:           []string{"acme.example"},
		ExternalAccountRequired: true,
	}
	s, _, _ := newTestServer(t, meta)
	rec := do(s, httptest.NewRequest(http.MethodGet, testBaseURL+"directory", nil))
	var dir struct {
		Meta struct {
			TermsOfService          string   `json:"termsOfService"`
			Website                 string   `json:"website"`
			CAAIdentities           []string `json:"caaIdentities"`
			ExternalAccountRequired bool     `json:"externalAccountRequired"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatalf("directory body: %v", err)
	}
	if dir.Meta.TermsOfService != meta.TermsOfService || dir.Meta.Website != meta.Website ||
		len(dir.Meta.CAAIdentities) != 1 || dir.Meta.CAAIdentities[0] != "acme.example" || !dir.Meta.ExternalAccountRequired {
		t.Fatalf("meta = %+v", dir.Meta)
	}
	meta.CAAIdentities[0] = "changed"
	rec = do(s, httptest.NewRequest(http.MethodGet, testBaseURL+"directory", nil))
	if !strings.Contains(rec.Body.String(), `"acme.example"`) {
		t.Fatal("server shares the caller's CAAIdentities slice")
	}
}

func TestNewNonce(t *testing.T) {
	s, _, nonces := newTestServer(t, DirectoryMeta{})
	head := do(s, httptest.NewRequest(http.MethodHead, testBaseURL+"new-nonce", nil))
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD new-nonce = %d", head.Code)
	}
	get := do(s, httptest.NewRequest(http.MethodGet, testBaseURL+"new-nonce", nil))
	if get.Code != http.StatusNoContent || get.Body.Len() != 0 {
		t.Fatalf("GET new-nonce = %d with %d body bytes", get.Code, get.Body.Len())
	}
	for _, rec := range []*httptest.ResponseRecorder{head, get} {
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
		}
		assertIndexLink(t, rec)
		value := rec.Header().Get("Replay-Nonce")
		if ok, err := nonces.Consume(t.Context(), value); err != nil || !ok {
			t.Fatalf("Replay-Nonce %q not accepted by the manager: %v %v", value, ok, err)
		}
	}
	if head.Header().Get("Replay-Nonce") == get.Header().Get("Replay-Nonce") {
		t.Fatal("two responses carried the same nonce")
	}
	rec := do(s, httptest.NewRequest(http.MethodPost, testBaseURL+"new-nonce", nil))
	assertProblem(t, rec, http.StatusMethodNotAllowed, ErrorMalformed)
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
}

func TestUnknownResource(t *testing.T) {
	s, _, _ := newTestServer(t, DirectoryMeta{})
	for _, path := range []string{testBaseURL + "missing", testBaseURL + "acct/", "https://acme.example/other", "https://acme.example/acme"} {
		rec := do(s, httptest.NewRequest(http.MethodGet, path, nil))
		assertProblem(t, rec, http.StatusNotFound, ErrorMalformed)
		if rec.Header().Get("Replay-Nonce") == "" {
			t.Fatalf("%s: error response without Replay-Nonce", path)
		}
		assertIndexLink(t, rec)
	}
}

func TestProblemResponseCarriesRetryAfter(t *testing.T) {
	s, _, _ := newTestServer(t, DirectoryMeta{})
	rec := httptest.NewRecorder()
	s.writeProblem(t.Context(), rec, NewProblem(ErrorRateLimited, "slow down").WithRetryAfter(1500*time.Millisecond))
	assertProblem(t, rec, http.StatusTooManyRequests, ErrorRateLimited)
	if rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
}

// Serves one request and returns the recorder.
func do(s *Server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec
}

// Checks a problem response's status, media type and type.
func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, typ ErrorType) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != contentTypeProblem {
		t.Fatalf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("problem body %q: %v", rec.Body.String(), err)
	}
	if p.Type != typ || p.Status != status {
		t.Fatalf("problem = %+v, want %s %d", p, typ, status)
	}
}

// Checks the directory link relation.
func assertIndexLink(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if want := `<` + testBaseURL + `directory>;rel="index"`; rec.Header().Get("Link") != want {
		t.Fatalf("Link = %q, want %q", rec.Header().Get("Link"), want)
	}
}
