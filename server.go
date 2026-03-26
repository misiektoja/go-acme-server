package acmeserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// Resource path segments below the base URL.
const (
	resourceDirectory = "directory"
	resourceNewNonce  = "new-nonce"
	accountPathPrefix = "acct/"
)

// Media types the protocol uses.
const (
	contentTypeJSON    = "application/json"
	contentTypeJOSE    = "application/jose+json"
	contentTypeProblem = "application/problem+json"
)

// Serves the ACME resources below Config.BaseURL. Mount it at the base path, for example
// http.Handle("/acme/", srv).
type Server struct {
	baseURL  string
	basePath string
	store    Store
	nonces   NonceManager
	clock    Clock
	log      *slog.Logger
	meta     DirectoryMeta
	maxBody  int64
	hasMeta  bool
}

// Validates the configuration and returns a Server. It starts no background work.
func New(cfg Config) (*Server, error) {
	base, err := normalizeBaseURL(cfg.BaseURL, cfg.AllowInsecureBaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		return nil, errorf("Config.Store is required")
	}
	if cfg.Nonces == nil {
		return nil, errorf("Config.Nonces is required")
	}
	if cfg.MaxRequestBody < 0 {
		return nil, errorf("Config.MaxRequestBody must not be negative")
	}
	s := &Server{
		baseURL:  base.String(),
		basePath: base.Path,
		store:    cfg.Store,
		nonces:   cfg.Nonces,
		clock:    cfg.Clock,
		log:      cfg.Logger,
		meta:     cfg.Meta,
		maxBody:  cfg.MaxRequestBody,
	}
	s.meta.CAAIdentities = append([]string(nil), cfg.Meta.CAAIdentities...)
	s.hasMeta = s.meta.TermsOfService != "" || s.meta.Website != "" || len(s.meta.CAAIdentities) > 0 ||
		s.meta.ExternalAccountRequired
	if s.clock == nil {
		s.clock = SystemClock()
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.maxBody == 0 {
		s.maxBody = DefaultMaxRequestBody
	}
	return s, nil
}

// Routes a request to the resource named by its path.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rel, ok := strings.CutPrefix(r.URL.Path, s.basePath)
	if !ok {
		s.writeProblem(r.Context(), w, notFound())
		return
	}
	switch rel {
	case resourceDirectory:
		s.serveDirectory(w, r)
	case resourceNewNonce:
		s.serveNewNonce(w, r)
	default:
		s.writeProblem(r.Context(), w, notFound())
	}
}

// Returns the absolute URL of a resource below the base URL.
func (s *Server) resourceURL(resource string) string { return s.baseURL + resource }

// Writes the directory object, see RFC 8555 section 7.1.1.
func (s *Server) serveDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeMethodNotAllowed(r.Context(), w, http.MethodGet, http.MethodHead)
		return
	}
	directory := map[string]any{
		"newNonce": s.resourceURL(resourceNewNonce),
	}
	if s.hasMeta {
		directory["meta"] = s.metaObject()
	}
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	s.writeBody(w, directory)
}

// Returns the directory meta member.
func (s *Server) metaObject() map[string]any {
	meta := map[string]any{}
	if s.meta.TermsOfService != "" {
		meta["termsOfService"] = s.meta.TermsOfService
	}
	if s.meta.Website != "" {
		meta["website"] = s.meta.Website
	}
	if len(s.meta.CAAIdentities) > 0 {
		meta["caaIdentities"] = s.meta.CAAIdentities
	}
	if s.meta.ExternalAccountRequired {
		meta["externalAccountRequired"] = true
	}
	return meta
}

// Answers HEAD with 200 and GET with 204, both with a fresh nonce.
func (s *Server) serveNewNonce(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead, http.MethodGet:
	default:
		s.writeMethodNotAllowed(r.Context(), w, http.MethodGet, http.MethodHead)
		return
	}
	nonce, err := s.nonces.Issue(r.Context())
	if err != nil {
		s.log.LogAttrs(r.Context(), slog.LevelError, "nonce issuance failed", slog.Any("error", err))
		s.writeProblem(r.Context(), w, NewProblem(ErrorServerInternal, "nonce issuance failed"))
		return
	}
	s.setCommonHeaders(w)
	w.Header().Set("Replay-Nonce", nonce)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Rejects a request whose method the resource does not support.
func (s *Server) writeMethodNotAllowed(ctx context.Context, w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "method not allowed").WithStatus(http.StatusMethodNotAllowed))
}

// Writes a problem document with a fresh nonce and the index link.
func (s *Server) writeProblem(ctx context.Context, w http.ResponseWriter, p *Problem) {
	s.setCommonHeaders(w)
	s.addNonce(ctx, w)
	if p.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(p.RetryAfter.Seconds())), 10))
	}
	w.Header().Set("Content-Type", contentTypeProblem)
	w.WriteHeader(p.HTTPStatus())
	s.writeBody(w, p)
}

// Adds the headers every non-directory response carries.
func (s *Server) setCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Link", `<`+s.resourceURL(resourceDirectory)+`>;rel="index"`)
}

// Attaches a fresh nonce. A failure is logged and the response is unchanged.
func (s *Server) addNonce(ctx context.Context, w http.ResponseWriter) {
	nonce, err := s.nonces.Issue(ctx)
	if err != nil {
		s.log.LogAttrs(ctx, slog.LevelWarn, "nonce issuance failed", slog.Any("error", err))
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
}

// Encodes v as JSON and logs failures, since the status is already written.
func (s *Server) writeBody(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.LogAttrs(context.Background(), slog.LevelWarn, "response encoding failed", slog.Any("error", err))
	}
}

// Returns the problem for an unknown resource path.
func notFound() *Problem {
	return NewProblem(ErrorMalformed, "unknown resource").WithStatus(http.StatusNotFound)
}

// Returns a configuration error with the package prefix.
func errorf(detail string) error { return &configError{detail: detail} }

// Reports an invalid Config.
type configError struct{ detail string }

// Returns the prefixed detail.
func (e *configError) Error() string { return "acmeserver: " + e.detail }
