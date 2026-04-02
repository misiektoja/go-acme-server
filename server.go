package acmeserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Resource path segments below the base URL.
const (
	resourceDirectory   = "directory"
	resourceNewNonce    = "new-nonce"
	resourceNewAccount  = "new-account"
	resourceNewOrder    = "new-order"
	resourceRevokeCert  = "revoke-cert"
	resourceKeyChange   = "key-change"
	accountPathPrefix   = "acct/"
	orderPathPrefix     = "order/"
	authzPathPrefix     = "authz/"
	challengePathPrefix = "chall/"
	certPathPrefix      = "cert/"
)

// Media types the protocol uses.
const (
	contentTypeJSON     = "application/json"
	contentTypeJOSE     = "application/jose+json"
	contentTypeProblem  = "application/problem+json"
	contentTypePEMChain = "application/pem-certificate-chain"
)

// Serves the ACME resources below Config.BaseURL. Mount it at the base path, for example
// http.Handle("/acme/", srv), and run Run in the same or another process. Without Run,
// challenges are never validated and orders are never issued.
type Server struct {
	baseURL        string
	basePath       string
	store          Store
	nonces         NonceManager
	clock          Clock
	log            *slog.Logger
	meta           DirectoryMeta
	maxBody        int64
	hasMeta        bool
	issuer         Issuer
	revoker        Revoker
	validators     map[ChallengeType]Validator
	eabKeys        ExternalAccountKeys
	policy         Policy
	issuancePolicy IssuancePolicy
	requireTOS     bool
	ipIdentifiers  bool
	orderLifetime  time.Duration
	authzLifetime  time.Duration
	maxIdentifiers int
	workers        WorkerConfig
	// Signals Run that new work was accepted in this process.
	wake    chan struct{}
	running atomic.Bool
}

// Validates the configuration and returns a Server. It starts no background work.
func New(cfg Config) (*Server, error) {
	base, err := normalizeBaseURL(cfg.BaseURL, cfg.AllowInsecureBaseURL)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	workers, err := cfg.Workers.withDefaults()
	if err != nil {
		return nil, err
	}
	s := &Server{
		baseURL:        base.String(),
		basePath:       base.Path,
		store:          cfg.Store,
		nonces:         cfg.Nonces,
		clock:          cfg.Clock,
		log:            cfg.Logger,
		meta:           cfg.Meta,
		maxBody:        cfg.MaxRequestBody,
		issuer:         cfg.Issuer,
		revoker:        cfg.Revoker,
		validators:     make(map[ChallengeType]Validator, len(cfg.Validators)),
		eabKeys:        cfg.ExternalAccounts,
		policy:         cfg.Policy,
		issuancePolicy: cfg.IssuancePolicy,
		requireTOS:     cfg.RequireTermsOfServiceAgreed,
		ipIdentifiers:  cfg.IPIdentifiers,
		orderLifetime:  cfg.OrderLifetime,
		authzLifetime:  cfg.AuthorizationLifetime,
		maxIdentifiers: cfg.MaxIdentifiers,
		workers:        workers,
		wake:           make(chan struct{}, 1),
	}
	maps.Copy(s.validators, cfg.Validators)
	s.meta.CAAIdentities = append([]string(nil), cfg.Meta.CAAIdentities...)
	s.hasMeta = s.meta.TermsOfService != "" || s.meta.Website != "" || len(s.meta.CAAIdentities) > 0 ||
		s.meta.ExternalAccountRequired
	if s.clock == nil {
		s.clock = SystemClock()
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.policy == nil {
		s.policy = AllowAll{}
	}
	if s.maxBody == 0 {
		s.maxBody = DefaultMaxRequestBody
	}
	if s.orderLifetime == 0 {
		s.orderLifetime = DefaultOrderLifetime
	}
	if s.authzLifetime == 0 {
		s.authzLifetime = DefaultAuthorizationLifetime
	}
	if s.maxIdentifiers == 0 {
		s.maxIdentifiers = DefaultMaxIdentifiers
	}
	return s, nil
}

// Checks the required dependencies and limits of a Config.
func (cfg Config) validate() error {
	switch {
	case cfg.Store == nil:
		return errorf("Config.Store is required")
	case cfg.Nonces == nil:
		return errorf("Config.Nonces is required")
	case cfg.Issuer == nil:
		return errorf("Config.Issuer is required")
	case cfg.Revoker == nil:
		return errorf("Config.Revoker is required")
	case len(cfg.Validators) == 0:
		return errorf("Config.Validators needs at least one validator")
	case cfg.Meta.ExternalAccountRequired && cfg.ExternalAccounts == nil:
		return errorf("Config.ExternalAccounts is required when Meta.ExternalAccountRequired is set")
	case cfg.RequireTermsOfServiceAgreed && cfg.Meta.TermsOfService == "":
		return errorf("Config.RequireTermsOfServiceAgreed needs Meta.TermsOfService")
	case cfg.MaxRequestBody < 0 || cfg.OrderLifetime < 0 || cfg.AuthorizationLifetime < 0 || cfg.MaxIdentifiers < 0:
		return errorf("Config limits must not be negative")
	}
	for typ, v := range cfg.Validators {
		if v == nil {
			return errorf("Config.Validators[" + string(typ) + "] is nil")
		}
		if typ != ChallengeHTTP01 && typ != ChallengeDNS01 && typ != ChallengeTLSALPN01 {
			return errorf("Config.Validators has the unknown challenge type " + string(typ))
		}
	}
	return nil
}

// Returns the worker configuration with defaults applied.
func (c WorkerConfig) withDefaults() (WorkerConfig, error) {
	if c.Concurrency < 0 || c.PollInterval < 0 || c.Lease < 0 || c.TaskTimeout < 0 || c.MaxAttempts < 0 ||
		c.RetryDelay < 0 || c.StaleAfter < 0 {
		return c, errorf("Config.Workers values must not be negative")
	}
	if c.Concurrency == 0 {
		c.Concurrency = 4
	}
	if c.PollInterval == 0 {
		c.PollInterval = time.Second
	}
	if c.Lease == 0 {
		c.Lease = 2 * time.Minute
	}
	if c.TaskTimeout == 0 {
		c.TaskTimeout = 30 * time.Second
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 5
	}
	if c.RetryDelay == 0 {
		c.RetryDelay = 5 * time.Second
	}
	if c.StaleAfter == 0 {
		c.StaleAfter = time.Minute
	}
	return c, nil
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
	case resourceNewAccount:
		s.servePOST(w, r, s.serveNewAccount)
	case resourceNewOrder:
		s.servePOST(w, r, s.serveNewOrder)
	case resourceRevokeCert:
		s.servePOST(w, r, s.serveRevokeCert)
	case resourceKeyChange:
		s.servePOST(w, r, s.serveKeyChange)
	default:
		s.serveResource(w, r, rel)
	}
}

// Routes a request to a resource that carries an ID in its path.
func (s *Server) serveResource(w http.ResponseWriter, r *http.Request, rel string) {
	kind, rest, ok := strings.Cut(rel, "/")
	if !ok {
		s.writeProblem(r.Context(), w, notFound())
		return
	}
	id, suffix, _ := strings.Cut(rest, "/")
	if !validID(id) {
		s.writeProblem(r.Context(), w, notFound())
		return
	}
	var handler func(http.ResponseWriter, *http.Request)
	switch {
	case kind+"/" == accountPathPrefix && suffix == "":
		handler = func(w http.ResponseWriter, r *http.Request) { s.serveAccount(w, r, id) }
	case kind+"/" == accountPathPrefix && suffix == "orders":
		handler = func(w http.ResponseWriter, r *http.Request) { s.serveAccountOrders(w, r, id) }
	case kind+"/" == orderPathPrefix && suffix == "":
		handler = func(w http.ResponseWriter, r *http.Request) { s.serveOrder(w, r, id) }
	case kind+"/" == orderPathPrefix && suffix == "finalize":
		handler = func(w http.ResponseWriter, r *http.Request) { s.serveFinalize(w, r, id) }
	case kind+"/" == authzPathPrefix && suffix == "":
		handler = func(w http.ResponseWriter, r *http.Request) { s.serveAuthorization(w, r, id) }
	case kind+"/" == challengePathPrefix && suffix == "":
		handler = func(w http.ResponseWriter, r *http.Request) { s.serveChallenge(w, r, id) }
	case kind+"/" == certPathPrefix && suffix == "":
		handler = func(w http.ResponseWriter, r *http.Request) { s.serveCertificate(w, r, id) }
	default:
		s.writeProblem(r.Context(), w, notFound())
		return
	}
	s.servePOST(w, r, handler)
}

// Runs the handler for POST requests and rejects every other method.
func (s *Server) servePOST(w http.ResponseWriter, r *http.Request, handler func(http.ResponseWriter, *http.Request)) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(r.Context(), w, http.MethodPost)
		return
	}
	handler(w, r)
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
		"newNonce":   s.resourceURL(resourceNewNonce),
		"newAccount": s.resourceURL(resourceNewAccount),
		"newOrder":   s.resourceURL(resourceNewOrder),
		"revokeCert": s.resourceURL(resourceRevokeCert),
		"keyChange":  s.resourceURL(resourceKeyChange),
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
		s.logError(r.Context(), "nonce issuance failed", err)
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
	w.Header().Add("Link", `<`+s.resourceURL(resourceDirectory)+`>;rel="index"`)
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

// Logs an operational failure at error level.
func (s *Server) logError(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	attrs = append(attrs, slog.Any("error", err))
	s.log.LogAttrs(ctx, slog.LevelError, msg, attrs...)
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
