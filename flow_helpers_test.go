package acmeserver_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/memstore"
	"github.com/misiektoja/go-acme-server/nonce"
)

// The base URL of every flow test server.
const baseURL = "https://acme.test/acme/"

// Wire values compared by the flow tests.
const (
	statusPending    = "pending"
	statusReady      = "ready"
	statusProcessing = "processing"
	statusValid      = "valid"
	statusInvalid    = "invalid"
	typeHTTP01       = "http-01"
	typeDNS01        = "dns-01"
)

// A test server with its collaborators.
type flow struct {
	t         *testing.T
	srv       *acmeserver.Server
	store     *memstore.Store
	ca        *testCA
	revoker   *recordingRevoker
	validator *fakeValidator
	logs      *bytes.Buffer
}

// Builds a server over memstore with a test CA, a recording revoker and a scriptable validator.
func newFlow(t *testing.T, mutate func(*acmeserver.Config)) *flow {
	t.Helper()
	f := &flow{
		t:         t,
		store:     memstore.New(),
		ca:        newTestCA(t),
		revoker:   &recordingRevoker{},
		validator: &fakeValidator{},
		logs:      &bytes.Buffer{},
	}
	cfg := acmeserver.Config{
		BaseURL: baseURL,
		Store:   f.store,
		Nonces:  nonce.New(nonce.Options{}),
		Logger:  slog.New(slog.NewTextHandler(f.logs, nil)),
		Issuer:  f.ca,
		Revoker: f.revoker,
		Validators: map[acmeserver.ChallengeType]acmeserver.Validator{
			acmeserver.ChallengeHTTP01: f.validator,
			acmeserver.ChallengeDNS01:  f.validator,
		},
		Workers: acmeserver.WorkerConfig{
			Concurrency:  2,
			PollInterval: 5 * time.Millisecond,
			Lease:        time.Second,
			TaskTimeout:  2 * time.Second,
			MaxAttempts:  3,
			RetryDelay:   time.Millisecond,
			StaleAfter:   50 * time.Millisecond,
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := acmeserver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.srv = srv
	return f
}

// Starts Run for the rest of the test.
func (f *flow) runWorker() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.srv.Run(ctx) }()
	f.t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			f.t.Errorf("Run: %v", err)
		}
	})
}

// Serves one request.
func (f *flow) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, r)
	return rec
}

// Polls until the condition holds or five seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// An ACME client bound to one account key.
type client struct {
	f   *flow
	key *ecdsa.PrivateKey
	kid string
}

// Returns a client with a fresh P-256 key and no account.
func (f *flow) newClient() *client {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	return &client{f: f, key: key}
}

// Fetches a nonce through HEAD new-nonce.
func (c *client) nonce() string {
	rec := c.f.do(httptest.NewRequest(http.MethodHead, baseURL+"new-nonce", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Replay-Nonce") == "" {
		c.f.t.Fatalf("new-nonce = %d", rec.Code)
	}
	return rec.Header().Get("Replay-Nonce")
}

// Signs and posts a payload. A nil payload sends POST-as-GET. The key is referenced by kid once
// the client has an account and embedded as jwk before that.
func (c *client) post(url string, payload any) *httptest.ResponseRecorder {
	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			c.f.t.Fatal(err)
		}
	}
	return c.postRaw(url, body, c.kid == "")
}

// Signs and posts raw payload bytes.
func (c *client) postRaw(url string, payload []byte, embedKey bool) *httptest.ResponseRecorder {
	header := map[string]any{"nonce": c.nonce(), "url": url}
	if embedKey {
		header["jwk"] = publicJWK(c.f.t, &c.key.PublicKey)
	} else {
		header["kid"] = c.kid
	}
	return c.send(url, signECDSA(c.f.t, c.key, header, payload))
}

// Signs a payload with the account kid and a fresh nonce without sending it.
func (c *client) signed(url string, payload any) []byte {
	body, err := json.Marshal(payload)
	if err != nil {
		c.f.t.Fatal(err)
	}
	return signECDSA(c.f.t, c.key, map[string]any{"nonce": c.nonce(), "url": url, "kid": c.kid}, body)
}

// Sends a prepared JWS body. It touches no test state, so goroutines may call it.
func (c *client) send(url string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/jose+json")
	return c.f.do(r)
}

// Creates an account and remembers its URL.
func (c *client) register() string {
	rec := c.post(baseURL+"new-account", map[string]any{"termsOfServiceAgreed": true,
		"contact": []string{"mailto:admin@example.test"}})
	if rec.Code != http.StatusCreated {
		c.f.t.Fatalf("new-account = %d %s", rec.Code, rec.Body.String())
	}
	c.kid = rec.Header().Get("Location")
	if !strings.HasPrefix(c.kid, baseURL+"acct/") {
		c.f.t.Fatalf("account Location = %q", c.kid)
	}
	return c.kid
}

// Creates an order for the names and returns its URL and body.
func (c *client) newOrder(names ...string) (string, orderBody) {
	identifiers := make([]map[string]string, 0, len(names))
	for _, name := range names {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": name})
	}
	rec := c.post(baseURL+"new-order", map[string]any{"identifiers": identifiers})
	if rec.Code != http.StatusCreated {
		c.f.t.Fatalf("new-order = %d %s", rec.Code, rec.Body.String())
	}
	var order orderBody
	decode(c.f.t, rec, &order)
	return rec.Header().Get("Location"), order
}

// Fetches a resource with POST-as-GET and decodes it.
func (c *client) get(url string, v any) *httptest.ResponseRecorder {
	rec := c.post(url, nil)
	if rec.Code != http.StatusOK {
		c.f.t.Fatalf("POST-as-GET %s = %d %s", url, rec.Code, rec.Body.String())
	}
	if v != nil {
		decode(c.f.t, rec, v)
	}
	return rec
}

// Responds to the http-01 challenge in every authorization of the order.
func (c *client) respondHTTP01(order orderBody) {
	for _, authzURL := range order.Authorizations {
		var authz authzBody
		c.get(authzURL, &authz)
		for _, ch := range authz.Challenges {
			if ch.Type == typeHTTP01 {
				rec := c.post(ch.URL, map[string]any{})
				if rec.Code != http.StatusOK {
					c.f.t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
				}
			}
		}
	}
}

// Waits until the order reaches the status.
func (c *client) waitOrder(url, status string) orderBody {
	var order orderBody
	waitFor(c.f.t, "order "+status, func() bool {
		c.get(url, &order)
		return order.Status == status
	})
	return order
}

// Finalizes the order with a fresh CSR for its identifiers signed by key.
func (c *client) finalize(order orderBody, key crypto.Signer) *httptest.ResponseRecorder {
	names := make([]string, 0, len(order.Identifiers))
	for _, id := range order.Identifiers {
		names = append(names, id.Value)
	}
	return c.finalizeCSR(order, makeCSR(c.f.t, key, names, nil))
}

// Finalizes the order with the given DER CSR.
func (c *client) finalizeCSR(order orderBody, der []byte) *httptest.ResponseRecorder {
	return c.post(order.Finalize, map[string]string{"csr": base64.RawURLEncoding.EncodeToString(der)})
}

// Wire shapes the tests decode.
type orderBody struct {
	Status         string                  `json:"status"`
	Expires        string                  `json:"expires"`
	Identifiers    []acmeserver.Identifier `json:"identifiers"`
	NotBefore      string                  `json:"notBefore"`
	NotAfter       string                  `json:"notAfter"`
	Error          *acmeserver.Problem     `json:"error"`
	Authorizations []string                `json:"authorizations"`
	Finalize       string                  `json:"finalize"`
	Certificate    string                  `json:"certificate"`
}

type authzBody struct {
	Identifier acmeserver.Identifier `json:"identifier"`
	Status     string                `json:"status"`
	Expires    string                `json:"expires"`
	Challenges []challengeBody       `json:"challenges"`
	Wildcard   bool                  `json:"wildcard"`
}

type challengeBody struct {
	Type           string              `json:"type"`
	URL            string              `json:"url"`
	Status         string              `json:"status"`
	Token          string              `json:"token"`
	TKAuthType     string              `json:"tkauth-type"`
	TokenAuthority string              `json:"token-authority"`
	Validated      string              `json:"validated"`
	Error          *acmeserver.Problem `json:"error"`
}

type accountBody struct {
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Orders               string   `json:"orders"`
}

// Decodes a JSON response body.
func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

// Checks a problem response.
func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, typ acmeserver.ErrorType) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	var p acmeserver.Problem
	decode(t, rec, &p)
	if p.Type != typ {
		t.Fatalf("problem type = %s (%s), want %s", p.Type, p.Detail, typ)
	}
}

// Returns the canonical JWK of an EC public key as a raw JSON message.
func publicJWK(t *testing.T, key *ecdsa.PublicKey) json.RawMessage {
	t.Helper()
	point, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	jwk := map[string]string{
		"kty": "EC", "crv": key.Curve.Params().Name,
		"x": base64.RawURLEncoding.EncodeToString(point[1 : 1+size]),
		"y": base64.RawURLEncoding.EncodeToString(point[1+size:]),
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Returns the RFC 7638 thumbprint of an EC public key.
func thumbprint(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	var jwk map[string]string
	if err := json.Unmarshal(publicJWK(t, key), &jwk); err != nil {
		t.Fatal(err)
	}
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Signs a flattened JWS with the ECDSA algorithm of the key's curve.
func signECDSA(t *testing.T, key *ecdsa.PrivateKey, header map[string]any, payload []byte) []byte {
	t.Helper()
	alg := curveAlgorithm(t, key.Curve)
	header["alg"] = alg
	protected, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p := base64.RawURLEncoding.EncodeToString(protected)
	pl := base64.RawURLEncoding.EncodeToString(payload)
	der, err := ecdsa.SignASN1(rand.Reader, key, ecdsaDigest(alg, []byte(p+"."+pl)))
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		t.Fatal(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	rs.R.FillBytes(sig[:size])
	rs.S.FillBytes(sig[size:])
	body, err := json.Marshal(map[string]string{"protected": p, "payload": pl,
		"signature": base64.RawURLEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Returns the JWS algorithm an EC curve signs with.
func curveAlgorithm(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	switch curve {
	case elliptic.P256():
		return "ES256"
	case elliptic.P384():
		return "ES384"
	case elliptic.P521():
		return "ES512"
	}
	t.Fatalf("unsupported curve %s", curve.Params().Name)
	return ""
}

// Returns the digest an ECDSA JWS algorithm signs.
func ecdsaDigest(alg string, input []byte) []byte {
	switch alg {
	case "ES384":
		sum := sha512.Sum384(input)
		return sum[:]
	case "ES512":
		sum := sha512.Sum512(input)
		return sum[:]
	}
	sum := sha256.Sum256(input)
	return sum[:]
}

// Returns a DER CSR for the names signed by key.
func makeCSR(t *testing.T, key crypto.Signer, dnsNames []string, ips []net.IP) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: dnsNames, IPAddresses: ips}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Returns a fresh P-256 key.
func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A CA that issues from a self-signed root and can be scripted to stall, fail or reject.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	mu   sync.Mutex
	// Attempts that return an error before issuance succeeds.
	failures int
	// Attempts that report a pending result before issuance succeeds.
	pending int
	// A final refusal returned instead of a certificate.
	reject *acmeserver.Problem
	// Operation IDs seen and the chains issued per operation.
	calls  []acmeserver.IssueRequest
	issued map[string][][]byte
	// When set, every issuance returns this chain.
	fixedChain [][]byte
	// When set, the CA shortens every certificate to this lifetime.
	maxLifetime time.Duration
}

// Returns a CA with a fresh root.
func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-acme-server test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{key: key, cert: cert, issued: map[string][][]byte{}}
}

// Issues a leaf for the request or follows the scripted behavior.
func (ca *testCA) Issue(_ context.Context, req acmeserver.IssueRequest) (acmeserver.IssueResult, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.calls = append(ca.calls, req)
	if ca.failures > 0 {
		ca.failures--
		return acmeserver.IssueResult{}, errors.New("CA unavailable")
	}
	if ca.pending > 0 {
		ca.pending--
		return acmeserver.IssueResult{Pending: true, RetryAfter: time.Millisecond}, nil
	}
	if ca.reject != nil {
		return acmeserver.IssueResult{Rejected: ca.reject}, nil
	}
	if ca.fixedChain != nil {
		return acmeserver.IssueResult{Chain: ca.fixedChain}, nil
	}
	if chain, ok := ca.issued[req.OperationID]; ok {
		return acmeserver.IssueResult{Chain: chain}, nil
	}
	notAfter := req.NotAfter
	if capped := time.Now().Add(ca.maxLifetime); ca.maxLifetime > 0 && (notAfter.IsZero() || capped.Before(notAfter)) {
		notAfter = capped.Truncate(time.Second)
	}
	chain, err := ca.sign(req.CSR.PublicKey, req.Identifiers, notAfter, grantedCACertificate(req.Validations))
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	ca.issued[req.OperationID] = chain
	return acmeserver.IssueResult{Chain: chain}, nil
}

// Reports whether every validation of the request authorized a CA certificate.
func grantedCACertificate(validations []acmeserver.Validation) bool {
	for _, validation := range validations {
		if !validation.CACertificate {
			return false
		}
	}
	return len(validations) != 0
}

// Signs a leaf for the identifiers, as a CA certificate when the authorizations granted one.
func (ca *testCA) sign(pub any, identifiers []acmeserver.Identifier, notAfter time.Time,
	isCA bool) ([][]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return nil, err
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, id := range identifiers {
		switch id.Type {
		case acmeserver.IdentifierIP:
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(id.Value))
		case acmeserver.IdentifierTNAuthList:
			value, err := base64.RawURLEncoding.DecodeString(id.Value)
			if err != nil {
				return nil, err
			}
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: tnAuthListOID, Value: value})
		case acmeserver.IdentifierDNS:
			tmpl.DNSNames = append(tmpl.DNSNames, id.Value)
		default:
			return nil, fmt.Errorf("unsupported identifier type %q", id.Type)
		}
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		return nil, err
	}
	return [][]byte{der, ca.cert.Raw}, nil
}

// Returns the number of Issue calls so far.
func (ca *testCA) callCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return len(ca.calls)
}

// A Revoker that records requests and can be scripted to fail.
type recordingRevoker struct {
	mu       sync.Mutex
	requests []acmeserver.RevokeRequest
	err      error
}

// Records the request and returns the scripted error.
func (r *recordingRevoker) Revoke(_ context.Context, req acmeserver.RevokeRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	return r.err
}

// A Validator whose result is chosen per call.
type fakeValidator struct {
	mu    sync.Mutex
	calls []acmeserver.ValidationRequest
	// Decides the result. Nil accepts everything.
	fn func(req acmeserver.ValidationRequest, attempt int) error
}

// Records the request and applies fn.
func (v *fakeValidator) Validate(_ context.Context, req acmeserver.ValidationRequest) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls = append(v.calls, req)
	if v.fn == nil {
		return nil
	}
	return v.fn(req, len(v.calls))
}

// Returns the number of Validate calls so far.
func (v *fakeValidator) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.calls)
}

// Sets the validation script.
func (v *fakeValidator) script(fn func(req acmeserver.ValidationRequest, attempt int) error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fn = fn
}

// A key store for external account bindings.
type eabKeys map[string][]byte

// Returns the MAC key or ErrNotFound.
func (k eabKeys) MACKey(_ context.Context, id string) ([]byte, error) {
	key, ok := k[id]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return key, nil
}
