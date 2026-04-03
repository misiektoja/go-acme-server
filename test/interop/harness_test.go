package interop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/challenge"
	"github.com/misiektoja/go-acme-server/nonce"
	"github.com/misiektoja/go-acme-server/test/interop/sqlitestore"
	"github.com/misiektoja/go-acme-server/test/interop/testutil"
)

// Names the versions every required client run must use.
const certbotVersion = "certbot 5.4.0"

// Routes only the harness identifier to its isolated responder.
type localResolver struct{}

// Refuses unexpected names instead of consulting external DNS.
func (localResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host != "issuance.test." {
		return nil, errors.New("unexpected test hostname")
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

// Holds the HTTPS endpoint, independent CA and durable ACME state of one scenario.
type harness struct {
	directory string
	store     *sqlitestore.Store
	ca        *durableCA
	server    *acmeserver.Server
	https     *httptest.Server
	port      int
	trustFile string
	client    *http.Client
}

// Creates a real HTTPS endpoint whose certificate is trusted explicitly by both clients.
func newHarness(t *testing.T, port int, external bool) *harness {
	t.Helper()
	directory := testutil.Scratch(t)
	createCA(t, directory)
	ca := openCA(t, directory)
	store, err := sqlitestore.Open(t.Context(), filepath.Join(directory, "acme.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	https := httptest.NewUnstartedServer(nil)
	baseURL := "https://" + https.Listener.Addr().String() + "/acme/"
	server := configuredServer(t, baseURL, port, external, store, ca)
	https.Config.Handler = server
	key := newKey(t)
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	https.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der, ca.root.Raw}, PrivateKey: key}}}
	https.StartTLS()
	t.Cleanup(https.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca.root)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	trustFile := filepath.Join(directory, "trust.pem")
	writePrivate(t, trustFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw}))
	h := &harness{directory: directory, store: store, ca: ca, server: server, https: https, port: port,
		trustFile: trustFile, client: &http.Client{Transport: transport, Timeout: 10 * time.Second}}
	t.Logf("Go=%s OS=%s arch=%s acmez=v3.1.6 Certbot=5.4.0 SQLite=v1.48.1", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if !external {
		runWorker(t, server)
	}
	return h
}

// Applies the same worker and validator configuration in the HTTP and worker processes.
func configuredServer(t *testing.T, baseURL string, port int, external bool, store acmeserver.Store, ca *durableCA) *acmeserver.Server {
	t.Helper()
	validator, err := challenge.NewHTTP01(challenge.HTTPOptions{TestPort: port, Network: challenge.NetworkOptions{
		Resolver: localResolver{}, AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := acmeserver.New(acmeserver.Config{BaseURL: baseURL, Store: store, Nonces: nonce.New(nonce.Options{}),
		Issuer: ca, Revoker: ca, Validators: map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: validator},
		Workers: acmeserver.WorkerConfig{External: external, PollInterval: 10 * time.Millisecond, RetryDelay: 10 * time.Millisecond,
			TaskTimeout: time.Second, Lease: 2 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

// Runs and joins a worker before its test's database connections close.
func runWorker(t *testing.T, server *acmeserver.Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

// Serves proof values supplied by the independent acmez client.
type solver struct {
	mu     sync.RWMutex
	proofs map[string]string
	hits   int
	wrong  bool
}

// Stores the client-computed key authorization at its HTTP challenge path.
func (s *solver) Present(_ context.Context, ch acme.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proofs["/.well-known/acme-challenge/"+ch.Token] = ch.KeyAuthorization
	return nil
}

// Removes only the completed challenge response.
func (s *solver) CleanUp(_ context.Context, ch acme.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.proofs, "/.well-known/acme-challenge/"+ch.Token)
	return nil
}

// Returns a proof only for the expected host and an active challenge path.
func (s *solver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	proof, ok := s.proofs[r.URL.Path]
	if !ok || r.Host != "issuance.test" {
		http.NotFound(w, r)
		return
	}
	s.hits++
	if s.wrong {
		proof = "incorrect"
	}
	fmt.Fprint(w, proof)
}

// Opens the standalone proof responder without requiring privileged ports.
func newSolver(t *testing.T, wrong bool) (*solver, int) {
	t.Helper()
	s := &solver{proofs: make(map[string]string), wrong: wrong}
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)
	return s, server.Listener.Addr().(*net.TCPAddr).Port
}

// Registers an independent client account with the generated HTTPS trust root.
func (h *harness) acmez(t *testing.T, s *solver) (*acmez.Client, acme.Account) {
	t.Helper()
	client := &acmez.Client{Client: &acme.Client{Directory: h.https.URL + "/acme/directory", HTTPClient: h.client},
		ChallengeSolvers: map[string]acmez.Solver{acme.ChallengeTypeHTTP01: s}}
	account, err := client.NewAccount(t.Context(), acme.Account{PrivateKey: newKey(t), TermsOfServiceAgreed: true})
	if err != nil {
		t.Fatal(err)
	}
	return client, account
}

// Checks the certificate, key binding and persisted resource outcomes after a real client succeeds.
func (h *harness) verify(t *testing.T, chainPEM []byte, key crypto.PublicKey) *acmeserver.Order {
	t.Helper()
	block, rest := pem.Decode(chainPEM)
	if block == nil {
		t.Fatal("missing leaf certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuer, trailing := pem.Decode(rest)
	if issuer == nil || len(bytes.TrimSpace(trailing)) != 0 || !bytes.Equal(issuer.Bytes, h.ca.root.Raw) {
		t.Fatal("unexpected chain")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicKey, leaf.RawSubjectPublicKeyInfo) || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "issuance.test" || len(leaf.IPAddresses) != 0 {
		t.Fatal("certificate key or identifiers differ from the client request")
	}
	roots := x509.NewCertPool()
	roots.AddCert(h.ca.root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "issuance.test"}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leaf.Raw)
	cert, err := h.store.Certificate(t.Context(), base64.RawURLEncoding.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	order, err := h.store.Order(t.Context(), cert.OrderID)
	if err != nil || order.Status != acmeserver.OrderValid || order.Issuance == nil || order.UnpublishedResult != nil {
		t.Fatalf("order = %+v, %v", order, err)
	}
	if !bytes.Equal(publicKey, mustCSR(t, order.CSR).RawSubjectPublicKeyInfo) || order.CertificateID != cert.ID || !bytes.Equal(cert.Chain[0], leaf.Raw) {
		t.Fatal("publication differs from returned certificate")
	}
	for _, id := range order.AuthorizationIDs {
		a, err := h.store.Authorization(t.Context(), id)
		if err != nil || a.Status != acmeserver.AuthorizationValid || !a.Expires.After(time.Now()) {
			t.Fatalf("authorization = %+v, %v", a, err)
		}
		ch, err := h.store.Challenge(t.Context(), a.ChallengeIDs[0])
		if err != nil || ch.Status != acmeserver.ChallengeValid || ch.Validated.IsZero() {
			t.Fatalf("challenge = %+v, %v", ch, err)
		}
	}
	if len(cert.Validations) != 1 || cert.Validations[0].Type != acmeserver.ChallengeHTTP01 {
		t.Fatal("missing validation evidence")
	}
	if _, err := h.store.ClaimTask(t.Context(), time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("unfinished work: %v", err)
	}
	t.Log("verified HTTPS trust, HTTP-01 proof, leaf key, exact SAN, validity, chain, certificate retrieval and valid resources")
	return order
}

// Parses the accepted CSR for independent comparison with the issued key.
func mustCSR(t *testing.T, der []byte) *x509.CertificateRequest {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	return csr
}

// Extracts the opaque account ID from the client-facing URL.
func accountID(account acme.Account) string {
	return account.Location[strings.LastIndex(account.Location, "/")+1:]
}

// Returns a required file while preserving useful diagnostics on failure.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
