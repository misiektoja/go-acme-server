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
	"slices"
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
const (
	certbotVersion = "certbot 5.8.0"
	clientVersions = "acmez=v3.1.6 Certbot=5.8.0 crypto/acme=v0.56.0 go-jose=v4.1.5 lego=v4.35.2 SQLite=v1.58.0"
)

// The only host name the harness resolves and issues for, and the loopback IP identifier.
const (
	testHost = "issuance.test"
	testIP   = "127.0.0.1"
)

// Routes only the harness identifier to its isolated responder.
type localResolver struct{}

// Refuses unexpected names instead of consulting external DNS.
func (localResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host != testHost+"." {
		return nil, errors.New("unexpected test hostname")
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

// Selects the isolated responders and worker mode of one scenario. A zero port or endpoint
// leaves that challenge type unconfigured.
type harnessOptions struct {
	httpPort int
	tlsPort  int
	dns      netip.AddrPort
	external bool
	// External account MAC keys by key identifier.
	eab map[string][]byte
	// How long the test CA answers Pending before it signs.
	delay time.Duration
	// Offers tkauth-01 for TNAuthList identifiers with this Token Authority trusted.
	authority *tokenAuthority
	// Accepts RFC 8738 IP identifiers.
	ipIdentifiers bool
}

// Returns the MAC key for a configured external account identifier.
type eabKeys map[string][]byte

// Looks up a MAC key or reports ErrNotFound.
func (k eabKeys) MACKey(_ context.Context, id string) ([]byte, error) {
	key, ok := k[id]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return key, nil
}

// Holds the HTTPS endpoint, independent CA and durable ACME state of one scenario.
type harness struct {
	directory string
	store     *sqlitestore.Store
	ca        *durableCA
	server    *acmeserver.Server
	https     *httptest.Server
	options   harnessOptions
	trustFile string
	client    *http.Client
}

// Creates a real HTTPS endpoint whose certificate is trusted explicitly by every client.
func newHarness(t *testing.T, options harnessOptions) *harness {
	t.Helper()
	directory := testutil.Scratch(t)
	createCA(t, directory)
	ca := openCA(t, directory)
	ca.delay = options.delay
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
	server := configuredServer(t, baseURL, options, store, ca)
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
	h := &harness{directory: directory, store: store, ca: ca, server: server, https: https, options: options,
		trustFile: trustFile, client: &http.Client{Transport: transport, Timeout: 10 * time.Second}}
	t.Logf("Go=%s OS=%s arch=%s %s", runtime.Version(), runtime.GOOS, runtime.GOARCH, clientVersions)
	if !options.external {
		runWorker(t, server)
	}
	return h
}

// Applies the same worker and validator configuration in the HTTP and worker processes.
func configuredServer(t *testing.T, baseURL string, options harnessOptions, store acmeserver.Store, ca *durableCA) *acmeserver.Server {
	t.Helper()
	network := challenge.NetworkOptions{Resolver: localResolver{}, AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	validators := make(map[acmeserver.ChallengeType]acmeserver.Validator)
	if options.httpPort != 0 {
		validator, err := challenge.NewHTTP01(challenge.HTTPOptions{TestPort: options.httpPort, Network: network})
		if err != nil {
			t.Fatal(err)
		}
		validators[acmeserver.ChallengeHTTP01] = validator
	}
	if options.tlsPort != 0 {
		validator, err := challenge.NewTLSALPN01(challenge.TLSALPNOptions{TestPort: options.tlsPort, Network: network})
		if err != nil {
			t.Fatal(err)
		}
		validators[acmeserver.ChallengeTLSALPN01] = validator
	}
	if options.dns.IsValid() {
		resolver, err := challenge.NewResolver(challenge.ResolverOptions{Servers: []netip.AddrPort{options.dns}})
		if err != nil {
			t.Fatal(err)
		}
		validator, err := challenge.NewDNS01(challenge.DNSOptions{Resolver: resolver})
		if err != nil {
			t.Fatal(err)
		}
		validators[acmeserver.ChallengeDNS01] = validator
	}
	if options.authority != nil {
		validator, err := challenge.NewTKAuth01(challenge.TKAuthOptions{Authorities: challenge.StaticTokenAuthorities{
			ByURL: map[string]*x509.Certificate{authorityCertURL: options.authority.certificate}}})
		if err != nil {
			t.Fatal(err)
		}
		validators[acmeserver.ChallengeTKAuth01] = validator
	}
	config := acmeserver.Config{BaseURL: baseURL, Store: store, Nonces: nonce.New(nonce.Options{}),
		Issuer: ca, Revoker: ca, Validators: validators, RenewalInfo: acmeserver.LifetimeRenewal{RetryAfter: time.Hour},
		Workers: acmeserver.WorkerConfig{External: options.external, PollInterval: 10 * time.Millisecond, RetryDelay: 10 * time.Millisecond,
			TaskTimeout: time.Second, Lease: 2 * time.Second}}
	if options.eab != nil {
		config.ExternalAccounts = eabKeys(options.eab)
		config.SingleUseExternalAccounts = true
	}
	if options.authority != nil {
		config.TNAuthListIdentifiers = true
		config.TokenAuthority = tokenAuthorityURL
	}
	config.IPIdentifiers = options.ipIdentifiers
	server, err := acmeserver.New(config)
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
	if !ok || (r.Host != testHost && r.Host != testIP) {
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
func (h *harness) acmez(t *testing.T, solvers map[string]acmez.Solver) (*acmez.Client, acme.Account) {
	t.Helper()
	client := &acmez.Client{Client: &acme.Client{Directory: h.https.URL + "/acme/directory", HTTPClient: h.client},
		ChallengeSolvers: solvers}
	account, err := client.NewAccount(t.Context(), acme.Account{PrivateKey: newKey(t), TermsOfServiceAgreed: true})
	if err != nil {
		t.Fatal(err)
	}
	return client, account
}

// Checks the returned chain against the client key, the requested names and the trusted root.
func (h *harness) verifyLeaf(t *testing.T, chainPEM []byte, key crypto.PublicKey, names []string) (*x509.Certificate, []byte) {
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
	// Names may be DNS names or IP addresses, and the leaf must carry exactly those.
	var dnsNames, ipNames []string
	for _, name := range names {
		if net.ParseIP(name) != nil {
			ipNames = append(ipNames, name)
		} else {
			dnsNames = append(dnsNames, name)
		}
	}
	leafIPs := make([]string, 0, len(leaf.IPAddresses))
	for _, ip := range leaf.IPAddresses {
		leafIPs = append(leafIPs, ip.String())
	}
	if !bytes.Equal(publicKey, leaf.RawSubjectPublicKeyInfo) ||
		!slices.Equal(slices.Sorted(slices.Values(leaf.DNSNames)), slices.Sorted(slices.Values(dnsNames))) ||
		!slices.Equal(slices.Sorted(slices.Values(leafIPs)), slices.Sorted(slices.Values(ipNames))) {
		t.Fatal("certificate key or identifiers differ from the client request")
	}
	roots := x509.NewCertPool()
	roots.AddCert(h.ca.root)
	for _, name := range names {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: strings.Replace(name, "*.", "host.", 1)}); err != nil {
			t.Fatal(err)
		}
	}
	return leaf, publicKey
}

// Checks the certificate, key binding and persisted resource outcomes after a real client succeeds.
// Every name must have been authorized through the named challenge type.
func (h *harness) verify(t *testing.T, chainPEM []byte, key crypto.PublicKey, names []string, typ acmeserver.ChallengeType) *acmeserver.Order {
	t.Helper()
	leaf, publicKey := h.verifyLeaf(t, chainPEM, key, names)
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
	if len(order.AuthorizationIDs) != len(names) {
		t.Fatalf("authorizations = %d for %d names", len(order.AuthorizationIDs), len(names))
	}
	for _, id := range order.AuthorizationIDs {
		a, err := h.store.Authorization(t.Context(), id)
		if err != nil || a.Status != acmeserver.AuthorizationValid || !a.Expires.After(time.Now()) {
			t.Fatalf("authorization = %+v, %v", a, err)
		}
		name := a.Identifier.Value
		if a.Wildcard {
			name = "*." + name
		}
		wantType := acmeserver.IdentifierDNS
		if net.ParseIP(name) != nil {
			wantType = acmeserver.IdentifierIP
		}
		if !slices.Contains(names, name) || a.Identifier.Type != wantType {
			t.Fatalf("authorization identifier %s wildcard=%v is not a requested name", a.Identifier, a.Wildcard)
		}
		h.verifyChallenges(t, a, typ)
	}
	if len(cert.Validations) != len(names) {
		t.Fatal("missing validation evidence")
	}
	for _, validation := range cert.Validations {
		if validation.Type != typ {
			t.Fatalf("validation type = %s", validation.Type)
		}
	}
	if _, err := h.store.ClaimTask(t.Context(), time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("unfinished work: %v", err)
	}
	t.Logf("verified HTTPS trust, %s proof, leaf key, exact SANs %v, validity, chain, certificate retrieval and valid resources", typ, names)
	return order
}

// Requires exactly one valid challenge of the expected type and untouched siblings.
func (h *harness) verifyChallenges(t *testing.T, a *acmeserver.Authorization, typ acmeserver.ChallengeType) {
	t.Helper()
	valid := 0
	for _, id := range a.ChallengeIDs {
		ch, err := h.store.Challenge(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case ch.Type == typ && ch.Status == acmeserver.ChallengeValid && !ch.Validated.IsZero():
			valid++
		case ch.Status == acmeserver.ChallengePending:
		default:
			t.Fatalf("challenge = %+v", ch)
		}
	}
	if valid != 1 {
		t.Fatalf("valid %s challenges = %d", typ, valid)
	}
}

// Requires that a failed client run left every order invalid without any CA issuance.
func (h *harness) verifyRejected(t *testing.T, account acme.Account, typ acmeserver.ChallengeType) {
	t.Helper()
	ids, err := h.store.OrderIDs(t.Context(), accountID(account), "", 10)
	if err != nil || len(ids) == 0 {
		t.Fatalf("orders = %v, %v", ids, err)
	}
	failed := 0
	for _, id := range ids {
		order, err := h.store.Order(t.Context(), id)
		if err != nil || order.Status != acmeserver.OrderInvalid || order.CertificateID != "" || order.Issuance != nil {
			t.Fatalf("order = %+v, %v", order, err)
		}
		for _, authzID := range order.AuthorizationIDs {
			a, err := h.store.Authorization(t.Context(), authzID)
			if err != nil {
				t.Fatal(err)
			}
			for _, challengeID := range a.ChallengeIDs {
				ch, err := h.store.Challenge(t.Context(), challengeID)
				if err != nil {
					t.Fatal(err)
				}
				if ch.Status == acmeserver.ChallengeInvalid {
					if ch.Type != typ || ch.Error == nil || a.Status != acmeserver.AuthorizationInvalid {
						t.Fatalf("challenge = %+v authorization = %+v", ch, a)
					}
					failed++
				}
			}
		}
	}
	if failed == 0 {
		t.Fatal("no challenge recorded the rejected proof")
	}
	var count int
	if err := h.ca.db.QueryRowContext(t.Context(), "SELECT count(*) FROM issuance").Scan(&count); err != nil || count != 0 {
		t.Fatalf("CA calls = %d, %v", count, err)
	}
	t.Logf("incorrect %s proof rejected, orders invalid, no CA issuance", typ)
}

// Checks that a delayed issuance went through Pending answers, one signing and one order.
func (h *harness) verifyDelayed(t *testing.T, order *acmeserver.Order) {
	t.Helper()
	rows, calls := h.issuances(t)
	if pending := h.ca.pendingAnswers(); pending < 1 || rows != 1 || calls != 1 {
		t.Fatalf("pending answers=%d issuance rows=%d calls=%d", pending, rows, calls)
	}
	ids, err := h.store.OrderIDs(t.Context(), order.AccountID, "", 10)
	if err != nil || len(ids) != 1 {
		t.Fatalf("orders of the account = %v, %v", ids, err)
	}
}

// Checks that the order's certificate is stored as revoked with the reason and no CA re-issuance.
// It returns the account the CA saw as requester, empty for a certificate-key revocation.
func (h *harness) verifyRevoked(t *testing.T, order *acmeserver.Order, reason int) string {
	t.Helper()
	cert, err := h.store.Certificate(t.Context(), order.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Revoked || cert.RevokedAt.IsZero() || cert.RevocationReason != reason {
		t.Fatalf("certificate revoked=%v at=%v reason=%d", cert.Revoked, cert.RevokedAt, cert.RevocationReason)
	}
	leaf, err := x509.ParseCertificate(cert.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	var issued, caReason, calls int
	var requester string
	err = h.ca.db.QueryRowContext(t.Context(), "SELECT (SELECT count(*) FROM issuance), reason, account, calls FROM revocation WHERE serial = ?",
		leaf.SerialNumber.String()).Scan(&issued, &caReason, &requester, &calls)
	if err != nil || issued != 1 || caReason != reason || calls != 1 {
		t.Fatalf("issuance rows=%d CA revocation reason=%d calls=%d, %v", issued, caReason, calls, err)
	}
	return requester
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
