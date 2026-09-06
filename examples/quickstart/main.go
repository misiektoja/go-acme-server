// A local ACME server for trying go-acme-server: in-memory storage, a throwaway CA and HTTP-01.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/challenge"
	"github.com/misiektoja/go-acme-server/memstore"
	"github.com/misiektoja/go-acme-server/nonce"
)

// A throwaway CA. It remembers every result by operation ID, which is what a real CA must do too.
type devCA struct {
	key  *ecdsa.PrivateKey
	root *x509.Certificate

	mu      sync.Mutex
	issued  map[string][]byte
	revoked map[string]bool
}

// Generates a self-signed root that lives as long as the process.
func newDevCA() (*devCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-acme-server quickstart root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &devCA{key: key, root: root, issued: map[string][]byte{}, revoked: map[string]bool{}}, nil
}

// Signs one certificate per operation ID and returns the same chain on every retry.
func (ca *devCA) Issue(_ context.Context, req acmeserver.IssueRequest) (acmeserver.IssueResult, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if der, ok := ca.issued[req.OperationID]; ok {
		return acmeserver.IssueResult{Chain: [][]byte{der, ca.root.Raw}}, nil
	}
	// The server forbids new signing after the deadline or during recovery of an earlier attempt.
	if req.RecoveryOnly || !req.Deadline.After(time.Now()) {
		return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorUnauthorized,
			"the signing deadline has passed")}, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	now := time.Now().Truncate(time.Second)
	leaf := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// The issued leaf must stay inside the validity the order asked for.
	if !req.NotBefore.IsZero() {
		leaf.NotBefore = req.NotBefore
	}
	if !req.NotAfter.IsZero() && req.NotAfter.Before(leaf.NotAfter) {
		leaf.NotAfter = req.NotAfter
	}
	for _, id := range req.Identifiers {
		switch id.Type {
		case acmeserver.IdentifierDNS:
			leaf.DNSNames = append(leaf.DNSNames, id.Value)
		case acmeserver.IdentifierIP:
			leaf.IPAddresses = append(leaf.IPAddresses, net.ParseIP(id.Value))
		case acmeserver.IdentifierTNAuthList:
			// TNAuthList identifiers are off in this configuration, so the server never sends one.
			return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier,
				"unsupported identifier type")}, nil
		default:
			return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier,
				"unsupported identifier type")}, nil
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, req.CSR.PublicKey, ca.key)
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	ca.issued[req.OperationID] = der
	return acmeserver.IssueResult{Chain: [][]byte{der, ca.root.Raw}}, nil
}

// Signs a TLS server certificate for localhost so clients can reach the directory over HTTPS.
func (ca *devCA) serverCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.root, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.root.Raw}, PrivateKey: key}, nil
}

// Records the revocation. A real CA publishes it through its CRL or OCSP responder.
func (ca *devCA) Revoke(_ context.Context, req acmeserver.RevokeRequest) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.revoked[req.OperationID] = true
	return nil
}

// Answers the quickstart name with the loopback address instead of asking DNS.
type localResolver struct{}

// Resolves quickstart.example.test to 127.0.0.1 and refuses every other name.
func (localResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if strings.TrimSuffix(host, ".") != "quickstart.example.test" {
		return nil, errors.New("unknown host " + host)
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("quickstart failed", "error", err)
		os.Exit(1)
	}
}

// Builds the server and serves it until the process is interrupted.
func run(logger *slog.Logger) error {
	ca, err := newDevCA()
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	// Clients trust this file so they can talk to the server and verify the issued chain.
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})
	if err := os.WriteFile("quickstart-root.pem", rootPEM, 0o600); err != nil {
		return fmt.Errorf("write root: %w", err)
	}
	serverCert, err := ca.serverCertificate()
	if err != nil {
		return fmt.Errorf("create server certificate: %w", err)
	}
	// Loopback is denied by the default egress policy, so the quickstart allows it explicitly.
	// TestPort sends HTTP-01 requests to port 5002 instead of port 80.
	http01, err := challenge.NewHTTP01(challenge.HTTPOptions{
		Network: challenge.NetworkOptions{
			Resolver:        localResolver{},
			AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		},
		TestPort: 5002,
	})
	if err != nil {
		return fmt.Errorf("create validator: %w", err)
	}
	srv, err := acmeserver.New(acmeserver.Config{
		BaseURL: "https://localhost:4000/acme/",
		Store:   memstore.New(),
		Nonces:  nonce.New(nonce.Options{}),
		Issuer:  ca,
		Revoker: ca,
		Validators: map[acmeserver.ChallengeType]acmeserver.Validator{
			acmeserver.ChallengeHTTP01: http01,
		},
		RenewalInfo: acmeserver.LifetimeRenewal{},
		Logger:      logger,
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// The worker validates challenges and issues certificates. Without it nothing progresses.
	go func() {
		if err := srv.Run(ctx); err != nil {
			logger.Error("worker", "error", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/acme/", srv)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.Ready(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	httpServer := &http.Server{
		Addr:              "localhost:4000",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}},
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	logger.Info("serving", "directory", "https://localhost:4000/acme/directory", "root", "quickstart-root.pem")
	if err := httpServer.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
