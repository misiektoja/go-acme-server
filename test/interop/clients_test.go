package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Obtains and retrieves a certificate through the independent acmez implementation.
func TestAcmezHTTP01(t *testing.T) {
	s, port := newSolver(t, false)
	h := newHarness(t, harnessOptions{httpPort: port})
	client, account := h.acmez(t, httpSolver(s))
	key := newKey(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	certs, err := client.ObtainCertificateForSANs(ctx, account, key, []string{testHost})
	if err != nil || len(certs) != 1 {
		t.Fatalf("issuance = %v, %v", len(certs), err)
	}
	h.verify(t, certs[0].ChainPEM, &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.hits < 1 || len(s.proofs) != 0 {
		t.Fatal("HTTP proof was not fetched and cleaned up")
	}
}

// Proves that a client cannot reach the CA with an incorrect HTTP response.
func TestAcmezRejectsWrongProof(t *testing.T) {
	s, port := newSolver(t, true)
	h := newHarness(t, harnessOptions{httpPort: port})
	client, account := h.acmez(t, httpSolver(s))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := client.ObtainCertificateForSANs(ctx, account, newKey(t), []string{testHost}); err == nil {
		t.Fatal("incorrect proof accepted")
	}
	h.verifyRejected(t, account, acmeserver.ChallengeHTTP01)
}

// Reserves an unprivileged port that Certbot will bind when its challenge starts.
func availablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// Requires the pinned Certbot CLI and verifies the certificate from its standalone HTTP solver.
func TestCertbotHTTP01(t *testing.T) {
	executable := os.Getenv("ACME_CERTBOT")
	if executable == "" {
		executable = "certbot"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, executable, "--version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(version)) != certbotVersion {
		t.Fatalf("required %s, got %q: %v", certbotVersion, version, err)
	}
	h := newHarness(t, harnessOptions{httpPort: availablePort(t)})
	key := newKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testHost}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(h.directory, "client.csr")
	writePrivate(t, csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	fullchain := filepath.Join(h.directory, "fullchain.pem")
	command := exec.CommandContext(ctx, executable, "certonly", "--standalone", "--preferred-challenges", "http",
		"--http-01-address", "127.0.0.1", "--http-01-port", strconv.Itoa(h.options.httpPort),
		"--server", h.https.URL+"/acme/directory", "--csr", csrPath,
		"--cert-path", filepath.Join(h.directory, "cert.pem"), "--chain-path", filepath.Join(h.directory, "chain.pem"),
		"--fullchain-path", fullchain, "--config-dir", filepath.Join(h.directory, "config"),
		"--work-dir", filepath.Join(h.directory, "work"), "--logs-dir", filepath.Join(h.directory, "logs"),
		"--non-interactive", "--agree-tos", "--register-unsafely-without-email", "--no-directory-hooks")
	command.Env = append(os.Environ(), "REQUESTS_CA_BUNDLE="+h.trustFile, "NO_PROXY=127.0.0.1,localhost", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=")
	output, err := command.CombinedOutput()
	writePrivate(t, filepath.Join(h.directory, "certbot-output.txt"), output)
	if err != nil {
		t.Fatalf("Certbot failed: %v\n%s", err, output)
	}
	order := h.verify(t, readFile(t, fullchain), &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	if !bytes.Equal(order.CSR, csr) {
		t.Fatal("Certbot changed the supplied CSR")
	}
	t.Log(certbotVersion + " standalone HTTP-01 passed with explicit HTTPS trust")
}

// Registers the HTTP-01 responder as the only acmez solver.
func httpSolver(s *solver) map[string]acmez.Solver {
	return map[string]acmez.Solver{acme.ChallengeTypeHTTP01: s}
}
