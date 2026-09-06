package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

// Returns the pinned Certbot executable after checking its version.
func certbotExecutable(ctx context.Context, t *testing.T) string {
	t.Helper()
	executable := os.Getenv("ACME_CERTBOT")
	if executable == "" {
		executable = "certbot"
	}
	version, err := exec.CommandContext(ctx, executable, "--version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(version)) != certbotVersion {
		t.Fatalf("required %s, got %q: %v", certbotVersion, version, err)
	}
	return executable
}

// Runs one Certbot command with explicit HTTPS trust and no proxy, keeping its output as evidence.
func (h *harness) certbot(ctx context.Context, t *testing.T, executable, evidence string, args ...string) []byte {
	t.Helper()
	common := []string{"--server", h.https.URL + "/acme/directory", "--config-dir", filepath.Join(h.directory, "config"),
		"--work-dir", filepath.Join(h.directory, "work"), "--logs-dir", filepath.Join(h.directory, "logs"), "--non-interactive"}
	command := exec.CommandContext(ctx, executable, append(args, common...)...)
	command.Env = append(os.Environ(), "REQUESTS_CA_BUNDLE="+h.trustFile, "NO_PROXY=127.0.0.1,localhost", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=")
	output, err := command.CombinedOutput()
	writePrivate(t, filepath.Join(h.directory, evidence), output)
	if err != nil {
		t.Fatalf("Certbot failed: %v\n%s", err, output)
	}
	return output
}

// Requires the pinned Certbot CLI and verifies the certificate from its standalone HTTP solver.
func TestCertbotHTTP01(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	executable := certbotExecutable(ctx, t)
	h := newHarness(t, harnessOptions{httpPort: availablePort(t)})
	key := newKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testHost}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(h.directory, "client.csr")
	writePrivate(t, csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	fullchain := filepath.Join(h.directory, "fullchain.pem")
	h.certbot(ctx, t, executable, "certbot-output.txt", "certonly", "--standalone", "--preferred-challenges", "http",
		"--http-01-address", "127.0.0.1", "--http-01-port", strconv.Itoa(h.options.httpPort), "--csr", csrPath,
		"--cert-path", filepath.Join(h.directory, "cert.pem"), "--chain-path", filepath.Join(h.directory, "chain.pem"),
		"--fullchain-path", fullchain, "--agree-tos", "--register-unsafely-without-email", "--no-directory-hooks")
	order := h.verify(t, readFile(t, fullchain), &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	if !bytes.Equal(order.CSR, csr) {
		t.Fatal("Certbot changed the supplied CSR")
	}
	t.Log(certbotVersion + " standalone HTTP-01 passed with explicit HTTPS trust")
}

// Certbot passes the wildcard identifier itself, so the hooks strip that label to reach the TXT
// owner shared with the base domain. Cleanup removes only its own value and keeps the file.
const (
	certbotAuthHook = `#!/bin/sh
set -eu
printf '%%s\n' "$CERTBOT_VALIDATION" >> "%s/_acme-challenge.${CERTBOT_DOMAIN#\*.}"
`
	certbotCleanupHook = `#!/bin/sh
set -eu
f="%s/_acme-challenge.${CERTBOT_DOMAIN#\*.}"
grep -v -x -F -e "$CERTBOT_VALIDATION" "$f" > "$f.next" || true
mv "$f.next" "$f"
`
)

// Issues through Certbot while the CA answers Pending for two seconds and checks that Certbot
// waits out the processing order instead of failing or ordering again.
func TestCertbotDelayedIssuance(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	executable := certbotExecutable(ctx, t)
	h := newHarness(t, harnessOptions{httpPort: availablePort(t), delay: 2 * time.Second})
	key := newKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testHost}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(h.directory, "client.csr")
	writePrivate(t, csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	fullchain := filepath.Join(h.directory, "fullchain.pem")
	h.certbot(ctx, t, executable, "certbot-delayed-output.txt", "certonly", "--standalone", "--preferred-challenges", "http",
		"--http-01-address", "127.0.0.1", "--http-01-port", strconv.Itoa(h.options.httpPort), "--csr", csrPath,
		"--cert-path", filepath.Join(h.directory, "cert.pem"), "--chain-path", filepath.Join(h.directory, "chain.pem"),
		"--fullchain-path", fullchain, "--agree-tos", "--register-unsafely-without-email", "--no-directory-hooks")
	order := h.verify(t, readFile(t, fullchain), &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	h.verifyDelayed(t, order)
	t.Log(certbotVersion + " waited for a delayed issuance and received the certificate")
}

// Issues a wildcard through Certbot's manual DNS hooks, then revokes it through Certbot.
func TestCertbotDNS01Wildcard(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	executable := certbotExecutable(ctx, t)
	responder, endpoint := newDNSResponder(t)
	h := newHarness(t, harnessOptions{dns: endpoint})
	records := filepath.Join(h.directory, "records")
	if err := os.Mkdir(records, 0o700); err != nil {
		t.Fatal(err)
	}
	responder.dir = records
	auth := filepath.Join(h.directory, "auth-hook.sh")
	writePrivate(t, auth, fmt.Appendf(nil, certbotAuthHook, records))
	cleanup := filepath.Join(h.directory, "cleanup-hook.sh")
	writePrivate(t, cleanup, fmt.Appendf(nil, certbotCleanupHook, records))
	for _, hook := range []string{auth, cleanup} {
		if err := os.Chmod(hook, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"*." + testHost, testHost}
	key := newKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(h.directory, "client.csr")
	writePrivate(t, csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	certPath, fullchain := filepath.Join(h.directory, "cert.pem"), filepath.Join(h.directory, "fullchain.pem")
	h.certbot(ctx, t, executable, "certbot-dns-output.txt", "certonly", "--manual", "--preferred-challenges", "dns",
		"--manual-auth-hook", auth, "--manual-cleanup-hook", cleanup, "--csr", csrPath, "--cert-path", certPath,
		"--chain-path", filepath.Join(h.directory, "chain.pem"), "--fullchain-path", fullchain,
		"--agree-tos", "--register-unsafely-without-email", "--no-directory-hooks")
	order := h.verify(t, readFile(t, fullchain), &key.PublicKey, names, acmeserver.ChallengeDNS01)
	if !bytes.Equal(order.CSR, csr) {
		t.Fatal("Certbot changed the supplied CSR")
	}
	concurrent, remaining := responder.summary()
	if left := strings.TrimSpace(string(readFile(t, filepath.Join(records, "_acme-challenge."+testHost)))); concurrent != 2 || remaining != 0 || left != "" {
		t.Fatalf("most TXT values in one answer = %d, owners left = %d, values left after cleanup = %q", concurrent, remaining, left)
	}
	h.certbot(ctx, t, executable, "certbot-revoke-output.txt", "revoke", "--cert-path", certPath, "--no-delete-after-revoke")
	h.verifyRevoked(t, order, 0)
	t.Log(certbotVersion + " manual DNS-01 wildcard issuance and account revocation passed")
}

// Issues for an IP identifier next to a DNS name through acmez and confirms that the IP
// authorization offers HTTP-01 only, as RFC 8738 requires, while the name still gets DNS-01.
func TestAcmezIPIdentifier(t *testing.T) {
	s, port := newSolver(t, false)
	_, endpoint := newDNSResponder(t)
	h := newHarness(t, harnessOptions{httpPort: port, dns: endpoint, ipIdentifiers: true})
	client, account := h.acmez(t, httpSolver(s))
	key := newKey(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	names := []string{testIP, testHost}
	certs, err := client.ObtainCertificateForSANs(ctx, account, key, names)
	if err != nil || len(certs) != 1 {
		t.Fatalf("issuance = %d, %v", len(certs), err)
	}
	order := h.verify(t, certs[0].ChainPEM, &key.PublicKey, names, acmeserver.ChallengeHTTP01)
	for _, id := range order.AuthorizationIDs {
		a, err := h.store.Authorization(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		offered := len(a.ChallengeIDs)
		if (a.Identifier.Type == acmeserver.IdentifierIP && offered != 1) || (a.Identifier.Type == acmeserver.IdentifierDNS && offered != 2) {
			t.Fatalf("%s authorization offered %d challenges", a.Identifier.Type, offered)
		}
	}
	// Without Config.IPIdentifiers the same order is refused before any authorization exists.
	plain := newHarness(t, harnessOptions{httpPort: port})
	client, account = plain.acmez(t, httpSolver(s))
	_, err = client.ObtainCertificateForSANs(ctx, account, newKey(t), []string{testIP})
	if err == nil || !strings.Contains(err.Error(), string(acmeserver.ErrorUnsupportedIdentifier)) {
		t.Fatalf("IP order without the option = %v, want unsupportedIdentifier", err)
	}
	t.Log("acmez v3.1.6 issued for 127.0.0.1 with issuance.test through HTTP-01 and the IP authorization offered no dns-01")
}

// Registers the HTTP-01 responder as the only acmez solver.
func httpSolver(s *solver) map[string]acmez.Solver {
	return map[string]acmez.Solver{acme.ChallengeTypeHTTP01: s}
}
