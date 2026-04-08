package interop

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Serves the RFC 8737 certificates that acmez generates, selected by the validator's SNI.
type alpnSolver struct {
	mu         sync.Mutex
	certs      map[string]*tls.Certificate
	handshakes int
	wrong      bool
}

// Starts a TLS listener that offers only the ACME protocol on an ephemeral loopback port.
func newALPNSolver(t *testing.T, wrong bool) (*alpnSolver, int) {
	t.Helper()
	s := &alpnSolver{certs: make(map[string]*tls.Certificate), wrong: wrong}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		NextProtos: []string{acmez.ACMETLS1Protocol}, GetCertificate: s.certificate})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go s.handshake(connection)
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return s, listener.Addr().(*net.TCPAddr).Port
}

// Completes one validation handshake without exchanging application data.
func (s *alpnSolver) handshake(connection net.Conn) {
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	if connection.(*tls.Conn).Handshake() == nil {
		s.mu.Lock()
		s.handshakes++
		s.mu.Unlock()
	}
}

// Returns the challenge certificate presented for the requested server name.
func (s *alpnSolver) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cert, ok := s.certs[hello.ServerName]
	if !ok {
		return nil, errors.New("no challenge certificate for " + hello.ServerName)
	}
	return cert, nil
}

// Builds the client's challenge certificate, optionally over a wrong key authorization.
func (s *alpnSolver) Present(_ context.Context, ch acme.Challenge) error {
	if s.wrong {
		ch.KeyAuthorization = ch.Token + ".wrong"
	}
	cert, err := acmez.TLSALPN01ChallengeCert(ch)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs[ch.Identifier.Value] = cert
	return nil
}

// Removes the challenge certificate for the identifier.
func (s *alpnSolver) CleanUp(_ context.Context, ch acme.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.certs, ch.Identifier.Value)
	return nil
}

// Registers the TLS listener as the only acmez solver.
func alpnSolvers(s *alpnSolver) map[string]acmez.Solver {
	return map[string]acmez.Solver{acme.ChallengeTypeTLSALPN01: s}
}

// Issues a certificate after the validator negotiates acme-tls/1 with the client's proof certificate.
func TestAcmezTLSALPN01(t *testing.T) {
	s, port := newALPNSolver(t, false)
	h := newHarness(t, harnessOptions{tlsPort: port})
	client, account := h.acmez(t, alpnSolvers(s))
	key := newKey(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	certs, err := client.ObtainCertificateForSANs(ctx, account, key, []string{testHost})
	if err != nil || len(certs) != 1 {
		t.Fatalf("issuance = %v, %v", len(certs), err)
	}
	h.verify(t, certs[0].ChainPEM, &key.PublicKey, []string{testHost}, acmeserver.ChallengeTLSALPN01)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handshakes < 1 || len(s.certs) != 0 {
		t.Fatalf("handshakes = %d, certificates left = %d", s.handshakes, len(s.certs))
	}
	t.Log("TLS-ALPN-01 proof negotiated with the client's certificate and cleaned up")
}

// Proves that a certificate carrying a wrong proof digest fails without CA issuance.
func TestAcmezRejectsWrongALPNProof(t *testing.T) {
	s, port := newALPNSolver(t, true)
	h := newHarness(t, harnessOptions{tlsPort: port})
	client, account := h.acmez(t, alpnSolvers(s))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := client.ObtainCertificateForSANs(ctx, account, newKey(t), []string{testHost}); err == nil {
		t.Fatal("incorrect TLS proof accepted")
	}
	h.verifyRejected(t, account, acmeserver.ChallengeTLSALPN01)
}
