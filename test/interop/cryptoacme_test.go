package interop

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Returns a Go crypto/acme client bound to the harness directory with explicit HTTPS trust.
func (h *harness) cryptoACME(t *testing.T, key *ecdsa.PrivateKey) *acme.Client {
	t.Helper()
	return &acme.Client{Key: key, DirectoryURL: h.https.URL + "/acme/directory", HTTPClient: h.client, UserAgent: "go-acme-server-interop"}
}

// Requires an ACME problem of the given type from a crypto/acme call.
func requireACMEError(t *testing.T, err error, status int, typ acmeserver.ErrorType) {
	t.Helper()
	var problem *acme.Error
	if !errors.As(err, &problem) || problem.StatusCode != status || !strings.HasSuffix(problem.ProblemType, string(typ)) {
		t.Fatalf("error = %v, want %d %s", err, status, typ)
	}
}

// Registers, updates and rolls over an account through crypto/acme and returns the client on its
// new key with the account URL.
func (h *harness) cryptoAccount(ctx context.Context, t *testing.T) (*acme.Client, string) {
	t.Helper()
	accountKey := newKey(t)
	client := h.cryptoACME(t, accountKey)
	account, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:first@issuance.test"}}, acme.AcceptTOS)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); !errors.Is(err, acme.ErrAccountAlreadyExists) {
		t.Fatalf("second registration = %v, want ErrAccountAlreadyExists", err)
	}
	// crypto/acme fills URI from a Location header, which account updates do not carry, so the
	// registration URI is kept for later lookups.
	location := account.URI
	account.Contact = []string{"mailto:second@issuance.test"}
	if account, err = client.UpdateReg(ctx, account); err != nil || len(account.Contact) != 1 || account.Contact[0] != "mailto:second@issuance.test" {
		t.Fatalf("update = %+v, %v", account, err)
	}
	stored := h.requireAccountKey(t, location, &accountKey.PublicKey)
	if len(stored.Contact) != 1 || stored.Contact[0] != "mailto:second@issuance.test" {
		t.Fatalf("stored contact = %v", stored.Contact)
	}
	rolled := newKey(t)
	if err := client.AccountKeyRollover(ctx, rolled); err != nil {
		t.Fatalf("rollover: %v", err)
	}
	client.Key = rolled
	if _, err := client.GetReg(ctx, ""); err != nil {
		t.Fatalf("account after rollover: %v", err)
	}
	h.requireAccountKey(t, location, &rolled.PublicKey)
	if _, err := h.cryptoACME(t, accountKey).GetReg(ctx, ""); err == nil {
		t.Fatal("the old key still reaches the account")
	}
	return client, location
}

// Issues one HTTP-01 certificate through crypto/acme and returns the chain, its key and the
// stored order.
func (h *harness) cryptoIssue(ctx context.Context, t *testing.T, client *acme.Client, s *solver) ([][]byte, *ecdsa.PrivateKey, *acmeserver.Order) {
	t.Helper()
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(testHost))
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	var http01 *acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			http01 = ch
		}
	}
	if http01 == nil {
		t.Fatalf("no http-01 challenge in %+v", authz.Challenges)
	}
	proof, err := client.HTTP01ChallengeResponse(http01.Token)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.proofs["/.well-known/acme-challenge/"+http01.Token] = proof
	s.mu.Unlock()
	accepted, err := client.Accept(ctx, http01)
	if err != nil || (accepted.Status != acme.StatusProcessing && accepted.Status != acme.StatusValid) {
		t.Fatalf("accept = %+v, %v", accepted, err)
	}
	if _, err := client.WaitAuthorization(ctx, order.AuthzURLs[0]); err != nil {
		t.Fatalf("authorization: %v", err)
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil || order.Status != acme.StatusReady {
		t.Fatalf("order = %+v, %v", order, err)
	}
	certKey := newKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testHost}}, certKey)
	if err != nil {
		t.Fatal(err)
	}
	chain, certURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	chainPEM := make([]byte, 0, 4096)
	for _, der := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	stored := h.verify(t, chainPEM, &certKey.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	if certURL != h.https.URL+"/acme/cert/"+stored.CertificateID {
		t.Fatalf("certificate URL %q does not name the stored certificate", certURL)
	}
	fetched, err := client.FetchCert(ctx, certURL, true)
	if err != nil || len(fetched) != 2 || string(fetched[0]) != string(chain[0]) {
		t.Fatalf("fetch = %d certificates, %v", len(fetched), err)
	}
	return chain, certKey, stored
}

// Drives account changes, HTTP-01 issuance, revocation by the certificate key and deactivation
// through the Go crypto/acme client.
func TestCryptoACMEAccountAndKeyRevocation(t *testing.T) {
	s, port := newSolver(t, false)
	h := newHarness(t, harnessOptions{httpPort: port})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	client, location := h.cryptoAccount(ctx, t)
	chain, certKey, order := h.cryptoIssue(ctx, t, client, s)

	// The certificate key signs the revocation, so no account is involved.
	if err := client.RevokeCert(ctx, certKey, chain[0], acme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("revocation by certificate key: %v", err)
	}
	if requester := h.verifyRevoked(t, order, int(acme.CRLReasonKeyCompromise)); requester != "" {
		t.Fatalf("CA saw requester %q for a key-signed revocation", requester)
	}
	// crypto/acme maps the server's alreadyRevoked problem to success, so the stored state is
	// checked instead of the error.
	if err := client.RevokeCert(ctx, nil, chain[0], acme.CRLReasonUnspecified); err != nil {
		t.Fatalf("repeated revocation = %v, want the client's alreadyRevoked success", err)
	}
	h.verifyRevoked(t, order, int(acme.CRLReasonKeyCompromise))
	requireACMEError(t, h.cryptoACME(t, newKey(t)).RevokeCert(ctx, nil, chain[0], acme.CRLReasonUnspecified), http.StatusForbidden, acmeserver.ErrorUnauthorized)

	if err := client.DeactivateReg(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	deactivated, err := h.store.Account(t.Context(), location[strings.LastIndex(location, "/")+1:])
	if err != nil || deactivated.Status != acmeserver.AccountDeactivated {
		t.Fatalf("stored account = %+v, %v", deactivated, err)
	}
	_, err = client.AuthorizeOrder(ctx, acme.DomainIDs(testHost))
	requireACMEError(t, err, http.StatusForbidden, acmeserver.ErrorUnauthorized)
	t.Log("crypto/acme v0.56.0 account update, key rollover, HTTP-01 issuance, key-signed revocation and deactivation passed")
}
