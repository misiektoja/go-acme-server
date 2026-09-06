package interop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/mholt/acmez/v3"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Returns the SHA-256 digest the server uses as a certificate ID.
func digest(der []byte) []byte {
	sum := sha256.Sum256(der)
	return sum[:]
}

// Checks the stored predecessor claim and the window the server suggested for a leaf.
func (h *harness) verifyReplacement(t *testing.T, leaf *x509.Certificate, replacing *acmeserver.Order, start, end time.Time) {
	t.Helper()
	predecessor, err := h.store.CertificateByRenewalID(t.Context(), replacing.Replaces)
	if err != nil || predecessor.ReplacedByOrderID != replacing.ID {
		t.Fatalf("predecessor = %+v, %v, want replaced by %s", predecessor, err, replacing.ID)
	}
	if leafID := base64.RawURLEncoding.EncodeToString(digest(leaf.Raw)); predecessor.ID != leafID {
		t.Fatalf("replaces %q names %s, want the leaf %s", replacing.Replaces, predecessor.ID, leafID)
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	wantStart := leaf.NotBefore.Add(lifetime * 2 / 3).Truncate(time.Second)
	wantEnd := leaf.NotBefore.Add(lifetime * 5 / 6).Truncate(time.Second)
	if !start.Equal(wantStart) || !end.Equal(wantEnd) {
		t.Fatalf("window = %s to %s, want %s to %s", start, end, wantStart, wantEnd)
	}
}

// Fetches renewal information through acmez, orders a replacement naming the leaf and confirms
// that acmez drops the claim after alreadyReplaced.
func TestAcmezRenewalInfo(t *testing.T) {
	s, port := newSolver(t, false)
	h := newHarness(t, harnessOptions{httpPort: port})
	client, account := h.acmez(t, httpSolver(s))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	key := newKey(t)
	certs, err := client.ObtainCertificateForSANs(ctx, account, key, []string{testHost})
	if err != nil || len(certs) != 1 {
		t.Fatalf("issuance = %d, %v", len(certs), err)
	}
	leaf, _ := h.verifyLeaf(t, certs[0].ChainPEM, &key.PublicKey, []string{testHost})
	info, err := client.GetRenewalInfo(ctx, leaf)
	if err != nil || !info.HasWindow() || info.RetryAfter == nil {
		t.Fatalf("renewal info = %+v, %v", info, err)
	}
	if wait := time.Until(*info.RetryAfter); wait < 55*time.Minute || wait > time.Hour {
		t.Fatalf("Retry-After %s from now, want about one hour", wait)
	}
	csr, err := acmez.NewCSR(newKey(t), []string{testHost})
	if err != nil {
		t.Fatal(err)
	}
	params, err := acmez.OrderParametersFromCSR(account, csr)
	if err != nil {
		t.Fatal(err)
	}
	params.Replaces = leaf
	renewed, err := client.ObtainCertificate(ctx, params)
	if err != nil || len(renewed) != 1 {
		t.Fatalf("replacement = %d, %v", len(renewed), err)
	}
	replacing := h.verify(t, renewed[0].ChainPEM, csr.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	h.verifyReplacement(t, leaf, replacing, info.SuggestedWindow.Start, info.SuggestedWindow.End)
	// acmez retries without replaces on alreadyReplaced, so the third order carries no claim.
	again, err := client.ObtainCertificate(ctx, params)
	if err != nil || len(again) != 1 {
		t.Fatalf("order after alreadyReplaced = %d, %v", len(again), err)
	}
	third := h.verify(t, again[0].ChainPEM, csr.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	if third.Replaces != "" {
		t.Fatalf("third order replaces %q after the server answered alreadyReplaced", third.Replaces)
	}
	predecessor, _ := h.store.CertificateByRenewalID(t.Context(), replacing.Replaces)
	if predecessor.ReplacedByOrderID != replacing.ID {
		t.Fatalf("claim moved to %s", predecessor.ReplacedByOrderID)
	}
	t.Log("acmez v3.1.6 read renewal information, replaced the certificate once and retried without the claim")
}

// Fetches renewal information through lego and orders a replacement naming the leaf.
func TestLegoRenewalInfo(t *testing.T) {
	port := availablePort(t)
	h := newHarness(t, harnessOptions{httpPort: port})
	client := h.lego(t)
	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	}
	key, resource := legoObtain(t, client, testHost)
	h.verify(t, resource.Certificate, &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	leaf, _ := h.verifyLeaf(t, resource.Certificate, &key.PublicKey, []string{testHost})
	info, err := client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
	if err != nil || info.RetryAfter != time.Hour {
		t.Fatalf("renewal info = %+v, %v", info, err)
	}
	replaces, err := certificate.MakeARICertID(leaf)
	if err != nil {
		t.Fatal(err)
	}
	renewedKey := newKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testHost}}, renewedKey)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: mustCSR(t, der), Bundle: true,
		ReplacesCertID: replaces})
	if err != nil {
		t.Fatalf("replacement: %v", err)
	}
	replacing := h.verify(t, renewed.Certificate, &renewedKey.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	h.verifyReplacement(t, leaf, replacing, info.SuggestedWindow.Start, info.SuggestedWindow.End)
	// lego retries without replaces on alreadyReplaced.
	again, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: mustCSR(t, der), Bundle: true,
		ReplacesCertID: replaces})
	if err != nil {
		t.Fatalf("order after alreadyReplaced: %v", err)
	}
	third := h.verify(t, again.Certificate, &renewedKey.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	if third.Replaces != "" {
		t.Fatalf("third order replaces %q after the server answered alreadyReplaced", third.Replaces)
	}
	t.Log("lego v4.35.2 read renewal information, replaced the certificate once and retried without the claim")
}
