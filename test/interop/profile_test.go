package interop

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The certificate profiles a harness with the profiles option offers. One is described elsewhere,
// so the directory carries both description forms.
var interopProfiles = []acmeserver.Profile{
	{Name: "tls-server-client", Description: "TLS server and client certificate"},
	{Name: "tls-client", Description: "TLS client certificate"},
	{Name: "short-lived", URL: "https://docs.acme.test/profiles/short-lived"},
}

// The profile an order gets when the client names none.
const interopDefaultProfile = "tls-server-client"

// Requests a profile through lego, falls back to the default without one and reports the refusal
// of a profile the server does not advertise.
func TestLegoProfiles(t *testing.T) {
	port := availablePort(t)
	h := newHarness(t, harnessOptions{httpPort: port, profiles: true})
	client := h.lego(t)
	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ requested, want string }{{"tls-client", "tls-client"}, {"", interopDefaultProfile}} {
		key := newKey(t)
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testHost}}, key)
		if err != nil {
			t.Fatal(err)
		}
		resource, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: mustCSR(t, der), Bundle: true,
			Profile: tc.requested})
		if err != nil {
			t.Fatalf("lego issuance with profile %q: %v", tc.requested, err)
		}
		order := h.verify(t, resource.Certificate, &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
		if order.Profile != tc.want {
			t.Fatalf("profile %q: stored order profile = %q, want %q", tc.requested, order.Profile, tc.want)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testHost}}, newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: mustCSR(t, der), Profile: "classic"})
	if err == nil || !strings.Contains(err.Error(), string(acmeserver.ErrorInvalidProfile)) {
		t.Fatalf("unadvertised profile = %v", err)
	}
	t.Log(clientLabel("lego") + " requested profile, default profile and invalidProfile refusal passed")
}

// Sends a required profile through Certbot and checks that Certbot drops a preferred profile the
// directory does not advertise, which leaves the order with the default.
func TestCertbotProfiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	executable := certbotExecutable(ctx, t)
	h := newHarness(t, harnessOptions{httpPort: availablePort(t), profiles: true})
	for i, tc := range []struct {
		flag, value, want string
	}{
		{"--required-profile", "tls-client", "tls-client"},
		{"--preferred-profile", "not-offered", interopDefaultProfile},
	} {
		key := newKey(t)
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testHost}}, key)
		if err != nil {
			t.Fatal(err)
		}
		run := strconv.Itoa(i)
		csrPath := filepath.Join(h.directory, "profile-"+run+".csr")
		writePrivate(t, csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
		fullchain := filepath.Join(h.directory, "profile-fullchain-"+run+".pem")
		h.certbot(ctx, t, executable, "certbot-profile-output-"+run+".txt", "certonly", "--standalone",
			"--preferred-challenges", "http", "--http-01-address", "127.0.0.1", "--http-01-port", strconv.Itoa(h.options.httpPort),
			"--csr", csrPath, "--cert-path", filepath.Join(h.directory, "profile-cert-"+run+".pem"),
			"--chain-path", filepath.Join(h.directory, "profile-chain-"+run+".pem"), "--fullchain-path", fullchain,
			"--agree-tos", "--register-unsafely-without-email", "--no-directory-hooks", tc.flag, tc.value)
		order := h.verify(t, readFile(t, fullchain), &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
		if order.Profile != tc.want {
			t.Fatalf("%s %s: stored order profile = %q, want %q", tc.flag, tc.value, order.Profile, tc.want)
		}
	}
	t.Log(certbotVersion + " required profile and unadvertised preferred profile passed")
}
