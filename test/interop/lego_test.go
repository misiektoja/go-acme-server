package interop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Holds the lego account key and registration.
type legoUser struct {
	key          *ecdsa.PrivateKey
	registration *registration.Resource
}

// Returns no contact, as the server does not require one.
func (*legoUser) GetEmail() string { return "" }

// Returns the registration lego stored after Register.
func (u *legoUser) GetRegistration() *registration.Resource { return u.registration }

// Returns the account key.
func (u *legoUser) GetPrivateKey() crypto.PrivateKey { return u.key }

// Publishes the DNS-01 digests lego computes in the local responder.
type legoDNSProvider struct {
	responder *dnsResponder
}

// Adds the TXT value at the owner lego derives from the identifier.
func (p legoDNSProvider) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	p.responder.add(strings.ToLower(info.EffectiveFQDN), info.Value)
	return nil
}

// Removes only the completed value.
func (p legoDNSProvider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	p.responder.remove(strings.ToLower(info.EffectiveFQDN), info.Value)
	return nil
}

// Shortens lego's fixed pre-check sleep, since the responder answers immediately.
func (legoDNSProvider) Timeout() (time.Duration, time.Duration) {
	return 5 * time.Second, 50 * time.Millisecond
}

// Registers a lego account over the generated HTTPS trust root.
func (h *harness) lego(t *testing.T) *lego.Client {
	t.Helper()
	user := &legoUser{key: newKey(t)}
	config := lego.NewConfig(user)
	config.CADirURL = h.https.URL + "/acme/directory"
	config.HTTPClient = h.client
	config.UserAgent = "go-acme-server-interop"
	config.Certificate.KeyType = certcrypto.EC256
	config.Certificate.Timeout = 20 * time.Second
	client, err := lego.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	user.registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// Requests a certificate for a CSR with the chain bundled.
func legoObtain(t *testing.T, client *lego.Client, names ...string) (*ecdsa.PrivateKey, *certificate.Resource) {
	t.Helper()
	key := newKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: csr, Bundle: true})
	if err != nil {
		t.Fatalf("lego issuance: %v", err)
	}
	return key, resource
}

// Issues through lego's HTTP-01 server, then revokes through lego and confirms the second
// revocation is refused.
func TestLegoHTTP01Revocation(t *testing.T) {
	port := availablePort(t)
	h := newHarness(t, harnessOptions{httpPort: port})
	client := h.lego(t)
	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	}
	key, resource := legoObtain(t, client, testHost)
	order := h.verify(t, resource.Certificate, &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	if resource.CertURL != h.https.URL+"/acme/cert/"+order.CertificateID {
		t.Fatalf("certificate URL %q does not name the stored certificate %q", resource.CertURL, order.CertificateID)
	}
	reason := uint(4)
	if err := client.Certificate.RevokeWithReason(resource.Certificate, &reason); err != nil {
		t.Fatalf("revocation: %v", err)
	}
	h.verifyRevoked(t, order, 4)
	err := client.Certificate.Revoke(resource.Certificate)
	if err == nil || !strings.Contains(err.Error(), string(acmeserver.ErrorAlreadyRevoked)) {
		t.Fatalf("second revocation = %v", err)
	}
	t.Log("lego v4.35.2 HTTP-01 issuance, revocation with reason superseded and alreadyRevoked refusal passed")
}

// Issues through lego while the CA answers Pending for two seconds.
func TestLegoDelayedIssuance(t *testing.T) {
	port := availablePort(t)
	h := newHarness(t, harnessOptions{httpPort: port, delay: 2 * time.Second})
	client := h.lego(t)
	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	}
	key, resource := legoObtain(t, client, testHost)
	order := h.verify(t, resource.Certificate, &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	h.verifyDelayed(t, order)
	t.Log("lego v4.35.2 waited for a delayed issuance and received the certificate")
}

// Issues through lego's TLS-ALPN-01 listener and confirms lego closed it afterwards.
func TestLegoTLSALPN01(t *testing.T) {
	port := availablePort(t)
	h := newHarness(t, harnessOptions{tlsPort: port})
	client := h.lego(t)
	if err := client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	}
	key, resource := legoObtain(t, client, testHost)
	h.verify(t, resource.Certificate, &key.PublicKey, []string{testHost}, acmeserver.ChallengeTLSALPN01)
	if connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
		connection.Close()
		t.Fatal("the lego challenge listener is still accepting connections")
	}
	t.Log("lego v4.35.2 TLS-ALPN-01 issuance passed and the challenge listener was closed")
}

// Issues a wildcard with its base domain through lego's DNS-01 solver against the local responder.
func TestLegoDNS01Wildcard(t *testing.T) {
	// Keeps lego's CNAME discovery off the host resolver.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	responder, endpoint := newDNSResponder(t)
	h := newHarness(t, harnessOptions{dns: endpoint})
	client := h.lego(t)
	// Propagation is checked by the server against the isolated responder, not by lego.
	if err := client.Challenge.SetDNS01Provider(legoDNSProvider{responder: responder}, dns01.PropagationWait(0, true)); err != nil {
		t.Fatal(err)
	}
	names := []string{"*." + testHost, testHost}
	key, resource := legoObtain(t, client, names...)
	h.verify(t, resource.Certificate, &key.PublicKey, names, acmeserver.ChallengeDNS01)
	concurrent, remaining := responder.summary()
	if concurrent != 2 || remaining != 0 {
		t.Fatalf("most TXT values in one answer = %d, owners left = %d", concurrent, remaining)
	}
	t.Log("lego v4.35.2 wildcard and base-domain DNS-01 proofs coexisted at one TXT owner and were cleaned up")
}
