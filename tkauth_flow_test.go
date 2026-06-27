package acmeserver_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/challenge"
)

// The tkauth-01 wire values the flow tests compare.
const (
	typeTKAuth01      = "tkauth-01"
	tkauthTypeATC     = "atc"
	tokenAuthorityURL = "https://authority.example.test"
	authorityCertURL  = "https://authority.example.test/cert"
)

// The id-pe-TNAuthList extension of RFC 8226 section 9.
var tnAuthListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26}

// The DER TN authorization list the flow tests order, a service provider code entry for 1234.
var flowAuthorityList = []byte{0x30, 0x08, 0xa0, 0x06, 0x16, 0x04, '1', '2', '3', '4'}

// Signs Authority Tokens for the flow tests.
type tokenAuthority struct {
	key         *ecdsa.PrivateKey
	certificate *x509.Certificate
}

// Returns a Token Authority with a self-signed certificate valid for an hour.
func newTokenAuthority(t *testing.T) *tokenAuthority {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "flow token authority"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tokenAuthority{key: key, certificate: certificate}
}

// Returns a compact Authority Token that attests the list for the account key thumbprint.
func (a *tokenAuthority) token(t *testing.T, thumbprint string, list []byte, ca bool) string {
	t.Helper()
	atc := map[string]any{"tktype": "TNAuthList", "tkvalue": base64.RawURLEncoding.EncodeToString(list),
		"fingerprint": thumbprint}
	if ca {
		atc["ca"] = true
	}
	header, err := json.Marshal(map[string]any{"typ": "JWT", "alg": "ES256", "x5u": authorityCertURL})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{"iss": tokenAuthorityURL, "exp": time.Now().Add(time.Hour).Unix(),
		"jti": "flow-token", "atc": atc})
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	der, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &pair); err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	pair.R.FillBytes(signature[:32])
	pair.S.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// Builds a server that offers tkauth-01 for TNAuthList identifiers alongside the network types.
func newTKAuthFlow(t *testing.T) (*flow, *tokenAuthority) {
	t.Helper()
	a := newTokenAuthority(t)
	validator, err := challenge.NewTKAuth01(challenge.TKAuthOptions{
		Authorities: challenge.StaticTokenAuthorities{
			ByURL: map[string]*x509.Certificate{authorityCertURL: a.certificate},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Validators[acmeserver.ChallengeTKAuth01] = validator
		cfg.TNAuthListIdentifiers = true
		cfg.TokenAuthority = tokenAuthorityURL
	})
	return f, a
}

// Creates an order for one TNAuthList identifier.
func (c *client) newAuthorityListOrder(list []byte) (string, orderBody) {
	c.f.t.Helper()
	rec := c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{
		{"type": "TNAuthList", "value": base64.RawURLEncoding.EncodeToString(list)}}})
	if rec.Code != http.StatusCreated {
		c.f.t.Fatalf("new-order = %d %s", rec.Code, rec.Body.String())
	}
	var order orderBody
	decode(c.f.t, rec, &order)
	return rec.Header().Get("Location"), order
}

// Returns the only challenge of the order's first authorization.
func (c *client) onlyChallenge(order orderBody) challengeBody {
	c.f.t.Helper()
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	if len(authz.Challenges) != 1 {
		c.f.t.Fatalf("challenges = %d, want 1", len(authz.Challenges))
	}
	return authz.Challenges[0]
}

// Returns a CSR that requests the authority list and optionally a CA certificate.
func makeTNAuthListCSR(t *testing.T, key crypto.Signer, list []byte, ca bool) []byte {
	t.Helper()
	template := &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{{Id: tnAuthListOID, Value: list}},
	}
	if ca {
		value, err := asn1.Marshal(struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional,default:-1"`
		}{IsCA: true, MaxPathLen: -1})
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions,
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: value})
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Issues a certificate for a TNAuthList identifier through the Authority Token challenge.
func TestTKAuth01Issuance(t *testing.T) {
	f, authority := newTKAuthFlow(t)
	f.runWorker()
	c := f.newClient()
	c.register()
	orderURL, order := c.newAuthorityListOrder(flowAuthorityList)
	if len(order.Identifiers) != 1 || order.Identifiers[0].Type != acmeserver.IdentifierTNAuthList {
		t.Fatalf("identifiers = %v", order.Identifiers)
	}
	ch := c.onlyChallenge(order)
	if ch.Type != typeTKAuth01 || ch.TKAuthType != tkauthTypeATC || ch.TokenAuthority != tokenAuthorityURL {
		t.Fatalf("challenge = %+v", ch)
	}
	token := authority.token(t, thumbprint(t, &c.key.PublicKey), flowAuthorityList, false)
	rec := c.post(ch.URL, map[string]any{"tkauth": token})
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
	}
	order = c.waitOrder(orderURL, statusReady)
	certKey := newKey(t)
	if rec := c.finalizeCSR(order, makeTNAuthListCSR(t, certKey, flowAuthorityList, false)); rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d %s", rec.Code, rec.Body.String())
	}
	order = c.waitOrder(orderURL, statusValid)
	leaf := c.downloadLeaf(order)
	if leaf.IsCA {
		t.Fatal("an end-entity order produced a CA certificate")
	}
	found := false
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(tnAuthListOID) {
			found = true
			if string(extension.Value) != string(flowAuthorityList) {
				t.Fatalf("leaf authority list = %x", extension.Value)
			}
		}
	}
	if !found {
		t.Fatal("the leaf carries no TN authorization list")
	}
}

// Downloads the order certificate and returns its leaf.
func (c *client) downloadLeaf(order orderBody) *x509.Certificate {
	c.f.t.Helper()
	rec := c.post(order.Certificate, nil)
	if rec.Code != http.StatusOK {
		c.f.t.Fatalf("certificate = %d %s", rec.Code, rec.Body.String())
	}
	block, _ := pem.Decode(rec.Body.Bytes())
	if block == nil {
		c.f.t.Fatal("the certificate response is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.f.t.Fatal(err)
	}
	return leaf
}

// Carries the CA grant of an Authority Token through to the accepted certificate request.
func TestTKAuth01CAGrant(t *testing.T) {
	for _, granted := range []bool{true, false} {
		t.Run(map[bool]string{true: "granted", false: "withheld"}[granted], func(t *testing.T) {
			f, authority := newTKAuthFlow(t)
			f.runWorker()
			c := f.newClient()
			c.register()
			orderURL, order := c.newAuthorityListOrder(flowAuthorityList)
			ch := c.onlyChallenge(order)
			token := authority.token(t, thumbprint(t, &c.key.PublicKey), flowAuthorityList, granted)
			if rec := c.post(ch.URL, map[string]any{"tkauth": token}); rec.Code != http.StatusOK {
				t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
			}
			order = c.waitOrder(orderURL, statusReady)
			certKey := newKey(t)
			rec := c.finalizeCSR(order, makeTNAuthListCSR(t, certKey, flowAuthorityList, !granted))
			assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorBadCSR)
			if rec := c.finalizeCSR(order, makeTNAuthListCSR(t, certKey, flowAuthorityList, granted)); rec.Code != http.StatusOK {
				t.Fatalf("finalize = %d %s", rec.Code, rec.Body.String())
			}
			order = c.waitOrder(orderURL, statusValid)
			if leaf := c.downloadLeaf(order); leaf.IsCA != granted {
				t.Fatalf("leaf IsCA = %v, want %v", leaf.IsCA, granted)
			}
		})
	}
}

// Refuses responses and orders that do not follow the tkauth-01 rules.
func TestTKAuth01Refusals(t *testing.T) {
	f, authority := newTKAuthFlow(t)
	f.runWorker()
	c := f.newClient()
	c.register()
	t.Run("invalid authority list", func(t *testing.T) {
		rec := c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{
			{"type": "TNAuthList", "value": base64.RawURLEncoding.EncodeToString([]byte("hello"))}}})
		assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorRejectedIdentifier)
	})
	t.Run("unknown identifier case", func(t *testing.T) {
		rec := c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{
			{"type": "tnauthlist", "value": base64.RawURLEncoding.EncodeToString(flowAuthorityList)}}})
		assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorUnsupportedIdentifier)
	})
	_, order := c.newAuthorityListOrder(flowAuthorityList)
	ch := c.onlyChallenge(order)
	t.Run("response without a token", func(t *testing.T) {
		assertProblem(t, c.post(ch.URL, map[string]any{}), http.StatusBadRequest, acmeserver.ErrorMalformed)
	})
	t.Run("oversized token", func(t *testing.T) {
		big := make([]byte, 17<<10)
		for i := range big {
			big[i] = 'a'
		}
		assertProblem(t, c.post(ch.URL, map[string]any{"tkauth": string(big)}), http.StatusBadRequest,
			acmeserver.ErrorMalformed)
	})
	t.Run("token for another account", func(t *testing.T) {
		other := f.newClient()
		other.register()
		token := authority.token(t, thumbprint(t, &other.key.PublicKey), flowAuthorityList, false)
		if rec := c.post(ch.URL, map[string]any{"tkauth": token}); rec.Code != http.StatusOK {
			t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
		}
		waitFor(t, "challenge invalid", func() bool {
			var current challengeBody
			c.get(ch.URL, &current)
			return current.Status == statusInvalid
		})
		if f.ca.callCount() != 0 {
			t.Fatal("the CA was called for an unauthorized order")
		}
	})
}

// Rejects a tkauth field on a challenge type that does not use Authority Tokens.
func TestTKAuthFieldOnNetworkChallenge(t *testing.T) {
	f, _ := newTKAuthFlow(t)
	c := f.newClient()
	c.register()
	_, order := c.newOrder("tkauth.test")
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	for _, ch := range authz.Challenges {
		if ch.Type != typeHTTP01 {
			continue
		}
		if ch.TKAuthType != "" || ch.TokenAuthority != "" {
			t.Fatalf("an http-01 challenge carries authority token members: %+v", ch)
		}
		assertProblem(t, c.post(ch.URL, map[string]any{"tkauth": "token"}), http.StatusBadRequest,
			acmeserver.ErrorMalformed)
	}
}

// Refuses TNAuthList identifiers while the extension is not configured.
func TestTNAuthListRequiresConfiguration(t *testing.T) {
	f := newFlow(t, nil)
	c := f.newClient()
	c.register()
	rec := c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{
		{"type": "TNAuthList", "value": base64.RawURLEncoding.EncodeToString(flowAuthorityList)}}})
	assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorUnsupportedIdentifier)
}
