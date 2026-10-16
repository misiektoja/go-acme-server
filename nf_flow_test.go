package acmeserver_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The NF instance the flow tests order, the example value of 3GPP TS 33.310 clause J.3.3.2.
const flowNfInstance = "4ace9d34-2c69-4f99-92d5-a73a3fe8e23b"

// The names the flow tests' NF tokens grant beyond the instance.
const (
	flowNFName = "amf1.example.test"
	flowNFRoot = "https://amf1.example.test/api"
	flowNFIP   = "192.0.2.10"
)

// Builds a server that offers tkauth-01 for NfInstanceId identifiers alongside the network types.
func newNFFlow(t *testing.T) (*flow, *tokenAuthority) {
	t.Helper()
	return newTokenFlow(t, nil, func(cfg *acmeserver.Config) { cfg.NfInstanceIDIdentifiers = true })
}

// Returns an NF Certificate Authority Token for the instance and account key thumbprint. A nil
// sans list leaves the claim out.
func (a *tokenAuthority) nfToken(t *testing.T, thumbprint, instance, nfType string, sans []string) string {
	t.Helper()
	atc := map[string]any{"tktype": "NfInstanceId", "tkvalue": instance, "fingerprint": thumbprint}
	if nfType != "" {
		atc["nftype"] = nfType
	}
	if sans != nil {
		atc["sans"] = sans
	}
	return a.sign(t, atc, time.Now().Add(time.Hour))
}

// Creates an order for one NfInstanceId identifier and any DNS names.
func (c *client) newNFOrder(instance string, names ...string) (string, orderBody) {
	c.f.t.Helper()
	rec := c.postNFOrder(instance, names...)
	if rec.Code != http.StatusCreated {
		c.f.t.Fatalf("new-order = %d %s", rec.Code, rec.Body.String())
	}
	var order orderBody
	decode(c.f.t, rec, &order)
	return rec.Header().Get("Location"), order
}

// Posts a new order for one NfInstanceId identifier and any DNS names.
func (c *client) postNFOrder(instance string, names ...string) *httptest.ResponseRecorder {
	c.f.t.Helper()
	identifiers := make([]map[string]string, 0, 1+len(names))
	identifiers = append(identifiers, map[string]string{"type": "NfInstanceId", "value": instance})
	for _, name := range names {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": name})
	}
	return c.post(baseURL+"new-order", map[string]any{"identifiers": identifiers})
}

// Orders the test instance, answers its challenge with a token that grants the test names and
// returns the ready order.
func (c *client) readyNFOrder(authority *tokenAuthority) (string, orderBody) {
	c.f.t.Helper()
	orderURL, order := c.newNFOrder(flowNfInstance)
	ch := c.onlyChallenge(order)
	token := authority.nfToken(c.f.t, thumbprint(c.f.t, &c.key.PublicKey), flowNfInstance, "AMF",
		[]string{flowNFName, flowNFRoot, flowNFIP})
	if rec := c.post(ch.URL, map[string]any{"tkauth": token}); rec.Code != http.StatusOK {
		c.f.t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
	}
	return orderURL, c.waitOrder(orderURL, statusReady)
}

// Returns a CSR for the URI, DNS and IP names with the common name.
func makeNFCSR(t *testing.T, key crypto.Signer, commonName string, uris []string, dnsNames []string, ips []string) []byte {
	t.Helper()
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames}
	for _, raw := range uris {
		uri, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = append(template.URIs, uri)
	}
	for _, ip := range ips {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Issues a network function certificate for an NfInstanceId identifier with the names the
// token grants, after the flow of 3GPP TS 33.310 Annex J.
func TestNfInstanceIssuance(t *testing.T) {
	f, authority := newNFFlow(t)
	f.runWorker()
	c := f.newClient()
	c.register()
	orderURL, order := c.newNFOrder(strings.ToUpper(flowNfInstance))
	want := []acmeserver.Identifier{{Type: acmeserver.IdentifierNfInstanceID, Value: flowNfInstance}}
	if !slices.Equal(order.Identifiers, want) {
		t.Fatalf("identifiers = %v, want %v", order.Identifiers, want)
	}
	ch := c.onlyChallenge(order)
	if ch.Type != typeTKAuth01 || ch.TKAuthType != tkauthTypeATC || ch.TokenAuthority != tokenAuthorityURL {
		t.Fatalf("challenge = %+v", ch)
	}
	token := authority.nfToken(t, thumbprint(t, &c.key.PublicKey), flowNfInstance, "AMF",
		[]string{flowNFName, flowNFRoot, flowNFIP})
	if rec := c.post(ch.URL, map[string]any{"tkauth": token}); rec.Code != http.StatusOK {
		t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
	}
	order = c.waitOrder(orderURL, statusReady)
	// The common name is outside the identifier model of an NF certificate, so it is not checked.
	csr := makeNFCSR(t, newKey(t), "any name", []string{"urn:uuid:" + flowNfInstance, flowNFRoot},
		[]string{flowNFName}, []string{flowNFIP})
	if rec := c.finalizeCSR(order, csr); rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d %s", rec.Code, rec.Body.String())
	}
	order = c.waitOrder(orderURL, statusValid)
	leaf := c.downloadLeaf(order)
	uris := make([]string, 0, len(leaf.URIs))
	for _, uri := range leaf.URIs {
		uris = append(uris, uri.String())
	}
	if !slices.Equal(uris, []string{"urn:uuid:" + flowNfInstance, flowNFRoot}) ||
		!slices.Equal(leaf.DNSNames, []string{flowNFName}) || len(leaf.IPAddresses) != 1 {
		t.Fatalf("leaf names = %v %v %v", uris, leaf.DNSNames, leaf.IPAddresses)
	}
	f.ca.mu.Lock()
	request := f.ca.calls[0]
	f.ca.mu.Unlock()
	if len(request.Validations) != 1 || request.Validations[0].NFType != "AMF" ||
		len(request.Validations[0].Names) != 3 || request.Validations[0].Type != acmeserver.ChallengeTKAuth01 {
		t.Fatalf("issuance evidence = %+v", request.Validations)
	}
}

// Accepts a request for the instance and any granted names, and refuses anything else.
func TestNfInstanceRequestScope(t *testing.T) {
	f, authority := newNFFlow(t)
	f.runWorker()
	c := f.newClient()
	c.register()
	orderURL, order := c.readyNFOrder(authority)
	key := newKey(t)
	urn := "urn:uuid:" + flowNfInstance
	refused := map[string][]byte{
		"instance missing":    makeNFCSR(t, key, "", []string{flowNFRoot}, []string{flowNFName}, nil),
		"name not granted":    makeNFCSR(t, key, "", []string{urn}, []string{"other.example.test"}, nil),
		"URI not granted":     makeNFCSR(t, key, "", []string{urn, "https://other.example.test/api"}, nil, nil),
		"another instance":    makeNFCSR(t, key, "", []string{urn, "urn:uuid:5bce9d34-2c69-4f99-92d5-a73a3fe8e23b"}, nil, nil),
		"unsupported URI":     makeNFCSR(t, key, "", []string{urn, "urn:isbn:0451450523"}, nil, nil),
		"common name only":    makeNFCSR(t, key, flowNFName, nil, nil, nil),
		"address not granted": makeNFCSR(t, key, "", []string{urn}, nil, []string{"192.0.2.11"}),
	}
	for name, csr := range refused {
		t.Run(name, func(t *testing.T) {
			assertProblem(t, c.finalizeCSR(order, csr), http.StatusBadRequest, acmeserver.ErrorBadCSR)
		})
	}
	if f.ca.callCount() != 0 {
		t.Fatal("the CA was called for a refused request")
	}
	if rec := c.finalizeCSR(order, makeNFCSR(t, key, "", []string{urn}, nil, nil)); rec.Code != http.StatusOK {
		t.Fatalf("finalize with the instance alone = %d %s", rec.Code, rec.Body.String())
	}
	c.waitOrder(orderURL, statusValid)
}

// Refuses NfInstanceId orders the server cannot or must not serve.
func TestNfInstanceOrderRefusals(t *testing.T) {
	f, _ := newNFFlow(t)
	c := f.newClient()
	c.register()
	cases := map[string]struct {
		identifiers []map[string]string
		want        acmeserver.ErrorType
	}{
		"not a UUID": {[]map[string]string{{"type": "NfInstanceId", "value": "amf-1"}},
			acmeserver.ErrorRejectedIdentifier},
		"two instances": {[]map[string]string{{"type": "NfInstanceId", "value": flowNfInstance},
			{"type": "NfInstanceId", "value": "5bce9d34-2c69-4f99-92d5-a73a3fe8e23b"}}, acmeserver.ErrorMalformed},
		"uri name": {[]map[string]string{{"type": "uri", "value": flowNFRoot}},
			acmeserver.ErrorUnsupportedIdentifier},
		"type in another case": {[]map[string]string{{"type": "nfinstanceid", "value": flowNfInstance}},
			acmeserver.ErrorUnsupportedIdentifier},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := c.post(baseURL+"new-order", map[string]any{"identifiers": tc.identifiers})
			assertProblem(t, rec, http.StatusBadRequest, tc.want)
		})
	}
	t.Run("combined with an authority list", func(t *testing.T) {
		f, _ := newTokenFlow(t, nil, func(cfg *acmeserver.Config) {
			cfg.NfInstanceIDIdentifiers, cfg.TNAuthListIdentifiers = true, true
		})
		c := f.newClient()
		c.register()
		rec := c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{
			{"type": "NfInstanceId", "value": flowNfInstance},
			{"type": "TNAuthList", "value": base64.RawURLEncoding.EncodeToString(flowAuthorityList)}}})
		assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorMalformed)
	})
	t.Run("not configured", func(t *testing.T) {
		f, _ := newTKAuthFlow(t)
		c := f.newClient()
		c.register()
		assertProblem(t, c.postNFOrder(flowNfInstance), http.StatusBadRequest, acmeserver.ErrorUnsupportedIdentifier)
	})
}

// Offers tkauth-01 only for the instance of an order that also names a DNS identifier.
func TestNfInstanceMixedOrder(t *testing.T) {
	f, _ := newNFFlow(t)
	c := f.newClient()
	c.register()
	_, order := c.newNFOrder(flowNfInstance, "mixed.example.test")
	for _, authzURL := range order.Authorizations {
		var authz authzBody
		c.get(authzURL, &authz)
		token := authz.Identifier.Type == acmeserver.IdentifierNfInstanceID
		for _, ch := range authz.Challenges {
			if (ch.Type == typeTKAuth01) != token {
				t.Fatalf("%s offers %s", authz.Identifier, ch.Type)
			}
		}
	}
}

// Limits revocation of an NF certificate to the enrolling account and the certificate key, see
// 3GPP TS 33.310 clause J.4, even for an account that holds a valid authorization for the instance.
func TestNfInstanceRevocation(t *testing.T) {
	f, authority := newNFFlow(t)
	f.runWorker()
	owner := f.newClient()
	owner.register()
	orderURL, order := owner.readyNFOrder(authority)
	csr := makeNFCSR(t, newKey(t), "", []string{"urn:uuid:" + flowNfInstance}, nil, nil)
	if rec := owner.finalizeCSR(order, csr); rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d %s", rec.Code, rec.Body.String())
	}
	leaf := owner.downloadLeaf(owner.waitOrder(orderURL, statusValid))
	payload := map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(leaf.Raw)}
	other := f.newClient()
	other.register()
	other.readyNFOrder(authority)
	assertProblem(t, other.post(baseURL+"revoke-cert", payload), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	if rec := owner.post(baseURL+"revoke-cert", payload); rec.Code != http.StatusOK {
		t.Fatalf("revocation by the enrolling account = %d %s", rec.Code, rec.Body.String())
	}
}
