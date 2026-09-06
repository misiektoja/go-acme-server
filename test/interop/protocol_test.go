package interop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Wire views read back by the protocol client.
type orderJSON struct {
	Status         string                  `json:"status"`
	Identifiers    []acmeserver.Identifier `json:"identifiers"`
	Authorizations []string                `json:"authorizations"`
	Finalize       string                  `json:"finalize"`
	Certificate    string                  `json:"certificate"`
}

type challengeJSON struct {
	Type           string `json:"type"`
	URL            string `json:"url"`
	Status         string `json:"status"`
	Token          string `json:"token"`
	TKAuthType     string `json:"tkauth-type"`
	TokenAuthority string `json:"token-authority"`
}

type authorizationJSON struct {
	Identifier acmeserver.Identifier `json:"identifier"`
	Status     string                `json:"status"`
	Challenges []challengeJSON       `json:"challenges"`
}

// The outcome of one HTTP exchange, safe to collect from goroutines.
type reply struct {
	status int
	header http.Header
	body   []byte
	err    error
}

// Posts a prepared JWS without touching the test object, so goroutines can use it.
func (h *harness) postRaw(url string, body []byte) reply {
	response, err := h.client.Post(url, "application/jose+json", bytes.NewReader(body))
	if err != nil {
		return reply{err: err}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return reply{status: response.StatusCode, header: response.Header, body: data, err: err}
}

// Drives ACME resources with go-jose signatures and reads the server's own resource views.
type protocolClient struct {
	h   *harness
	t   *testing.T
	key *ecdsa.PrivateKey
	kid string
	d   directory
}

// Registers a P-256 account and returns a client bound to it.
func (h *harness) newProtocolClient(t *testing.T) *protocolClient {
	t.Helper()
	c := &protocolClient{h: h, t: t, key: newKey(t), d: h.resources(t)}
	response, body := h.post(t, c.d.NewAccount, c.signEmbedded(c.d.NewAccount, []byte(`{"termsOfServiceAgreed":true}`)))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("newAccount: %d %s", response.StatusCode, body)
	}
	c.kid = response.Header.Get("Location")
	return c
}

// Signs with the embedded account JWK, as newAccount requires.
func (c *protocolClient) signEmbedded(url string, payload []byte) []byte {
	c.t.Helper()
	return c.h.joseSign(c.t, joseRequest{alg: jose.ES256, key: c.key, url: url}, payload)
}

// Signs with the account URL as kid.
func (c *protocolClient) sign(url string, payload []byte) []byte {
	c.t.Helper()
	return c.h.joseSign(c.t, joseRequest{alg: jose.ES256, key: c.key, kid: c.kid, url: url}, payload)
}

// Posts a signed payload and decodes a successful JSON response into v.
func (c *protocolClient) post(url string, payload []byte, v any) reply {
	c.t.Helper()
	r := c.h.postRaw(url, c.sign(url, payload))
	if r.err != nil {
		c.t.Fatal(r.err)
	}
	if v != nil && r.status < 300 {
		if err := json.Unmarshal(r.body, v); err != nil {
			c.t.Fatalf("decode %s: %v", r.body, err)
		}
	}
	return r
}

// Creates an order for DNS names and returns its URL and view.
func (c *protocolClient) newOrder(names ...string) (string, orderJSON) {
	c.t.Helper()
	identifiers := make([]acmeserver.Identifier, 0, len(names))
	for _, name := range names {
		identifiers = append(identifiers, acmeserver.Identifier{Type: acmeserver.IdentifierDNS, Value: name})
	}
	return c.newOrderFor(identifiers)
}

// Creates an order for any identifiers and returns its URL and view.
func (c *protocolClient) newOrderFor(identifiers []acmeserver.Identifier) (string, orderJSON) {
	c.t.Helper()
	payload, err := json.Marshal(map[string]any{"identifiers": identifiers})
	if err != nil {
		c.t.Fatal(err)
	}
	var order orderJSON
	r := c.post(c.d.NewOrder, payload, &order)
	if r.status != http.StatusCreated {
		c.t.Fatalf("newOrder: %d %s", r.status, r.body)
	}
	return r.header.Get("Location"), order
}

// Fetches a resource with POST-as-GET.
func (c *protocolClient) get(url string, v any) reply {
	c.t.Helper()
	r := c.post(url, []byte{}, v)
	if r.status != http.StatusOK {
		c.t.Fatalf("GET %s: %d %s", url, r.status, r.body)
	}
	return r
}

// Returns the key authorization for a challenge token under this account key.
func (c *protocolClient) keyAuthorization(token string) string {
	c.t.Helper()
	return token + "." + joseThumbprint(c.t, &c.key.PublicKey)
}

// Returns the challenge of one type from an authorization view.
func (c *protocolClient) challenge(authzURL string, typ acmeserver.ChallengeType) (authorizationJSON, challengeJSON) {
	c.t.Helper()
	var authz authorizationJSON
	c.get(authzURL, &authz)
	for _, ch := range authz.Challenges {
		if ch.Type == string(typ) {
			return authz, ch
		}
	}
	c.t.Fatalf("no %s challenge in %+v", typ, authz)
	return authz, challengeJSON{}
}

// Publishes an HTTP-01 proof in the local responder.
func (c *protocolClient) presentHTTP(s *solver, ch challengeJSON) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proofs["/.well-known/acme-challenge/"+ch.Token] = c.keyAuthorization(ch.Token)
}

// Publishes a DNS-01 digest in the local responder.
func (c *protocolClient) presentDNS(d *dnsResponder, name string, ch challengeJSON) {
	digest := sha256.Sum256([]byte(c.keyAuthorization(ch.Token)))
	d.add("_acme-challenge."+strings.ToLower(name)+".", base64.RawURLEncoding.EncodeToString(digest[:]))
}

// Polls an order until it reaches the status or the deadline passes.
func (c *protocolClient) waitOrder(url, status string) orderJSON {
	c.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var order orderJSON
		c.get(url, &order)
		if order.Status == status {
			return order
		}
		if order.Status == "invalid" || time.Now().After(deadline) {
			c.t.Fatalf("order is %s while waiting for %s", order.Status, status)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Builds the finalize payload for a CSR.
func finalizePayload(t *testing.T, csr []byte) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"csr": base64.RawURLEncoding.EncodeToString(csr)})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// Creates a CSR for the names with a fresh key.
func newCSR(t *testing.T, names ...string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key := newKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, csr
}

// Downloads the certificate chain of a valid order.
func (c *protocolClient) certificate(order orderJSON) []byte {
	c.t.Helper()
	if order.Certificate == "" {
		c.t.Fatal("valid order has no certificate URL")
	}
	return c.get(order.Certificate, nil).body
}

// Runs fn concurrently n times and returns the replies in call order.
func concurrently(n int, fn func(i int) reply) []reply {
	replies := make([]reply, n)
	done := make(chan struct{})
	for i := range n {
		go func() {
			defer func() { done <- struct{}{} }()
			replies[i] = fn(i)
		}()
	}
	for range n {
		<-done
	}
	return replies
}

// Counts replies with the status and fails on transport errors.
func countStatus(t *testing.T, replies []reply, status int) int {
	t.Helper()
	n := 0
	for _, r := range replies {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.status == status {
			n++
		}
	}
	return n
}

// Reads the CA's issuance row count and total call count.
func (h *harness) issuances(t *testing.T) (int, int) {
	t.Helper()
	var rows, calls int
	if err := h.ca.db.QueryRowContext(t.Context(), "SELECT count(*), coalesce(sum(calls), 0) FROM issuance").Scan(&rows, &calls); err != nil {
		t.Fatal(err)
	}
	return rows, calls
}
