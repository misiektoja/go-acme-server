package interop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The Token Authority identity the harness trusts for tkauth-01.
const (
	tokenAuthorityURL = "https://authority.issuance.test"
	authorityCertURL  = "https://authority.issuance.test/cert"
)

// The id-pe-TNAuthList extension of RFC 8226 section 9.
var tnAuthListExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26}

// A DER TN authorization list with one service provider code entry.
var authorityList = []byte{0x30, 0x08, 0xa0, 0x06, 0x16, 0x04, '5', '6', '7', '8'}

// Signs RFC 9448 Authority Tokens with a self-signed certificate.
type tokenAuthority struct {
	key         *ecdsa.PrivateKey
	certificate *x509.Certificate
}

// Creates a Token Authority whose certificate is valid for an hour.
func newTokenAuthority(t *testing.T) *tokenAuthority {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "interop token authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
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

// Returns a compact ES256 Authority Token binding the list to an account key thumbprint.
func (a *tokenAuthority) token(t *testing.T, thumbprint string, list []byte, exp time.Time) string {
	t.Helper()
	header := mustJSON(t, map[string]any{"typ": "JWT", "alg": "ES256", "x5u": authorityCertURL})
	claims := mustJSON(t, map[string]any{"iss": tokenAuthorityURL, "exp": exp.Unix(), "jti": "interop-" + thumbprint[:8],
		"atc": map[string]any{"tktype": "TNAuthList", "tkvalue": base64.RawURLEncoding.EncodeToString(list), "fingerprint": thumbprint}})
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

// Returns a CSR that requests the TN authorization list and no names.
func tnAuthListCSR(t *testing.T, key crypto.Signer, list []byte) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{Id: tnAuthListExtension, Value: list}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Orders one TNAuthList identifier and returns its only challenge, which must be tkauth-01.
func (c *protocolClient) tkauthOrder(list []byte) (string, orderJSON, challengeJSON) {
	c.t.Helper()
	value := base64.RawURLEncoding.EncodeToString(list)
	orderURL, order := c.newOrderFor([]acmeserver.Identifier{{Type: acmeserver.IdentifierTNAuthList, Value: value}})
	if len(order.Identifiers) != 1 || order.Identifiers[0].Type != acmeserver.IdentifierTNAuthList || order.Identifiers[0].Value != value {
		c.t.Fatalf("identifiers = %+v", order.Identifiers)
	}
	var authz authorizationJSON
	c.get(order.Authorizations[0], &authz)
	if len(authz.Challenges) != 1 {
		c.t.Fatalf("challenges = %+v, want tkauth-01 alone", authz.Challenges)
	}
	ch := authz.Challenges[0]
	if ch.Type != string(acmeserver.ChallengeTKAuth01) || ch.TKAuthType != "atc" || ch.TokenAuthority != tokenAuthorityURL {
		c.t.Fatalf("challenge = %+v", ch)
	}
	return orderURL, order, ch
}

// Issues a TNAuthList certificate over HTTPS and SQLite with an Authority Token and checks that
// the token expiry bounds the certificate.
func TestTKAuth01Issuance(t *testing.T) {
	authority := newTokenAuthority(t)
	h := newHarness(t, harnessOptions{authority: authority})
	c := h.newProtocolClient(t)
	orderURL, order, ch := c.tkauthOrder(authorityList)
	exp := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	token := authority.token(t, joseThumbprint(t, &c.key.PublicKey), authorityList, exp)
	var answered challengeJSON
	if r := c.post(ch.URL, mustJSON(t, map[string]string{"tkauth": token}), &answered); r.status != http.StatusOK {
		t.Fatalf("challenge response: %d %s", r.status, r.body)
	}
	order = c.waitOrder(orderURL, "ready")
	key := newKey(t)
	if r := c.post(order.Finalize, finalizePayload(t, tnAuthListCSR(t, key, authorityList)), nil); r.status != http.StatusOK {
		t.Fatalf("finalize: %d %s", r.status, r.body)
	}
	order = c.waitOrder(orderURL, "valid")
	leaf, _ := h.verifyLeaf(t, c.certificate(order), &key.PublicKey, nil)
	value, found := leafAuthorityList(leaf)
	if !found || string(value) != string(authorityList) || leaf.IsCA {
		t.Fatalf("leaf authority list = %x found=%v CA=%v", value, found, leaf.IsCA)
	}
	if leaf.NotAfter.After(exp) {
		t.Fatalf("leaf NotAfter %v exceeds the token expiry %v", leaf.NotAfter, exp)
	}
	stored, err := h.store.Order(t.Context(), orderURL[strings.LastIndex(orderURL, "/")+1:])
	if err != nil || stored.Status != acmeserver.OrderValid || len(stored.AuthorizationIDs) != 1 {
		t.Fatalf("stored order = %+v, %v", stored, err)
	}
	authz, err := h.store.Authorization(t.Context(), stored.AuthorizationIDs[0])
	if err != nil || authz.Status != acmeserver.AuthorizationValid || !authz.GrantExpires.Equal(exp) {
		t.Fatalf("stored authorization = %+v, %v", authz, err)
	}
	h.verifyChallenges(t, authz, acmeserver.ChallengeTKAuth01)
	cert, err := h.store.Certificate(t.Context(), stored.CertificateID)
	if err != nil || len(cert.Validations) != 1 || cert.Validations[0].Type != acmeserver.ChallengeTKAuth01 ||
		!cert.Validations[0].GrantExpires.Equal(exp) {
		t.Fatalf("stored certificate evidence = %+v, %v", cert, err)
	}
	t.Log("tkauth-01 issuance over HTTPS and SQLite carried the TN authorization list and the token expiry bound")
}

// Refuses an Authority Token issued to another account key and leaves the order invalid.
func TestTKAuth01RejectsForeignToken(t *testing.T) {
	authority := newTokenAuthority(t)
	h := newHarness(t, harnessOptions{authority: authority})
	c := h.newProtocolClient(t)
	orderURL, _, ch := c.tkauthOrder(authorityList)
	foreign := authority.token(t, joseThumbprint(t, &newKey(t).PublicKey), authorityList, time.Now().Add(time.Hour))
	r := c.post(ch.URL, mustJSON(t, map[string]string{"tkauth": foreign}), nil)
	if r.status != http.StatusOK {
		t.Fatalf("challenge response: %d %s", r.status, r.body)
	}
	deadline := time.Now().Add(20 * time.Second)
	var order orderJSON
	for {
		c.get(orderURL, &order)
		if order.Status == "invalid" || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if order.Status != "invalid" {
		t.Fatalf("order is %s after a foreign token", order.Status)
	}
	var authz authorizationJSON
	c.get(order.Authorizations[0], &authz)
	if authz.Status != "invalid" || len(authz.Challenges) != 1 || authz.Challenges[0].Status != "invalid" {
		t.Fatalf("authorization = %+v", authz)
	}
	if rows, _ := h.issuances(t); rows != 0 {
		t.Fatalf("issuance rows = %d", rows)
	}
	t.Log("an Authority Token for another account key was refused without CA issuance")
}

// Returns the TN authorization list extension value of a certificate.
func leafAuthorityList(leaf *x509.Certificate) ([]byte, bool) {
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(tnAuthListExtension) {
			return extension.Value, true
		}
	}
	return nil, false
}
