package interop

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The directory URLs the cross-check posts to.
type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	KeyChange  string `json:"keyChange"`
}

// The problem members the cross-check compares.
type problem struct {
	Type       string   `json:"type"`
	Status     int      `json:"status"`
	Algorithms []string `json:"algorithms"`
}

// Fetches a fresh nonce from the live server for each go-jose signature.
type nonceSource struct {
	h *harness
	t *testing.T
}

// Returns the Replay-Nonce of a new-nonce request.
func (n nonceSource) Nonce() (string, error) {
	n.t.Helper()
	response, err := n.h.client.Head(n.h.resources(n.t).NewNonce)
	if err != nil {
		return "", err
	}
	response.Body.Close()
	return response.Header.Get("Replay-Nonce"), nil
}

// Fetches the directory through the trusted HTTPS endpoint.
func (h *harness) resources(t *testing.T) directory {
	t.Helper()
	response, err := h.client.Get(h.https.URL + "/acme/directory")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var d directory
	if err := json.NewDecoder(response.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

// Describes one go-jose signature: the key, algorithm and ACME header shape.
type joseRequest struct {
	alg jose.SignatureAlgorithm
	key any
	// The account URL for kid requests. Empty embeds the JWK.
	kid string
	url string
	// Omits the nonce for inner key change and external account binding signatures.
	noNonce bool
	// Additional protected header members.
	extra map[jose.HeaderKey]any
}

// Signs a payload with go-jose in the flattened JSON serialization.
func (h *harness) joseSign(t *testing.T, r joseRequest, payload []byte) []byte {
	t.Helper()
	options := &jose.SignerOptions{EmbedJWK: r.kid == ""}
	if !r.noNonce {
		options.NonceSource = nonceSource{h, t}
	}
	options.WithHeader("url", r.url)
	if r.kid != "" {
		options.WithHeader("kid", r.kid)
	}
	for k, v := range r.extra {
		options.WithHeader(k, v)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: r.alg, Key: r.key}, options)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(signature.FullSerialize())
}

// Posts a JWS body and returns the status, headers and decoded body.
func (h *harness) post(t *testing.T, url string, body []byte) (*http.Response, []byte) {
	t.Helper()
	response, err := h.client.Post(url, "application/jose+json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response, data
}

// Requires an ACME problem with the given status and type.
func requireProblem(t *testing.T, response *http.Response, body []byte, status int, typ acmeserver.ErrorType) problem {
	t.Helper()
	var p problem
	if response.StatusCode != status || json.Unmarshal(body, &p) != nil || p.Type != "urn:ietf:params:acme:error:"+string(typ) {
		t.Fatalf("status %d body %s, want %d %s", response.StatusCode, body, status, typ)
	}
	return p
}

// Returns the go-jose RFC 7638 thumbprint of a public key.
func joseThumbprint(t *testing.T, key crypto.PublicKey) string {
	t.Helper()
	digest, err := (&jose.JSONWebKey{Key: key}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(digest)
}

// Compares a stored account against the key go-jose signed with.
func (h *harness) requireAccountKey(t *testing.T, location string, key crypto.PublicKey) *acmeserver.Account {
	t.Helper()
	account, err := h.store.Account(t.Context(), location[strings.LastIndex(location, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	expected, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := x509.MarshalPKIXPublicKey(account.Key)
	if err != nil || !bytes.Equal(stored, expected) {
		t.Fatalf("stored key differs: %v", err)
	}
	if account.KeyThumbprint != joseThumbprint(t, key) {
		t.Fatalf("thumbprint %s differs from go-jose", account.KeyThumbprint)
	}
	return account
}

// Generates signing keys for every algorithm the server advertises.
func joseKeys(t *testing.T) []joseRequest {
	t.Helper()
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return []joseRequest{{alg: jose.ES256, key: p256}, {alg: jose.ES384, key: p384}, {alg: jose.RS256, key: rsaKey}, {alg: jose.EdDSA, key: edKey}}
}

// Creates accounts, reads them, changes keys and binds external accounts with go-jose signatures.
func TestGoJoseAccounts(t *testing.T) {
	macKey := make([]byte, 32)
	if _, err := rand.Read(macKey); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, harnessOptions{httpPort: availablePort(t), eab: map[string][]byte{"eab-1": macKey}})
	d := h.resources(t)
	for _, r := range joseKeys(t) {
		t.Run(string(r.alg), func(t *testing.T) {
			r.url = d.NewAccount
			response, body := h.post(t, d.NewAccount, h.joseSign(t, r, []byte(`{"termsOfServiceAgreed":true}`)))
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("newAccount: %d %s", response.StatusCode, body)
			}
			location := response.Header.Get("Location")
			public := r.key.(crypto.Signer).Public()
			h.requireAccountKey(t, location, public)
			r.kid = location
			r.url = location
			response, body = h.post(t, location, h.joseSign(t, r, []byte{}))
			if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"valid"`) {
				t.Fatalf("POST-as-GET: %d %s", response.StatusCode, body)
			}
			r.url = d.NewOrder
			response, body = h.post(t, d.NewOrder, h.joseSign(t, r, []byte(`{"identifiers":[{"type":"dns","value":"`+testHost+`"}]}`)))
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("newOrder: %d %s", response.StatusCode, body)
			}
		})
	}
	t.Run("key change", func(t *testing.T) {
		old := joseKeys(t)[0]
		old.url = d.NewAccount
		response, body := h.post(t, d.NewAccount, h.joseSign(t, old, []byte(`{"termsOfServiceAgreed":true}`)))
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("newAccount: %d %s", response.StatusCode, body)
		}
		location := response.Header.Get("Location")
		replacement := joseRequest{alg: jose.ES256, key: p256Key(t)}
		oldJWK, err := json.Marshal(jose.JSONWebKey{Key: old.key.(crypto.Signer).Public()})
		if err != nil {
			t.Fatal(err)
		}
		inner := h.joseSign(t, joseRequest{alg: replacement.alg, key: replacement.key, url: d.KeyChange, noNonce: true},
			[]byte(`{"account":"`+location+`","oldKey":`+string(oldJWK)+`}`))
		response, body = h.post(t, d.KeyChange, h.joseSign(t, joseRequest{alg: old.alg, key: old.key, kid: location, url: d.KeyChange}, inner))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("keyChange: %d %s", response.StatusCode, body)
		}
		h.requireAccountKey(t, location, replacement.key.(crypto.Signer).Public())
		response, body = h.post(t, location, h.joseSign(t, joseRequest{alg: old.alg, key: old.key, kid: location, url: location}, []byte{}))
		requireProblem(t, response, body, http.StatusForbidden, acmeserver.ErrorUnauthorized)
		response, body = h.post(t, location, h.joseSign(t, joseRequest{alg: replacement.alg, key: replacement.key, kid: location, url: location}, []byte{}))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("POST-as-GET with the new key: %d %s", response.StatusCode, body)
		}
	})
	t.Run("external account binding", func(t *testing.T) {
		r := joseKeys(t)[3]
		r.url = d.NewAccount
		accountJWK, err := json.Marshal(jose.JSONWebKey{Key: r.key.(crypto.Signer).Public()})
		if err != nil {
			t.Fatal(err)
		}
		binding := h.joseSign(t, joseRequest{alg: jose.HS256, key: macKey, kid: "eab-1", url: d.NewAccount, noNonce: true}, accountJWK)
		response, body := h.post(t, d.NewAccount, h.joseSign(t, r, []byte(`{"termsOfServiceAgreed":true,"externalAccountBinding":`+string(binding)+`}`)))
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("newAccount with binding: %d %s", response.StatusCode, body)
		}
		account := h.requireAccountKey(t, response.Header.Get("Location"), r.key.(crypto.Signer).Public())
		if account.ExternalAccountID != "eab-1" {
			t.Fatalf("external account = %q", account.ExternalAccountID)
		}
		if account.ExternalAccountClaim != "eab-1" {
			t.Fatalf("external account claim = %q", account.ExternalAccountClaim)
		}
		response, body = h.post(t, d.NewAccount, h.joseSign(t, r, []byte(`{"termsOfServiceAgreed":true,"externalAccountBinding":`+string(binding)+`}`)))
		if response.StatusCode != http.StatusOK || response.Header.Get("Location") != h.https.URL+"/acme/acct/"+account.ID {
			t.Fatalf("retried newAccount with binding: %d %s", response.StatusCode, body)
		}
		wrong := h.joseSign(t, joseRequest{alg: jose.HS256, key: bytes.Repeat([]byte{1}, 32), kid: "eab-1", url: d.NewAccount, noNonce: true}, accountJWK)
		other := joseKeys(t)[0]
		other.url = d.NewAccount
		response, body = h.post(t, d.NewAccount, h.joseSign(t, other, []byte(`{"termsOfServiceAgreed":true,"externalAccountBinding":`+string(wrong)+`}`)))
		requireProblem(t, response, body, http.StatusForbidden, acmeserver.ErrorUnauthorized)
		otherJWK, err := json.Marshal(jose.JSONWebKey{Key: other.key.(crypto.Signer).Public()})
		if err != nil {
			t.Fatal(err)
		}
		reuse := h.joseSign(t, joseRequest{alg: jose.HS256, key: macKey, kid: "eab-1", url: d.NewAccount, noNonce: true}, otherJWK)
		response, body = h.post(t, d.NewAccount, h.joseSign(t, other, []byte(`{"termsOfServiceAgreed":true,"externalAccountBinding":`+string(reuse)+`}`)))
		requireProblem(t, response, body, http.StatusForbidden, acmeserver.ErrorUnauthorized)
		if _, err := h.store.AccountByKey(t.Context(), joseThumbprint(t, other.key.(crypto.Signer).Public())); err == nil {
			t.Fatal("a second account claimed the used binding")
		}
	})
	t.Log("go-jose v4.1.5 signatures, thumbprints, key change and external account binding agree with the server")
}

// Sends go-jose signatures the server must refuse and checks the problem type of each refusal.
func TestGoJoseRejectedRequests(t *testing.T) {
	h := newHarness(t, harnessOptions{httpPort: availablePort(t)})
	d := h.resources(t)
	keys := joseKeys(t)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"termsOfServiceAgreed":true}`)
	cases := []struct {
		name   string
		body   func(t *testing.T) []byte
		url    string
		status int
		typ    acmeserver.ErrorType
	}{
		{"PS256", func(t *testing.T) []byte {
			return h.joseSign(t, joseRequest{alg: jose.PS256, key: keys[2].key, url: d.NewAccount}, payload)
		}, d.NewAccount, http.StatusBadRequest, acmeserver.ErrorBadSignatureAlgorithm},
		{"ES512", func(t *testing.T) []byte {
			return h.joseSign(t, joseRequest{alg: jose.ES512, key: p521, url: d.NewAccount}, payload)
		}, d.NewAccount, http.StatusBadRequest, acmeserver.ErrorBadSignatureAlgorithm},
		{"HS256 account", func(t *testing.T) []byte {
			return h.joseSign(t, joseRequest{alg: jose.HS256, key: make([]byte, 32), kid: d.NewAccount, url: d.NewAccount}, payload)
		}, d.NewAccount, http.StatusBadRequest, acmeserver.ErrorBadSignatureAlgorithm},
		{"general serialization", func(t *testing.T) []byte {
			options := (&jose.SignerOptions{EmbedJWK: true, NonceSource: nonceSource{h, t}}).WithHeader("url", d.NewAccount)
			signer, err := jose.NewMultiSigner([]jose.SigningKey{{Algorithm: jose.ES256, Key: keys[0].key}, {Algorithm: jose.ES384, Key: keys[1].key}}, options)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			return []byte(signature.FullSerialize())
		}, d.NewAccount, http.StatusBadRequest, acmeserver.ErrorMalformed},
		{"compact serialization", func(t *testing.T) []byte {
			var parsed struct{ Protected, Payload, Signature string }
			if err := json.Unmarshal(h.joseSign(t, joseRequest{alg: jose.ES256, key: keys[0].key, url: d.NewAccount}, payload), &parsed); err != nil {
				t.Fatal(err)
			}
			return []byte(parsed.Protected + "." + parsed.Payload + "." + parsed.Signature)
		}, d.NewAccount, http.StatusBadRequest, acmeserver.ErrorMalformed},
		{"jwk and kid", func(t *testing.T) []byte {
			return h.joseSign(t, joseRequest{alg: jose.ES256, key: keys[0].key, url: d.NewAccount, extra: map[jose.HeaderKey]any{"kid": d.NewAccount}}, payload)
		}, d.NewAccount, http.StatusBadRequest, acmeserver.ErrorMalformed},
		{"crit", func(t *testing.T) []byte {
			return h.joseSign(t, joseRequest{alg: jose.ES256, key: keys[0].key, url: d.NewAccount, extra: map[jose.HeaderKey]any{"crit": []string{"url"}}}, payload)
		}, d.NewAccount, http.StatusBadRequest, acmeserver.ErrorMalformed},
		{"wrong url", func(t *testing.T) []byte {
			return h.joseSign(t, joseRequest{alg: jose.ES256, key: keys[0].key, url: d.NewOrder}, payload)
		}, d.NewAccount, http.StatusForbidden, acmeserver.ErrorUnauthorized},
		{"swapped signature", func(t *testing.T) []byte {
			var first, second map[string]string
			if err := json.Unmarshal(h.joseSign(t, joseRequest{alg: jose.ES256, key: keys[0].key, url: d.NewAccount}, payload), &first); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(h.joseSign(t, joseRequest{alg: jose.ES256, key: p256Key(t), url: d.NewAccount}, payload), &second); err != nil {
				t.Fatal(err)
			}
			first["signature"] = second["signature"]
			body, err := json.Marshal(first)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}, d.NewAccount, http.StatusForbidden, acmeserver.ErrorUnauthorized},
		{"unknown kid", func(t *testing.T) []byte {
			return h.joseSign(t, joseRequest{alg: jose.ES256, key: keys[0].key, kid: strings.TrimSuffix(d.NewAccount, "new-account") + "acct/missing", url: d.NewOrder}, payload)
		}, d.NewOrder, http.StatusBadRequest, acmeserver.ErrorAccountDoesNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response, body := h.post(t, tc.url, tc.body(t))
			p := requireProblem(t, response, body, tc.status, tc.typ)
			if tc.typ == acmeserver.ErrorBadSignatureAlgorithm && strings.Join(p.Algorithms, ",") != "ES256,ES384,RS256,EdDSA" {
				t.Fatalf("algorithms = %v", p.Algorithms)
			}
			if response.Header.Get("Replay-Nonce") == "" {
				t.Fatal("refusal carried no fresh nonce")
			}
		})
	}
	t.Run("replayed nonce", func(t *testing.T) {
		body := h.joseSign(t, joseRequest{alg: jose.ES256, key: keys[0].key, url: d.NewAccount}, payload)
		response, data := h.post(t, d.NewAccount, body)
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("first use: %d %s", response.StatusCode, data)
		}
		response, data = h.post(t, d.NewAccount, body)
		requireProblem(t, response, data, http.StatusBadRequest, acmeserver.ErrorBadNonce)
		if response.Header.Get("Replay-Nonce") == "" {
			t.Fatal("badNonce carried no fresh nonce")
		}
	})
	t.Log("go-jose v4.1.5 refusals map to the expected ACME problem types")
}

// Generates a P-256 key for a second signer.
func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
