package acmeserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/misiektoja/go-acme-server/internal/jws"
)

// The ID of the account most request tests seed.
const testAccountID = "acct-test-1"

// Pairs a private key with the JWS algorithm it signs with.
type signer struct {
	key crypto.Signer
	alg string
}

// Generates a key for the algorithm.
func newSigner(t *testing.T, alg string) signer {
	t.Helper()
	var key crypto.Signer
	var err error
	switch alg {
	case "ES256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "RS256":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "EdDSA":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unsupported algorithm %s", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: key, alg: alg}
}

// Builds a flattened JWS with the given protected header and payload.
func (s signer) sign(t *testing.T, header map[string]any, payload []byte) []byte {
	t.Helper()
	header["alg"] = s.alg
	protected, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p := base64.RawURLEncoding.EncodeToString(protected)
	pl := base64.RawURLEncoding.EncodeToString(payload)
	input := []byte(p + "." + pl)
	var sig []byte
	switch k := s.key.(type) {
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		var digest []byte
		switch s.alg {
		case "ES384":
			d := sha512.Sum384(input)
			digest = d[:]
		case "ES512":
			d := sha512.Sum512(input)
			digest = d[:]
		default:
			d := sha256.Sum256(input)
			digest = d[:]
		}
		der, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			t.Fatal(err)
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &rs); err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 2*size)
		rs.R.FillBytes(sig[:size])
		rs.S.FillBytes(sig[size:])
	case *rsa.PrivateKey:
		d := sha256.Sum256(input)
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, input)
	}
	body, err := json.Marshal(map[string]string{"protected": p, "payload": pl, "signature": base64.RawURLEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Returns the canonical JWK of the signer's public key.
func (s signer) jwk(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := jws.MarshalJWK(s.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Stores an account for the signer's key.
func seedAccount(t *testing.T, store *testStore, s signer, status AccountStatus) *Account {
	t.Helper()
	thumbprint, err := jws.Thumbprint(s.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{ID: testAccountID, Status: status, Key: s.key.Public(), KeyThumbprint: thumbprint}
	if err := store.CreateAccount(t.Context(), account); err != nil {
		t.Fatal(err)
	}
	return account
}

// Issues a nonce from the server's manager.
func freshNonce(t *testing.T, s *Server) string {
	t.Helper()
	value, err := s.nonces.Issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// Builds a POST with the JOSE media type.
func postJOSE(url string, body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	r.Header.Set("Content-Type", contentTypeJOSE)
	return r
}

// Returns a protected header that names the seeded account.
func accountHeader(s *Server, rel, nonceValue string) map[string]any {
	return map[string]any{"nonce": nonceValue, "url": s.resourceURL(rel), "kid": s.resourceURL(accountPathPrefix + testAccountID)}
}

func TestReadSignedRequestWithAccountKey(t *testing.T) {
	for _, alg := range []string{"ES256", "ES384", "ES512", "RS256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			s, store, _ := newTestServer(t, DirectoryMeta{})
			sig := newSigner(t, alg)
			account := seedAccount(t, store, sig, AccountValid)
			body := sig.sign(t, accountHeader(s, "new-order", freshNonce(t, s)), []byte(`{"identifiers":[]}`))
			req, p := s.readSignedRequest(postJOSE(s.resourceURL("new-order"), body), "new-order", keyModeAccount)
			if p != nil {
				t.Fatalf("readSignedRequest: %v", p)
			}
			if req.Account == nil || req.Account.ID != account.ID || req.Account.Revision != 1 {
				t.Fatalf("account = %+v", req.Account)
			}
			if string(req.Payload) != `{"identifiers":[]}` {
				t.Fatalf("payload = %s", req.Payload)
			}
			if thumb, _ := jws.Thumbprint(req.Key); thumb != account.KeyThumbprint {
				t.Fatal("request key is not the account key")
			}
		})
	}
}

func TestReadSignedRequestPostAsGet(t *testing.T) {
	s, store, _ := newTestServer(t, DirectoryMeta{})
	sig := newSigner(t, "ES256")
	seedAccount(t, store, sig, AccountValid)
	rel := accountPathPrefix + testAccountID
	body := sig.sign(t, accountHeader(s, rel, freshNonce(t, s)), nil)
	req, p := s.readSignedRequest(postJOSE(s.resourceURL(rel), body), rel, keyModeAccount)
	if p != nil {
		t.Fatalf("readSignedRequest: %v", p)
	}
	if len(req.Payload) != 0 {
		t.Fatalf("payload = %q, want empty", req.Payload)
	}
}

// Rejects request target changes that decoded routing would otherwise hide.
func TestSignedRequestBindsExactTarget(t *testing.T) {
	for _, target := range []string{"new-%6frder", "new-order?", "new-order/"} {
		t.Run(target, func(t *testing.T) {
			s, store, _ := newTestServer(t, DirectoryMeta{})
			sig := newSigner(t, "ES256")
			seedAccount(t, store, sig, AccountValid)
			body := sig.sign(t, accountHeader(s, "new-order", freshNonce(t, s)), []byte(`{}`))
			_, p := s.readSignedRequest(postJOSE(s.resourceURL(target), body), "new-order", keyModeAccount)
			if p == nil || p.Type != ErrorUnauthorized {
				t.Fatalf("altered request target accepted: %v", p)
			}
		})
	}
}

func TestReadSignedRequestWithEmbeddedKey(t *testing.T) {
	s, _, _ := newTestServer(t, DirectoryMeta{})
	sig := newSigner(t, "ES256")
	header := map[string]any{"nonce": freshNonce(t, s), "url": s.resourceURL("new-account"), "jwk": sig.jwk(t)}
	body := sig.sign(t, header, []byte(`{"termsOfServiceAgreed":true}`))
	req, p := s.readSignedRequest(postJOSE(s.resourceURL("new-account"), body), "new-account", keyModeEmbedded)
	if p != nil {
		t.Fatalf("readSignedRequest: %v", p)
	}
	if req.Account != nil || req.Key == nil {
		t.Fatalf("request = %+v", req)
	}
	header["nonce"] = freshNonce(t, s)
	header["url"] = s.resourceURL("revoke-cert")
	body = sig.sign(t, header, []byte(`{}`))
	if _, p := s.readSignedRequest(postJOSE(s.resourceURL("revoke-cert"), body), "revoke-cert", keyModeEither); p != nil {
		t.Fatalf("keyModeEither with jwk: %v", p)
	}
}

func TestReadSignedRequestKeyModeMismatch(t *testing.T) {
	s, store, _ := newTestServer(t, DirectoryMeta{})
	sig := newSigner(t, "ES256")
	seedAccount(t, store, sig, AccountValid)
	embedded := sig.sign(t, map[string]any{"nonce": freshNonce(t, s), "url": s.resourceURL("new-order"), "jwk": sig.jwk(t)}, []byte(`{}`))
	_, p := s.readSignedRequest(postJOSE(s.resourceURL("new-order"), embedded), "new-order", keyModeAccount)
	assertProblemType(t, p, ErrorMalformed, http.StatusBadRequest)
	byAccount := sig.sign(t, accountHeader(s, "new-account", freshNonce(t, s)), []byte(`{}`))
	_, p = s.readSignedRequest(postJOSE(s.resourceURL("new-account"), byAccount), "new-account", keyModeEmbedded)
	assertProblemType(t, p, ErrorMalformed, http.StatusBadRequest)
	byAccount = sig.sign(t, accountHeader(s, "revoke-cert", freshNonce(t, s)), []byte(`{}`))
	if _, p := s.readSignedRequest(postJOSE(s.resourceURL("revoke-cert"), byAccount), "revoke-cert", keyModeEither); p != nil {
		t.Fatalf("keyModeEither with kid: %v", p)
	}
}

func TestReadSignedRequestRejects(t *testing.T) {
	s, store, _ := newTestServer(t, DirectoryMeta{})
	sig := newSigner(t, "ES256")
	seedAccount(t, store, sig, AccountValid)
	other := newSigner(t, "ES256")
	rel := "new-order"
	cases := []struct {
		name   string
		req    func(t *testing.T) *http.Request
		typ    ErrorType
		status int
	}{
		{"wrong content type", func(t *testing.T) *http.Request {
			r := postJOSE(s.resourceURL(rel), sig.sign(t, accountHeader(s, rel, freshNonce(t, s)), []byte(`{}`)))
			r.Header.Set("Content-Type", "application/json")
			return r
		}, ErrorMalformed, http.StatusUnsupportedMediaType},
		{"missing content type", func(t *testing.T) *http.Request {
			r := postJOSE(s.resourceURL(rel), sig.sign(t, accountHeader(s, rel, freshNonce(t, s)), []byte(`{}`)))
			r.Header.Del("Content-Type")
			return r
		}, ErrorMalformed, http.StatusUnsupportedMediaType},
		{"oversized body", func(t *testing.T) *http.Request {
			return postJOSE(s.resourceURL(rel), []byte(`{"protected":"`+strings.Repeat("a", DefaultMaxRequestBody)+`"}`))
		}, ErrorMalformed, http.StatusRequestEntityTooLarge},
		{"not a jws", func(t *testing.T) *http.Request {
			return postJOSE(s.resourceURL(rel), []byte(`{"hello":"world"}`))
		}, ErrorMalformed, http.StatusBadRequest},
		{"duplicate member", func(t *testing.T) *http.Request {
			return postJOSE(s.resourceURL(rel), []byte(`{"protected":"e30","protected":"e30","payload":"","signature":"AA"}`))
		}, ErrorMalformed, http.StatusBadRequest},
		{"unsupported algorithm", func(t *testing.T) *http.Request {
			h := accountHeader(s, rel, freshNonce(t, s))
			body := sig.sign(t, h, []byte(`{}`))
			return postJOSE(s.resourceURL(rel), rewriteAlg(t, body, "HS256"))
		}, ErrorBadSignatureAlgorithm, http.StatusBadRequest},
		{"unknown nonce", func(t *testing.T) *http.Request {
			return postJOSE(s.resourceURL(rel), sig.sign(t, accountHeader(s, rel, "bm90LWlzc3VlZA"), []byte(`{}`)))
		}, ErrorBadNonce, http.StatusBadRequest},
		{"replayed nonce", func(t *testing.T) *http.Request {
			n := freshNonce(t, s)
			first := postJOSE(s.resourceURL(rel), sig.sign(t, accountHeader(s, rel, n), []byte(`{}`)))
			if _, p := s.readSignedRequest(first, rel, keyModeAccount); p != nil {
				t.Fatalf("first use: %v", p)
			}
			return postJOSE(s.resourceURL(rel), sig.sign(t, accountHeader(s, rel, n), []byte(`{}`)))
		}, ErrorBadNonce, http.StatusBadRequest},
		{"missing nonce", func(t *testing.T) *http.Request {
			h := accountHeader(s, rel, "x")
			delete(h, "nonce")
			return postJOSE(s.resourceURL(rel), sig.sign(t, h, []byte(`{}`)))
		}, ErrorBadNonce, http.StatusBadRequest},
		{"url mismatch", func(t *testing.T) *http.Request {
			h := accountHeader(s, rel, freshNonce(t, s))
			h["url"] = s.resourceURL("new-account")
			return postJOSE(s.resourceURL(rel), sig.sign(t, h, []byte(`{}`)))
		}, ErrorUnauthorized, http.StatusForbidden},
		{"url other host", func(t *testing.T) *http.Request {
			h := accountHeader(s, rel, freshNonce(t, s))
			h["url"] = "https://evil.example/acme/" + rel
			return postJOSE(s.resourceURL(rel), sig.sign(t, h, []byte(`{}`)))
		}, ErrorUnauthorized, http.StatusForbidden},
		{"kid on other host", func(t *testing.T) *http.Request {
			h := accountHeader(s, rel, freshNonce(t, s))
			h["kid"] = "https://evil.example/acme/acct/" + testAccountID
			return postJOSE(s.resourceURL(rel), sig.sign(t, h, []byte(`{}`)))
		}, ErrorMalformed, http.StatusBadRequest},
		{"kid with path traversal", func(t *testing.T) *http.Request {
			h := accountHeader(s, rel, freshNonce(t, s))
			h["kid"] = s.resourceURL(accountPathPrefix + "../new-order")
			return postJOSE(s.resourceURL(rel), sig.sign(t, h, []byte(`{}`)))
		}, ErrorMalformed, http.StatusBadRequest},
		{"unknown account", func(t *testing.T) *http.Request {
			h := accountHeader(s, rel, freshNonce(t, s))
			h["kid"] = s.resourceURL(accountPathPrefix + "does-not-exist")
			return postJOSE(s.resourceURL(rel), sig.sign(t, h, []byte(`{}`)))
		}, ErrorAccountDoesNotExist, http.StatusBadRequest},
		{"wrong key", func(t *testing.T) *http.Request {
			return postJOSE(s.resourceURL(rel), other.sign(t, accountHeader(s, rel, freshNonce(t, s)), []byte(`{}`)))
		}, ErrorUnauthorized, http.StatusForbidden},
		{"tampered payload", func(t *testing.T) *http.Request {
			body := sig.sign(t, accountHeader(s, rel, freshNonce(t, s)), []byte(`{"a":1}`))
			var env map[string]string
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatal(err)
			}
			env["payload"] = base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`))
			raw, _ := json.Marshal(env)
			return postJOSE(s.resourceURL(rel), raw)
		}, ErrorUnauthorized, http.StatusForbidden},
		{"algorithm key mismatch", func(t *testing.T) *http.Request {
			body := sig.sign(t, accountHeader(s, rel, freshNonce(t, s)), []byte(`{}`))
			return postJOSE(s.resourceURL(rel), rewriteAlg(t, body, "RS256"))
		}, ErrorMalformed, http.StatusBadRequest},
		{"embedded private key", func(t *testing.T) *http.Request {
			h := map[string]any{"nonce": freshNonce(t, s), "url": s.resourceURL("new-account")}
			h["jwk"] = json.RawMessage(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","d":"AAAA"}`)
			return postJOSE(s.resourceURL("new-account"), sig.sign(t, h, []byte(`{}`)))
		}, ErrorBadPublicKey, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode := keyModeAccount
			r := tc.req(t)
			resource := rel
			if strings.HasSuffix(r.URL.Path, "new-account") {
				mode, resource = keyModeEmbedded, "new-account"
			}
			_, p := s.readSignedRequest(r, resource, mode)
			assertProblemType(t, p, tc.typ, tc.status)
			if tc.typ == ErrorBadSignatureAlgorithm && strings.Join(p.Algorithms, ",") != "ES256,ES384,ES512,RS256,EdDSA" {
				t.Fatalf("algorithms = %v", p.Algorithms)
			}
		})
	}
}

func TestReadSignedRequestAccountStatus(t *testing.T) {
	for _, status := range []AccountStatus{AccountDeactivated, AccountRevoked} {
		t.Run(string(status), func(t *testing.T) {
			s, store, _ := newTestServer(t, DirectoryMeta{})
			sig := newSigner(t, "ES256")
			seedAccount(t, store, sig, status)
			body := sig.sign(t, accountHeader(s, "new-order", freshNonce(t, s)), []byte(`{}`))
			_, p := s.readSignedRequest(postJOSE(s.resourceURL("new-order"), body), "new-order", keyModeAccount)
			assertProblemType(t, p, ErrorUnauthorized, http.StatusForbidden)
		})
	}
}

func TestReadSignedRequestStoreFailure(t *testing.T) {
	s, _, _ := newTestServer(t, DirectoryMeta{})
	s.store = failingStore{}
	sig := newSigner(t, "ES256")
	body := sig.sign(t, accountHeader(s, "new-order", freshNonce(t, s)), []byte(`{}`))
	_, p := s.readSignedRequest(postJOSE(s.resourceURL("new-order"), body), "new-order", keyModeAccount)
	assertProblemType(t, p, ErrorServerInternal, http.StatusInternalServerError)
}

func TestReadSignedRequestNonceFailure(t *testing.T) {
	s, store, _ := newTestServer(t, DirectoryMeta{})
	sig := newSigner(t, "ES256")
	seedAccount(t, store, sig, AccountValid)
	body := sig.sign(t, accountHeader(s, "new-order", "bm9uY2U"), []byte(`{}`))
	s.nonces = failingNonces{}
	_, p := s.readSignedRequest(postJOSE(s.resourceURL("new-order"), body), "new-order", keyModeAccount)
	assertProblemType(t, p, ErrorServerInternal, http.StatusInternalServerError)
}

func TestValidID(t *testing.T) {
	if !validID("abc-DEF_123") || validID("") || validID("a/b") || validID("a.b") || validID(strings.Repeat("a", maxIDLength+1)) {
		t.Fatal("validID accepted or rejected the wrong IDs")
	}
}

func TestProblemFromJWS(t *testing.T) {
	if p := problemFromJWS(errors.New("plain")); p.Type != ErrorMalformed {
		t.Fatalf("plain error mapped to %s", p.Type)
	}
	cases := map[jws.Code]ErrorType{
		jws.CodeMalformed:             ErrorMalformed,
		jws.CodeBadNonce:              ErrorBadNonce,
		jws.CodeBadSignatureAlgorithm: ErrorBadSignatureAlgorithm,
		jws.CodeBadPublicKey:          ErrorBadPublicKey,
		jws.CodeBadSignature:          ErrorUnauthorized,
	}
	for code, want := range cases {
		if p := problemFromJWS(&jws.Error{Code: code, Detail: "d"}); p.Type != want || p.Detail != "d" {
			t.Fatalf("code %d mapped to %+v", code, p)
		}
	}
}

// Replaces the alg member of a signed body's protected header without re-signing.
func rewriteAlg(t *testing.T, body []byte, alg string) []byte {
	t.Helper()
	var env map[string]string
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	protected, err := base64.RawURLEncoding.DecodeString(env["protected"])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(protected, &header); err != nil {
		t.Fatal(err)
	}
	header["alg"] = alg
	protected, _ = json.Marshal(header)
	env["protected"] = base64.RawURLEncoding.EncodeToString(protected)
	raw, _ := json.Marshal(env)
	return raw
}

// Checks a returned problem's type and status.
func assertProblemType(t *testing.T, p *Problem, typ ErrorType, status int) {
	t.Helper()
	if p == nil {
		t.Fatalf("expected %s problem, got success", typ)
	}
	if p.Type != typ || p.HTTPStatus() != status {
		t.Fatalf("problem = %s %d (%s), want %s %d", p.Type, p.HTTPStatus(), p.Detail, typ, status)
	}
}

// Fails every account operation with a backend error. Other methods are never reached.
type failingStore struct{ Store }

var errBackend = errors.New("backend unavailable")

// Fails.
func (failingStore) CreateAccount(context.Context, *Account) error { return errBackend }

// Fails.
func (failingStore) Account(context.Context, string) (*Account, error) { return nil, errBackend }

// Fails.
func (failingStore) AccountByKey(context.Context, string) (*Account, error) { return nil, errBackend }

// Fails.
func (failingStore) UpdateAccount(context.Context, *Account) error { return errBackend }

// Fails every operation.
type failingNonces struct{}

// Fails.
func (failingNonces) Issue(context.Context) (string, error) { return "", errBackend }

// Fails.
func (failingNonces) Consume(context.Context, string) (bool, error) { return false, errBackend }
