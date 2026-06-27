package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// Returns a fresh P-256 signer for the compact JWS tests.
func newCompactKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return key
}

// Signs a compact JWS with the header and payload.
func signCompact(tb testing.TB, key crypto.Signer, header map[string]any, payload []byte) string {
	tb.Helper()
	var env struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(sign(tb, key, algES256, header, payload), &env); err != nil {
		tb.Fatal(err)
	}
	return env.Protected + "." + env.Payload + "." + env.Signature
}

func TestParseCompactAndVerify(t *testing.T) {
	key := newCompactKey(t)
	header := map[string]any{"typ": "JWT", "alg": algES256, "x5u": "https://authority.example.test/cert",
		"kid": "authority-1"}
	token := signCompact(t, key, header, []byte(`{"jti":"id1"}`))
	message, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if message.Header.Algorithm != algES256 || message.Header.Type != "JWT" ||
		message.Header.X5U != "https://authority.example.test/cert" || message.Header.KeyID != "authority-1" {
		t.Fatalf("header = %+v", message.Header)
	}
	if string(message.Payload) != `{"jti":"id1"}` {
		t.Fatalf("payload = %s", message.Payload)
	}
	if err := message.Verify(key.Public()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	other := newCompactKey(t)
	if err := message.Verify(other.Public()); !isCode(err, CodeBadSignature) {
		t.Fatalf("Verify with another key = %v", err)
	}
}

func TestParseCompactChain(t *testing.T) {
	key := newCompactKey(t)
	leaf := []byte{0x30, 0x01, 0x02}
	header := map[string]any{"alg": algES256, "x5c": []string{base64.StdEncoding.EncodeToString(leaf)}}
	message, err := ParseCompact(signCompact(t, key, header, []byte("{}")))
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if len(message.Header.X5C) != 1 || string(message.Header.X5C[0]) != string(leaf) {
		t.Fatalf("x5c = %v", message.Header.X5C)
	}
}

func TestParseCompactRejects(t *testing.T) {
	key := newCompactKey(t)
	valid := signCompact(t, key, map[string]any{"alg": algES256}, []byte("{}"))
	parts := strings.Split(valid, ".")
	cases := map[string]string{
		"two parts":         parts[0] + "." + parts[1],
		"four parts":        valid + "." + parts[2],
		"empty header":      "." + parts[1] + "." + parts[2],
		"empty payload":     parts[0] + ".." + parts[2],
		"empty signature":   parts[0] + "." + parts[1] + ".",
		"padded header":     parts[0] + "=." + parts[1] + "." + parts[2],
		"header not base64": "not base64!" + "." + parts[1] + "." + parts[2],
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCompact(token); !isTyped(err) {
				t.Fatalf("ParseCompact = %v", err)
			}
		})
	}
	headers := map[string]map[string]any{
		"no alg":        {"typ": "JWT"},
		"none alg":      {"alg": "none"},
		"HMAC alg":      {"alg": "HS256"},
		"other typ":     {"alg": algES256, "typ": "JOSE"},
		"embedded key":  {"alg": algES256, "jwk": map[string]any{"kty": "EC"}},
		"crit":          {"alg": algES256, "crit": []string{"exp"}},
		"detached":      {"alg": algES256, "b64": false},
		"content type":  {"alg": algES256, "cty": "json"},
		"empty x5u":     {"alg": algES256, "x5u": ""},
		"empty x5c":     {"alg": algES256, "x5c": []string{}},
		"bad x5c":       {"alg": algES256, "x5c": []string{"not base64!"}},
		"unpadded x5c":  {"alg": algES256, "x5c": []string{"MAEC"[:3]}},
		"duplicate key": nil,
	}
	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			var token string
			if header != nil {
				token = signCompact(t, key, header, []byte("{}"))
			} else {
				protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","alg":"ES256"}`))
				token = protected + "." + parts[1] + "." + parts[2]
			}
			if _, err := ParseCompact(token); !isTyped(err) {
				t.Fatalf("ParseCompact = %v", err)
			}
		})
	}
}

func FuzzParseCompact(f *testing.F) {
	key := newCompactKey(f)
	f.Add(signCompact(f, key, map[string]any{"alg": algES256, "typ": "JWT"}, []byte(`{"jti":"id1"}`)))
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		message, err := ParseCompact(token)
		if err != nil {
			if !isTyped(err) {
				t.Fatalf("ParseCompact returned %v", err)
			}
			return
		}
		if !slices.Contains(Algorithms, message.Header.Algorithm) || len(message.Payload) == 0 {
			t.Fatalf("accepted header %+v", message.Header)
		}
		if len(message.Header.X5C) > maxX5CLength {
			t.Fatalf("accepted %d chain elements", len(message.Header.X5C))
		}
	})
}
