package jws

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// RFC 7638 section 3.1 RSA key and its thumbprint.
const (
	rfc7638N          = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
)

// RFC 7515 appendix A.3 EC key.
const (
	rfc7515ECX = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	rfc7515ECY = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
)

// RFC 8037 appendix A Ed25519 key and its thumbprint.
const (
	rfc8037X          = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037Thumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
)

func TestParseJWKVectors(t *testing.T) {
	rsaJWK := `{"kty":"RSA","n":"` + rfc7638N + `","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`
	key, err := ParseJWK([]byte(rsaJWK))
	if err != nil {
		t.Fatalf("ParseJWK(rsa): %v", err)
	}
	if _, ok := key.(*rsa.PublicKey); !ok {
		t.Fatalf("ParseJWK(rsa) = %T", key)
	}
	if got := mustThumbprint(t, key); got != rfc7638Thumbprint {
		t.Fatalf("rsa thumbprint = %s", got)
	}

	ecJWK := `{"kty":"EC","crv":"P-256","x":"` + rfc7515ECX + `","y":"` + rfc7515ECY + `"}`
	key, err = ParseJWK([]byte(ecJWK))
	if err != nil {
		t.Fatalf("ParseJWK(ec): %v", err)
	}
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		t.Fatalf("ParseJWK(ec) = %T", key)
	}
	canonical, err := MarshalJWK(key)
	if err != nil {
		t.Fatalf("MarshalJWK(ec): %v", err)
	}
	if want := `{"crv":"P-256","kty":"EC","x":"` + rfc7515ECX + `","y":"` + rfc7515ECY + `"}`; string(canonical) != want {
		t.Fatalf("MarshalJWK(ec) = %s", canonical)
	}

	okpJWK := `{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037X + `"}`
	key, err = ParseJWK([]byte(okpJWK))
	if err != nil {
		t.Fatalf("ParseJWK(okp): %v", err)
	}
	if _, ok := key.(ed25519.PublicKey); !ok {
		t.Fatalf("ParseJWK(okp) = %T", key)
	}
	if got := mustThumbprint(t, key); got != rfc8037Thumbprint {
		t.Fatalf("okp thumbprint = %s", got)
	}
}

func TestThumbprintRSAStripsLeadingZeros(t *testing.T) {
	n, err := base64.RawURLEncoding.DecodeString(rfc7638N)
	if err != nil {
		t.Fatal(err)
	}
	padded := base64.RawURLEncoding.EncodeToString(append([]byte{0}, n...))
	key, err := ParseJWK([]byte(`{"kty":"RSA","n":"` + padded + `","e":"AAEAAQ"}`))
	if err != nil {
		t.Fatalf("ParseJWK(padded): %v", err)
	}
	if got := mustThumbprint(t, key); got != rfc7638Thumbprint {
		t.Fatalf("padded rsa thumbprint = %s, want %s", got, rfc7638Thumbprint)
	}
}

func TestThumbprintECKeepsFixedWidth(t *testing.T) {
	var key *ecdsa.PublicKey
	var point []byte
	for range 4096 {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		point, err = priv.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if point[1] == 0 {
			key = &priv.PublicKey
			break
		}
	}
	if key == nil {
		t.Skip("no P-256 key with a leading zero x coordinate found")
	}
	x, y := point[1:33], point[33:]
	canonical := `{"crv":"P-256","kty":"EC","x":"` + base64.RawURLEncoding.EncodeToString(x) +
		`","y":"` + base64.RawURLEncoding.EncodeToString(y) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := mustThumbprint(t, key); got != want {
		t.Fatalf("thumbprint = %s, want %s", got, want)
	}
	stripped := strings.Replace(canonical, base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(new(big.Int).SetBytes(x).Bytes()), 1)
	strippedSum := sha256.Sum256([]byte(stripped))
	if base64.RawURLEncoding.EncodeToString(strippedSum[:]) == want {
		t.Fatal("stripping the leading zero did not change the thumbprint, the test key is unsuitable")
	}
}

func TestMarshalJWKRoundTrip(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]any{"ec": &ecKey.PublicKey, "rsa": &rsaKey.PublicKey, "okp": edPub} {
		raw, err := MarshalJWK(key)
		if err != nil {
			t.Fatalf("%s: MarshalJWK: %v", name, err)
		}
		parsed, err := ParseJWK(raw)
		if err != nil {
			t.Fatalf("%s: ParseJWK(%s): %v", name, raw, err)
		}
		if mustThumbprint(t, parsed) != mustThumbprint(t, key) {
			t.Fatalf("%s: thumbprint changed across round trip", name)
		}
	}
	if _, err := MarshalJWK("not a key"); err == nil {
		t.Fatal("MarshalJWK(string) succeeded")
	}
}

func TestParseJWKRejects(t *testing.T) {
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallN := base64.RawURLEncoding.EncodeToString(smallRSA.N.Bytes())
	offCurveY := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cases := map[string]string{
		"empty":             ``,
		"not object":        `"EC"`,
		"no kty":            `{"crv":"P-256","x":"` + rfc7515ECX + `","y":"` + rfc7515ECY + `"}`,
		"oct":               `{"kty":"oct","k":"AAAA"}`,
		"private d":         `{"kty":"EC","crv":"P-256","x":"` + rfc7515ECX + `","y":"` + rfc7515ECY + `","d":"AAAA"}`,
		"private rsa p":     `{"kty":"RSA","n":"` + rfc7638N + `","e":"AQAB","p":"AAAA"}`,
		"duplicate member":  `{"kty":"EC","kty":"EC","crv":"P-256","x":"` + rfc7515ECX + `","y":"` + rfc7515ECY + `"}`,
		"unknown curve":     `{"kty":"EC","crv":"secp256k1","x":"` + rfc7515ECX + `","y":"` + rfc7515ECY + `"}`,
		"short coordinate":  `{"kty":"EC","crv":"P-256","x":"` + rfc7515ECX[:40] + `","y":"` + rfc7515ECY + `"}`,
		"wrong curve size":  `{"kty":"EC","crv":"P-384","x":"` + rfc7515ECX + `","y":"` + rfc7515ECY + `"}`,
		"off curve":         `{"kty":"EC","crv":"P-256","x":"` + rfc7515ECX + `","y":"` + offCurveY + `"}`,
		"bad base64":        `{"kty":"EC","crv":"P-256","x":"` + rfc7515ECX + `!","y":"` + rfc7515ECY + `"}`,
		"padded base64":     `{"kty":"EC","crv":"P-256","x":"` + rfc7515ECX + `=","y":"` + rfc7515ECY + `"}`,
		"rsa small":         `{"kty":"RSA","n":"` + smallN + `","e":"AQAB"}`,
		"rsa even exponent": `{"kty":"RSA","n":"` + rfc7638N + `","e":"AQAA"}`,
		"rsa exponent one":  `{"kty":"RSA","n":"` + rfc7638N + `","e":"AQ"}`,
		"rsa huge exponent": `{"kty":"RSA","n":"` + rfc7638N + `","e":"AQAAAAE"}`,
		"rsa missing e":     `{"kty":"RSA","n":"` + rfc7638N + `"}`,
		"rsa missing n":     `{"kty":"RSA","e":"AQAB"}`,
		"okp wrong curve":   `{"kty":"OKP","crv":"Ed448","x":"` + rfc8037X + `"}`,
		"okp short":         `{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037X[:20] + `"}`,
		"unsupported kty":   `{"kty":"PQC","x":"AAAA"}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseJWK([]byte(in))
			var jwsErr *Error
			if !errors.As(err, &jwsErr) || jwsErr.Code != CodeBadPublicKey {
				t.Fatalf("ParseJWK(%s) error = %v, want badPublicKey", in, err)
			}
		})
	}
}

// Returns the thumbprint of key or fails the test.
func mustThumbprint(t *testing.T, key any) string {
	t.Helper()
	got, err := Thumbprint(key)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return got
}
