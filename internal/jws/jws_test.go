package jws

import (
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
	"strings"
	"testing"
)

// Signing inputs and signatures from RFC 7515 appendix A and RFC 8037 appendix A.
const (
	rfc7515Payload  = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	rfc7515RS256Sig = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
	rfc7515RSAN     = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
	rfc7515ES256Sig = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	rfc7515RS256In  = "eyJhbGciOiJSUzI1NiJ9." + rfc7515Payload
	rfc7515ES256In  = "eyJhbGciOiJFUzI1NiJ9." + rfc7515Payload
	rfc8037Input    = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	rfc8037Sig      = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func TestVerifySignatureVectors(t *testing.T) {
	rsaKey, err := ParseJWK([]byte(`{"kty":"RSA","n":"` + rfc7515RSAN + `","e":"AQAB"}`))
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-256","x":"` + rfc7515ECX + `","y":"` + rfc7515ECY + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	edKey, err := ParseJWK([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037X + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		alg   string
		key   crypto.PublicKey
		input string
		sig   string
	}{
		{"RS256", rsaKey, rfc7515RS256In, rfc7515RS256Sig},
		{"ES256", ecKey, rfc7515ES256In, rfc7515ES256Sig},
		{"EdDSA", edKey, rfc8037Input, rfc8037Sig},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			sig := decode(t, tc.sig)
			if err := verifySignature(tc.alg, tc.key, []byte(tc.input), sig); err != nil {
				t.Fatalf("verifySignature: %v", err)
			}
			tampered := []byte(tc.input + "x")
			if !isCode(verifySignature(tc.alg, tc.key, tampered, sig), CodeBadSignature) {
				t.Fatal("tampered input verified")
			}
			sig[len(sig)-1] ^= 1
			if !isCode(verifySignature(tc.alg, tc.key, []byte(tc.input), sig), CodeBadSignature) {
				t.Fatal("tampered signature verified")
			}
		})
	}
	if !isCode(verifySignature("ES256", rsaKey, []byte("x"), make([]byte, 64)), CodeMalformed) {
		t.Fatal("RSA key accepted for ES256")
	}
	if !isCode(verifySignature("RS256", ecKey, []byte("x"), make([]byte, 256)), CodeMalformed) {
		t.Fatal("EC key accepted for RS256")
	}
	if !isCode(verifySignature("EdDSA", ecKey, []byte("x"), make([]byte, 64)), CodeMalformed) {
		t.Fatal("EC key accepted for EdDSA")
	}
	if !isCode(verifySignature("ES256", ecKey, []byte("x"), make([]byte, 63)), CodeBadSignature) {
		t.Fatal("short ECDSA signature accepted")
	}
	if !isCode(verifySignature("HS256", ecKey, []byte("x"), make([]byte, 32)), CodeBadSignatureAlgorithm) {
		t.Fatal("HS256 accepted")
	}
}

func TestParseAndVerifyAllAlgorithms(t *testing.T) {
	es256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	es384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rs256, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		alg  string
		priv crypto.Signer
		pub  crypto.PublicKey
	}{
		{"ES256", es256, &es256.PublicKey},
		{"ES384", es384, &es384.PublicKey},
		{"RS256", rs256, &rs256.PublicKey},
		{"EdDSA", edPriv, edPub},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			header := map[string]any{"alg": tc.alg, "nonce": "bm9uY2U", "url": "https://acme.test/acme/new-account"}
			header["jwk"] = json.RawMessage(mustMarshalJWK(t, tc.pub))
			body := sign(t, tc.priv, tc.alg, header, []byte(`{"termsOfServiceAgreed":true}`))
			msg, err := Parse(body)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if msg.Header.Algorithm != tc.alg || msg.Header.Nonce != "bm9uY2U" || msg.Header.KeyID != "" || msg.Header.Key == nil {
				t.Fatalf("header = %+v", msg.Header)
			}
			if string(msg.Payload) != `{"termsOfServiceAgreed":true}` {
				t.Fatalf("payload = %s", msg.Payload)
			}
			if err := msg.Verify(msg.Header.Key); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if tc.alg == "ES256" && !isCode(msg.Verify(&other.PublicKey), CodeBadSignature) {
				t.Fatal("wrong key verified")
			}
		})
	}
}

func TestParseKeyIDAndEmptyPayload(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	header := map[string]any{"alg": "ES256", "nonce": "bm9uY2U", "url": "https://acme.test/acme/acct/1", "kid": "https://acme.test/acme/acct/1"}
	msg, err := Parse(sign(t, priv, "ES256", header, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Header.KeyID != "https://acme.test/acme/acct/1" || msg.Header.Key != nil {
		t.Fatalf("header = %+v", msg.Header)
	}
	if len(msg.Payload) != 0 {
		t.Fatalf("payload = %q, want empty", msg.Payload)
	}
	if err := msg.Verify(&priv.PublicKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	msg, err = Parse(sign(t, priv, "ES256", header, []byte("{}")))
	if err != nil || string(msg.Payload) != "{}" {
		t.Fatalf("Parse({}) = %v, %v", msg, err)
	}
}

func TestParseRejects(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := json.RawMessage(mustMarshalJWK(t, &priv.PublicKey))
	base := func() map[string]any {
		return map[string]any{"alg": "ES256", "nonce": "bm9uY2U", "url": "https://acme.test/acme/new-account", "jwk": jwk}
	}
	valid := sign(t, priv, "ES256", base(), []byte("{}"))
	var env map[string]string
	if err := json.Unmarshal(valid, &env); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		body []byte
		code Code
	}{
		{"not json", []byte("nope"), CodeMalformed},
		{"array", []byte("[]"), CodeMalformed},
		{"general serialization", []byte(`{"payload":"e30","signatures":[]}`), CodeMalformed},
		{"unprotected header", mutate(t, env, func(m map[string]any) { m["header"] = map[string]any{"kid": "x"} }), CodeMalformed},
		{"missing protected", mutate(t, env, func(m map[string]any) { delete(m, "protected") }), CodeMalformed},
		{"missing payload", mutate(t, env, func(m map[string]any) { delete(m, "payload") }), CodeMalformed},
		{"missing signature", mutate(t, env, func(m map[string]any) { delete(m, "signature") }), CodeMalformed},
		{"empty signature", mutate(t, env, func(m map[string]any) { m["signature"] = "" }), CodeMalformed},
		{"padded protected", mutate(t, env, func(m map[string]any) { m["protected"] = env["protected"] + "=" }), CodeMalformed},
		{"newline in payload", mutate(t, env, func(m map[string]any) { m["payload"] = "e3\n0" }), CodeMalformed},
		{"standard base64", mutate(t, env, func(m map[string]any) { m["signature"] = "ab+/" }), CodeMalformed},
		{"protected not object", mutate(t, env, func(m map[string]any) { m["protected"] = b64(`"x"`) }), CodeMalformed},
		{"protected empty", mutate(t, env, func(m map[string]any) { m["protected"] = "" }), CodeMalformed},
		{"duplicate header member", mutate(t, env, func(m map[string]any) {
			m["protected"] = b64(`{"alg":"ES256","alg":"ES256","nonce":"bm9uY2U","url":"u","kid":"k"}`)
		}), CodeMalformed},
		{"missing alg", withHeader(t, priv, base(), func(h map[string]any) { delete(h, "alg") }), CodeMalformed},
		{"alg none", withHeader(t, priv, base(), func(h map[string]any) { h["alg"] = "none" }), CodeBadSignatureAlgorithm},
		{"alg HS256", withHeader(t, priv, base(), func(h map[string]any) { h["alg"] = "HS256" }), CodeBadSignatureAlgorithm},
		{"alg PS256", withHeader(t, priv, base(), func(h map[string]any) { h["alg"] = "PS256" }), CodeBadSignatureAlgorithm},
		{"alg lowercase", withHeader(t, priv, base(), func(h map[string]any) { h["alg"] = "es256" }), CodeBadSignatureAlgorithm},
		{"missing nonce", withHeader(t, priv, base(), func(h map[string]any) { delete(h, "nonce") }), CodeBadNonce},
		{"empty nonce", withHeader(t, priv, base(), func(h map[string]any) { h["nonce"] = "" }), CodeBadNonce},
		{"nonce not base64url", withHeader(t, priv, base(), func(h map[string]any) { h["nonce"] = "a+b" }), CodeMalformed},
		{"missing url", withHeader(t, priv, base(), func(h map[string]any) { delete(h, "url") }), CodeMalformed},
		{"jwk and kid", withHeader(t, priv, base(), func(h map[string]any) { h["kid"] = "k" }), CodeMalformed},
		{"neither jwk nor kid", withHeader(t, priv, base(), func(h map[string]any) { delete(h, "jwk") }), CodeMalformed},
		{"empty kid", withHeader(t, priv, base(), func(h map[string]any) { delete(h, "jwk"); h["kid"] = "" }), CodeMalformed},
		{"crit", withHeader(t, priv, base(), func(h map[string]any) { h["crit"] = []string{"exp"} }), CodeMalformed},
		{"empty crit", withHeader(t, priv, base(), func(h map[string]any) { h["crit"] = []string{} }), CodeMalformed},
		{"b64 false", withHeader(t, priv, base(), func(h map[string]any) { h["b64"] = false; h["crit"] = []string{"b64"} }), CodeMalformed},
		{"b64 true", withHeader(t, priv, base(), func(h map[string]any) { h["b64"] = true }), CodeMalformed},
		{"bad jwk", withHeader(t, priv, base(), func(h map[string]any) { h["jwk"] = map[string]any{"kty": "oct", "k": "AAAA"} }), CodeBadPublicKey},
		{"private jwk", withHeader(t, priv, base(), func(h map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": rfc7515ECX, "y": rfc7515ECY, "d": "AAAA"}
		}), CodeBadPublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.body)
			if !isCode(err, tc.code) {
				t.Fatalf("Parse error = %v, want code %d", err, tc.code)
			}
		})
	}
}

func TestParseIgnoresUnknownMembers(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	header := map[string]any{"alg": "ES256", "nonce": "bm9uY2U", "url": "u", "kid": "k", "typ": "JOSE+JSON", "x-extra": 1}
	body := sign(t, priv, "ES256", header, nil)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	env["extra"] = "ignored"
	raw, _ := json.Marshal(env)
	msg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := msg.Verify(&priv.PublicKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	header := map[string]any{"alg": "ES256", "nonce": "bm9uY2U", "url": "u", "jwk": json.RawMessage(mustMarshalJWK(f, &priv.PublicKey))}
	f.Add(sign(f, priv, "ES256", header, []byte("{}")))
	f.Add([]byte(`{"protected":"","payload":"","signature":""}`))
	f.Add([]byte(`{"protected":"e30","payload":"e30","signature":"AA"}`))
	f.Add([]byte(`{"signatures":[]}`))
	f.Add([]byte(strings.Repeat("[", 100)))
	f.Fuzz(func(t *testing.T, body []byte) {
		msg, err := Parse(body)
		if err != nil {
			var jwsErr *Error
			if !errors.As(err, &jwsErr) || jwsErr.Code == 0 {
				t.Fatalf("Parse returned an untyped error: %v", err)
			}
			return
		}
		if msg.Header.Algorithm == "" || msg.Header.URL == "" || msg.Header.Nonce == "" {
			t.Fatalf("Parse accepted an incomplete header: %+v", msg.Header)
		}
		if (msg.Header.KeyID == "") == (msg.Header.Key == nil) {
			t.Fatalf("Parse accepted a header without exactly one key reference: %+v", msg.Header)
		}
		if msg.Header.Key != nil {
			_ = msg.Verify(msg.Header.Key)
		}
	})
}

// Builds a flattened JWS over the header and payload with the given signer.
func sign(tb testing.TB, key crypto.Signer, alg string, header map[string]any, payload []byte) []byte {
	tb.Helper()
	protected, err := json.Marshal(header)
	if err != nil {
		tb.Fatal(err)
	}
	p := base64.RawURLEncoding.EncodeToString(protected)
	pl := base64.RawURLEncoding.EncodeToString(payload)
	input := []byte(p + "." + pl)
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		var digest []byte
		if alg == "ES384" {
			d := sha512.Sum384(input)
			digest = d[:]
		} else {
			d := sha256.Sum256(input)
			digest = d[:]
		}
		der, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			tb.Fatal(err)
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &rs); err != nil {
			tb.Fatal(err)
		}
		sig = make([]byte, 2*size)
		rs.R.FillBytes(sig[:size])
		rs.S.FillBytes(sig[size:])
	case *rsa.PrivateKey:
		d := sha256.Sum256(input)
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		if err != nil {
			tb.Fatal(err)
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, input)
	default:
		tb.Fatalf("unsupported signer %T", key)
	}
	body, err := json.Marshal(map[string]string{"protected": p, "payload": pl, "signature": base64.RawURLEncoding.EncodeToString(sig)})
	if err != nil {
		tb.Fatal(err)
	}
	return body
}

// Signs with a header modified by fn.
func withHeader(t *testing.T, key crypto.Signer, header map[string]any, fn func(map[string]any)) []byte {
	t.Helper()
	fn(header)
	return sign(t, key, "ES256", header, []byte("{}"))
}

// Re-encodes a valid envelope after fn changed it.
func mutate(t *testing.T, env map[string]string, fn func(map[string]any)) []byte {
	t.Helper()
	m := make(map[string]any, len(env))
	for k, v := range env {
		m[k] = v
	}
	fn(m)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Returns the canonical JWK of key or fails.
func mustMarshalJWK(tb testing.TB, key crypto.PublicKey) []byte {
	tb.Helper()
	raw, err := MarshalJWK(key)
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// Encodes a string as unpadded base64url.
func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// Decodes unpadded base64url or fails.
func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Reports whether err is a *Error with the given code.
func isCode(err error, code Code) bool {
	var jwsErr *Error
	return errors.As(err, &jwsErr) && jwsErr.Code == code
}
