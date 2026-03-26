// Package jws parses and verifies the restricted JWS profile of RFC 8555 section 6.2.
package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
)

// Classifies a rejection so the server can map it to an ACME problem type.
type Code int

// Rejection codes.
const (
	CodeMalformed Code = iota + 1
	CodeBadNonce
	CodeBadSignatureAlgorithm
	CodeBadPublicKey
	CodeBadSignature
)

// Describes why a JWS was rejected.
type Error struct {
	Code   Code
	Detail string
}

// Returns the detail.
func (e *Error) Error() string { return e.Detail }

// Lists the JWS algorithms the server accepts in the order they are advertised.
var Algorithms = []string{"ES256", "ES384", "RS256", "EdDSA"}

// Holds the protected header parameters that ACME requires.
type Header struct {
	Algorithm string
	Nonce     string
	URL       string
	// The account URL when the request is authenticated by an existing account.
	KeyID string
	// The embedded public key when the request carries a jwk parameter.
	Key crypto.PublicKey
}

// A parsed ACME request body.
type Message struct {
	Header Header
	// The decoded payload. It is empty for POST-as-GET requests.
	Payload      []byte
	signingInput []byte
	signature    []byte
}

// The flattened JWS JSON serialization plus the members that must be absent.
type envelopeJSON struct {
	Protected  *string         `json:"protected"`
	Payload    *string         `json:"payload"`
	Signature  *string         `json:"signature"`
	Header     json.RawMessage `json:"header"`
	Signatures json.RawMessage `json:"signatures"`
}

// The protected header with the parameters ACME requires or forbids.
type headerJSON struct {
	Alg   *string         `json:"alg"`
	Nonce *string         `json:"nonce"`
	URL   *string         `json:"url"`
	KID   *string         `json:"kid"`
	JWK   json.RawMessage `json:"jwk"`
	Crit  json.RawMessage `json:"crit"`
	B64   json.RawMessage `json:"b64"`
}

// Decodes a flattened JWS and checks the protected header rules. It does not verify the signature.
func Parse(body []byte) (*Message, error) {
	var env envelopeJSON
	if err := UnmarshalStrict(body, &env); err != nil {
		return nil, malformed("invalid JWS: " + detailOf(err))
	}
	if env.Signatures != nil {
		return nil, malformed("JWS general serialization is not allowed")
	}
	if env.Header != nil {
		return nil, malformed("JWS unprotected header is not allowed")
	}
	if env.Protected == nil || env.Payload == nil || env.Signature == nil {
		return nil, malformed("JWS must have protected, payload and signature members")
	}
	protected, err := decodeBase64(*env.Protected)
	if err != nil || len(protected) == 0 {
		return nil, malformed("JWS protected header is not valid base64url")
	}
	payload, err := decodeBase64(*env.Payload)
	if err != nil {
		return nil, malformed("JWS payload is not valid base64url")
	}
	signature, err := decodeBase64(*env.Signature)
	if err != nil || len(signature) == 0 {
		return nil, malformed("JWS signature is not valid base64url")
	}
	header, err := parseHeader(protected)
	if err != nil {
		return nil, err
	}
	return &Message{
		Header:       header,
		Payload:      payload,
		signingInput: []byte(*env.Protected + "." + *env.Payload),
		signature:    signature,
	}, nil
}

// Decodes the protected header and checks the ACME parameter rules.
func parseHeader(protected []byte) (Header, error) {
	var hdr headerJSON
	if err := UnmarshalStrict(protected, &hdr); err != nil {
		return Header{}, malformed("JWS protected header: " + detailOf(err))
	}
	if hdr.Crit != nil {
		return Header{}, malformed("JWS critical header parameters are not supported")
	}
	if hdr.B64 != nil {
		return Header{}, malformed("JWS b64 header parameter is not supported")
	}
	if hdr.Alg == nil || *hdr.Alg == "" {
		return Header{}, malformed("JWS protected header has no alg")
	}
	if !slices.Contains(Algorithms, *hdr.Alg) {
		return Header{}, &Error{
			Code:   CodeBadSignatureAlgorithm,
			Detail: fmt.Sprintf("JWS algorithm %q is not supported", *hdr.Alg),
		}
	}
	if hdr.URL == nil || *hdr.URL == "" {
		return Header{}, malformed("JWS protected header has no url")
	}
	if hdr.Nonce == nil || *hdr.Nonce == "" {
		return Header{}, &Error{Code: CodeBadNonce, Detail: "JWS protected header has no nonce"}
	}
	if !isBase64URL(*hdr.Nonce) {
		return Header{}, malformed("JWS nonce is not valid base64url")
	}
	hasKID := hdr.KID != nil
	hasJWK := hdr.JWK != nil
	if hasKID == hasJWK {
		return Header{}, malformed("JWS protected header must have exactly one of jwk and kid")
	}
	header := Header{Algorithm: *hdr.Alg, Nonce: *hdr.Nonce, URL: *hdr.URL}
	if hasKID {
		if *hdr.KID == "" {
			return Header{}, malformed("JWS kid is empty")
		}
		header.KeyID = *hdr.KID
		return header, nil
	}
	key, err := ParseJWK(hdr.JWK)
	if err != nil {
		return Header{}, err
	}
	header.Key = key
	return header, nil
}

// Checks the signature with a public key that must match the declared algorithm.
func (m *Message) Verify(key crypto.PublicKey) error {
	return verifySignature(m.Header.Algorithm, key, m.signingInput, m.signature)
}

// Verifies a JWS signature over the signing input with the named algorithm.
func verifySignature(alg string, key crypto.PublicKey, signingInput, signature []byte) error {
	switch alg {
	case "ES256":
		digest := sha256.Sum256(signingInput)
		return verifyECDSA(key, elliptic.P256(), 32, digest[:], signature)
	case "ES384":
		digest := sha512.Sum384(signingInput)
		return verifyECDSA(key, elliptic.P384(), 48, digest[:], signature)
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return keyMismatch(alg)
		}
		digest := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return badSignature()
		}
		return nil
	case "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return keyMismatch(alg)
		}
		if !ed25519.Verify(pub, signingInput, signature) {
			return badSignature()
		}
		return nil
	}
	return &Error{Code: CodeBadSignatureAlgorithm, Detail: fmt.Sprintf("JWS algorithm %q is not supported", alg)}
}

// Verifies a fixed-width R||S signature over a digest.
func verifyECDSA(key crypto.PublicKey, curve elliptic.Curve, size int, digest, signature []byte) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != curve {
		crv, _, _ := curveName(curve)
		return keyMismatch("ES" + crv[2:])
	}
	if len(signature) != 2*size {
		return badSignature()
	}
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !ecdsa.Verify(pub, digest, r, s) {
		return badSignature()
	}
	return nil
}

// Returns a malformed error.
func malformed(detail string) *Error { return &Error{Code: CodeMalformed, Detail: detail} }

// Returns the error for a signature that does not verify.
func badSignature() *Error {
	return &Error{Code: CodeBadSignature, Detail: "JWS signature verification failed"}
}

// Returns the error for a key whose type does not fit the declared algorithm.
func keyMismatch(alg string) *Error {
	return malformed(fmt.Sprintf("JWS key type does not match algorithm %s", alg))
}
