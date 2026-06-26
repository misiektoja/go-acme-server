package jws

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
)

// Bounds on the certificate chain a compact JWS header may carry.
const maxX5CLength = 10

// The protected header parameters of a compact JWS.
type CompactHeader struct {
	Algorithm string
	// The media type, restricted to JWT when present.
	Type string
	// The URL of the signer's certificate, empty when absent.
	X5U string
	// The signer's DER certificate chain, leaf first, empty when absent.
	X5C [][]byte
	// The signer's key identifier, empty when absent.
	KeyID string
}

// A parsed compact JWS.
type CompactMessage struct {
	Header CompactHeader
	// The decoded payload.
	Payload      []byte
	signingInput []byte
	signature    []byte
}

// The protected header members a compact JWS may carry.
type compactHeaderJSON struct {
	Alg  *string         `json:"alg"`
	Typ  *string         `json:"typ"`
	Cty  *string         `json:"cty"`
	X5U  *string         `json:"x5u"`
	X5C  []string        `json:"x5c"`
	KID  *string         `json:"kid"`
	JWK  json.RawMessage `json:"jwk"`
	Crit json.RawMessage `json:"crit"`
	B64  json.RawMessage `json:"b64"`
}

// Decodes a compact JWS of the form protected.payload.signature without verifying its signature.
// It accepts the signature algorithms of Algorithms and rejects an embedded key.
func ParseCompact(token string) (*CompactMessage, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, malformed("compact JWS must have three parts")
	}
	protected, err := decodeBase64(parts[0])
	if err != nil || len(protected) == 0 {
		return nil, malformed("compact JWS protected header is not valid base64url")
	}
	payload, err := decodeBase64(parts[1])
	if err != nil || len(payload) == 0 {
		return nil, malformed("compact JWS payload is not valid base64url")
	}
	signature, err := decodeBase64(parts[2])
	if err != nil || len(signature) == 0 {
		return nil, malformed("compact JWS signature is not valid base64url")
	}
	header, err := parseCompactHeader(protected)
	if err != nil {
		return nil, err
	}
	return &CompactMessage{
		Header:       header,
		Payload:      payload,
		signingInput: []byte(parts[0] + "." + parts[1]),
		signature:    signature,
	}, nil
}

// Decodes the protected header and checks the parameters a token may use.
func parseCompactHeader(protected []byte) (CompactHeader, error) {
	var raw compactHeaderJSON
	if err := UnmarshalStrict(protected, &raw); err != nil {
		return CompactHeader{}, malformed("compact JWS protected header: " + detailOf(err))
	}
	switch {
	case raw.Crit != nil:
		return CompactHeader{}, malformed("compact JWS crit header is not supported")
	case raw.B64 != nil:
		return CompactHeader{}, malformed("compact JWS b64 header is not supported")
	case raw.JWK != nil:
		return CompactHeader{}, malformed("compact JWS must not carry an embedded key")
	case raw.Cty != nil:
		return CompactHeader{}, malformed("compact JWS cty header is not supported")
	case raw.Alg == nil:
		return CompactHeader{}, malformed("compact JWS protected header needs alg")
	case !slices.Contains(Algorithms, *raw.Alg):
		return CompactHeader{}, &Error{Code: CodeBadSignatureAlgorithm,
			Detail: "compact JWS algorithm " + *raw.Alg + " is not supported"}
	}
	header := CompactHeader{Algorithm: *raw.Alg}
	if raw.Typ != nil {
		if !strings.EqualFold(*raw.Typ, "JWT") {
			return CompactHeader{}, malformed("compact JWS typ must be JWT")
		}
		header.Type = *raw.Typ
	}
	if raw.X5U != nil {
		if *raw.X5U == "" {
			return CompactHeader{}, malformed("compact JWS x5u is empty")
		}
		header.X5U = *raw.X5U
	}
	if raw.KID != nil {
		header.KeyID = *raw.KID
	}
	if raw.X5C != nil {
		if len(raw.X5C) == 0 || len(raw.X5C) > maxX5CLength {
			return CompactHeader{}, malformed("compact JWS x5c length is not acceptable")
		}
		for _, encoded := range raw.X5C {
			der, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(der) == 0 {
				return CompactHeader{}, malformed("compact JWS x5c is not valid base64")
			}
			header.X5C = append(header.X5C, der)
		}
	}
	return header, nil
}

// Checks the signature with a public key that must match the declared algorithm.
func (m *CompactMessage) Verify(key crypto.PublicKey) error {
	return verifySignature(m.Header.Algorithm, key, m.signingInput, m.signature)
}
