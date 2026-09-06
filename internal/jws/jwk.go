package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// RSA modulus sizes accepted for account keys, in bits.
const (
	MinRSABits = 2048
	MaxRSABits = 4096
)

// The largest public exponent the Go RSA implementation verifies with.
const maxRSAExponent = 1<<31 - 1

// Holds every RFC 7517 and RFC 7518 member that decides whether a key is acceptable.
type jwkJSON struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
	// Private members. Any of them present rejects the key.
	D   *json.RawMessage `json:"d"`
	P   *json.RawMessage `json:"p"`
	Q   *json.RawMessage `json:"q"`
	DP  *json.RawMessage `json:"dp"`
	DQ  *json.RawMessage `json:"dq"`
	QI  *json.RawMessage `json:"qi"`
	Oth *json.RawMessage `json:"oth"`
	K   *json.RawMessage `json:"k"`
}

// Parses a public JWK into a Go public key. It accepts P-256, P-384 and P-521 EC keys,
// RSA keys of MinRSABits to MaxRSABits and Ed25519 keys.
func ParseJWK(raw []byte) (crypto.PublicKey, error) {
	var k jwkJSON
	if err := UnmarshalStrict(raw, &k); err != nil {
		return nil, badKey("invalid JWK: " + detailOf(err))
	}
	if k.D != nil || k.P != nil || k.Q != nil || k.DP != nil || k.DQ != nil || k.QI != nil || k.Oth != nil || k.K != nil {
		return nil, badKey("JWK contains private key material")
	}
	switch k.Kty {
	case "EC":
		return parseECKey(k)
	case "RSA":
		return parseRSAKey(k)
	case "OKP":
		return parseOKPKey(k)
	case "":
		return nil, badKey("JWK has no key type")
	}
	return nil, badKey(fmt.Sprintf("unsupported JWK key type %q", k.Kty))
}

// Decodes an EC JWK and checks that the point lies on the named curve.
func parseECKey(k jwkJSON) (crypto.PublicKey, error) {
	var curve elliptic.Curve
	var size int
	switch k.Crv {
	case "P-256":
		curve, size = elliptic.P256(), 32
	case "P-384":
		curve, size = elliptic.P384(), 48
	case "P-521":
		curve, size = elliptic.P521(), 66
	default:
		return nil, badKey(fmt.Sprintf("unsupported EC curve %q", k.Crv))
	}
	x, err := decodeBase64(k.X)
	if err != nil {
		return nil, badKey("EC x coordinate is not valid base64url")
	}
	y, err := decodeBase64(k.Y)
	if err != nil {
		return nil, badKey("EC y coordinate is not valid base64url")
	}
	if len(x) != size || len(y) != size {
		return nil, badKey(fmt.Sprintf("EC coordinates on %s must be %d bytes", k.Crv, size))
	}
	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1:], x)
	copy(point[1+size:], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, badKey("EC point is not on the curve")
	}
	return pub, nil
}

// Decodes an RSA JWK and enforces the modulus and exponent bounds.
func parseRSAKey(k jwkJSON) (crypto.PublicKey, error) {
	n, err := decodeBase64(k.N)
	if err != nil || len(n) == 0 {
		return nil, badKey("RSA modulus is missing or not valid base64url")
	}
	e, err := decodeBase64(k.E)
	if err != nil || len(e) == 0 {
		return nil, badKey("RSA exponent is missing or not valid base64url")
	}
	exponent := new(big.Int).SetBytes(e)
	if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > maxRSAExponent || exponent.Bit(0) == 0 {
		return nil, badKey("RSA public exponent must be odd and between 3 and 2^31-1")
	}
	modulus := new(big.Int).SetBytes(n)
	if bits := modulus.BitLen(); bits < MinRSABits || bits > MaxRSABits {
		return nil, badKey(fmt.Sprintf("RSA modulus must be between %d and %d bits, got %d", MinRSABits, MaxRSABits, bits))
	}
	if modulus.Bit(0) == 0 {
		return nil, badKey("RSA modulus must be odd")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

// Decodes an Ed25519 JWK.
func parseOKPKey(k jwkJSON) (crypto.PublicKey, error) {
	if k.Crv != "Ed25519" {
		return nil, badKey(fmt.Sprintf("unsupported OKP curve %q", k.Crv))
	}
	x, err := decodeBase64(k.X)
	if err != nil {
		return nil, badKey("OKP x coordinate is not valid base64url")
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, badKey(fmt.Sprintf("Ed25519 public key must be %d bytes", ed25519.PublicKeySize))
	}
	return ed25519.PublicKey(x), nil
}

// Returns the base64url RFC 7638 SHA-256 thumbprint of a public key.
func Thumbprint(key crypto.PublicKey) (string, error) {
	canonical, err := MarshalJWK(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Encodes a public key as the RFC 7638 canonical JWK. RSA integers drop leading zero octets
// and EC coordinates keep the fixed width of their curve, as RFC 8555 erratum 7565 requires.
func MarshalJWK(key crypto.PublicKey) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		crv, size, ok := curveName(k.Curve)
		if !ok {
			return nil, errors.New("jws: unsupported EC curve")
		}
		point, err := k.Bytes()
		if err != nil {
			return nil, fmt.Errorf("jws: %w", err)
		}
		if len(point) != 1+2*size || point[0] != 4 {
			return nil, errors.New("jws: EC public key is not an uncompressed point")
		}
		x, y := point[1:1+size], point[1+size:]
		return fmt.Appendf(nil, `{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, encodeBase64(x), encodeBase64(y)), nil
	case *rsa.PublicKey:
		if k.N == nil || k.N.Sign() <= 0 || k.E <= 0 {
			return nil, errors.New("jws: invalid RSA public key")
		}
		e := big.NewInt(int64(k.E)).Bytes()
		return fmt.Appendf(nil, `{"e":%q,"kty":"RSA","n":%q}`, encodeBase64(e), encodeBase64(k.N.Bytes())), nil
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, errors.New("jws: invalid Ed25519 public key")
		}
		return fmt.Appendf(nil, `{"crv":"Ed25519","kty":"OKP","x":%q}`, encodeBase64(k)), nil
	}
	return nil, fmt.Errorf("jws: unsupported public key type %T", key)
}

// Returns the JWA name and coordinate size of a supported curve.
func curveName(curve elliptic.Curve) (string, int, bool) {
	switch curve {
	case elliptic.P256():
		return "P-256", 32, true
	case elliptic.P384():
		return "P-384", 48, true
	case elliptic.P521():
		return "P-521", 66, true
	}
	return "", 0, false
}

// Returns a badPublicKey error.
func badKey(detail string) *Error { return &Error{Code: CodeBadPublicKey, Detail: detail} }

// Returns the detail of a *Error or the message of any other error.
func detailOf(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Detail
	}
	return err.Error()
}

// Decodes unpadded base64url and rejects every character outside its alphabet.
func decodeBase64(s string) ([]byte, error) {
	if !isBase64URL(s) {
		return nil, errors.New("invalid base64url character")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// Encodes bytes as unpadded base64url.
func encodeBase64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Reports whether s uses only the unpadded base64url alphabet.
func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
