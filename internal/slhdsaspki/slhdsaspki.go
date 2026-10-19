// Package slhdsaspki encodes SLH-DSA public keys as the SubjectPublicKeyInfo of RFC 9909.
package slhdsaspki

import (
	"encoding/asn1"
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The parameter sets with their RFC 9909 identifiers, which name both the key and its pure
// signature. circl numbers the sets in a different order, so the mapping is explicit.
var algorithms = [...]struct {
	id  slhdsa.ID
	oid asn1.ObjectIdentifier
}{
	{slhdsa.SHA2_128s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}},
	{slhdsa.SHA2_128f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}},
	{slhdsa.SHA2_192s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}},
	{slhdsa.SHA2_192f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}},
	{slhdsa.SHA2_256s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}},
	{slhdsa.SHA2_256f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}},
	{slhdsa.SHAKE_128s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}},
	{slhdsa.SHAKE_128f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}},
	{slhdsa.SHAKE_192s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}},
	{slhdsa.SHAKE_192f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}},
	{slhdsa.SHAKE_256s, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}},
	{slhdsa.SHAKE_256f, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}},
}

// Returns the RFC 9909 identifier of a parameter set.
func OID(id slhdsa.ID) (asn1.ObjectIdentifier, bool) {
	for _, alg := range algorithms {
		if alg.id == id {
			return alg.oid, true
		}
	}
	return nil, false
}

// Returns the parameter set an RFC 9909 identifier names.
func FromOID(oid asn1.ObjectIdentifier) (slhdsa.ID, bool) {
	for _, alg := range algorithms {
		if alg.oid.Equal(oid) {
			return alg.id, true
		}
	}
	return 0, false
}

// Reads an AlgorithmIdentifier and reports whether its parameters are absent, as RFC 9909 requires.
func ReadAlgorithm(s *cryptobyte.String) (asn1.ObjectIdentifier, bool, bool) {
	var alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return nil, false, false
	}
	return oid, alg.Empty(), true
}

// Parses a SubjectPublicKeyInfo and reports whether it holds an SLH-DSA key. A malformed
// SLH-DSA key is an error and any other key is left to the caller.
func Parse(der []byte) (slhdsa.PublicKey, bool, error) {
	s := cryptobyte.String(der)
	var info cryptobyte.String
	if !s.ReadASN1(&info, cbasn1.SEQUENCE) || !s.Empty() {
		return slhdsa.PublicKey{}, false, nil
	}
	oid, absent, ok := ReadAlgorithm(&info)
	id, isSLHDSA := FromOID(oid)
	if !ok || !isSLHDSA {
		return slhdsa.PublicKey{}, false, nil
	}
	var bits asn1.BitString
	if !absent || !info.ReadASN1BitString(&bits) || !info.Empty() || bits.BitLength%8 != 0 {
		return slhdsa.PublicKey{}, true, errors.New("malformed SLH-DSA public key")
	}
	key := slhdsa.PublicKey{ID: id}
	if err := key.UnmarshalBinary(bits.Bytes); err != nil {
		return slhdsa.PublicKey{}, true, errors.New("malformed SLH-DSA public key")
	}
	return key, true, nil
}

// Encodes an SLH-DSA key as a SubjectPublicKeyInfo with absent parameters.
func Marshal(key slhdsa.PublicKey) ([]byte, error) {
	oid, ok := OID(key.ID)
	if !ok {
		return nil, errors.New("unknown SLH-DSA parameter set")
	}
	raw, err := key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
		})
		b.AddASN1BitString(raw)
	})
	return b.Bytes()
}
