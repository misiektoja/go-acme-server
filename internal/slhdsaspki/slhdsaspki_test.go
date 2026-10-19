package slhdsaspki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Checks that Parse accepts only the exact encoding of an SLH-DSA key, refuses every other
// SubjectPublicKeyInfo that names an SLH-DSA set and leaves the rest to the caller.
func FuzzParse(f *testing.F) {
	// Any 2n bytes form a public key, so random keys in every set seed the target without the cost
	// of SLH-DSA key generation.
	for _, alg := range algorithms {
		raw := make([]byte, alg.id.Scheme().PublicKeySize())
		if _, err := rand.Read(raw); err != nil {
			f.Fatal(err)
		}
		key := slhdsa.PublicKey{ID: alg.id}
		if err := key.UnmarshalBinary(raw); err != nil {
			f.Fatal(err)
		}
		spki, err := Marshal(key)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(spki)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	classical, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(classical)
	f.Add([]byte{0x30, 0x00})
	// The SLH-DSA-SHA2-128s identifier followed by truncated parameters still names an SLH-DSA key.
	f.Add([]byte("000 \x06\t`\x86H\x01e\x03\x04\x03\x1400000000000000000000000000000000000"))
	f.Fuzz(func(t *testing.T, der []byte) {
		key, isSLHDSA, err := Parse(der)
		if want := namesSLHDSA(der); isSLHDSA != want {
			t.Fatalf("Parse reports SLH-DSA = %v, encoding/asn1 reads %v", isSLHDSA, want)
		}
		if !isSLHDSA {
			if err != nil || key.ID != 0 {
				t.Fatalf("Parse returned %v and a key for another algorithm: %v", key.ID, err)
			}
			return
		}
		if err != nil {
			return
		}
		again, err := Marshal(key)
		if err != nil || !bytes.Equal(again, der) {
			t.Fatalf("accepted a key that encodes as %x, %v", again, err)
		}
	})
}

// Reports with encoding/asn1 whether der is one SEQUENCE whose algorithm identifier starts with
// an SLH-DSA identifier. Whatever follows that identifier does not change the key type.
func namesSLHDSA(der []byte) bool {
	var info struct{ Algorithm asn1.RawValue }
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 || info.Algorithm.Class != asn1.ClassUniversal ||
		info.Algorithm.Tag != asn1.TagSequence || !info.Algorithm.IsCompound {
		return false
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info.Algorithm.Bytes, &oid); err != nil {
		return false
	}
	_, ok := FromOID(oid)
	return ok
}
