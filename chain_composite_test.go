package acmeserver

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

// Accepts chains signed with composite ML-DSA CA keys and rejects links that do not verify.
func TestChainChecksCompositeSignatures(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key := newSigner(t, "ES256").key
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"a.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	generate := func(alg compositemldsa.Algorithm) crypto.Signer {
		k, err := compositemldsa.GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	// Issues a certificate for pub signed by signer under parent, or self-signed when parent is nil.
	issue := func(tmpl *x509.Certificate, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) []byte {
		if parent == nil {
			parent = tmpl
		}
		der, err := compositex509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	ca := func(name string, isCA bool) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: isCA, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
	}
	parse := func(der []byte) *x509.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"a.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour)}

	rootKey := generate(compositemldsa.MLDSA65ECDSAP256SHA512)
	rootDER := issue(ca("composite root", true), rootKey.Public(), nil, rootKey)
	root := parse(rootDER)
	interKey := generate(compositemldsa.MLDSA44ECDSAP256SHA256)
	interDER := issue(ca("composite intermediate", true), interKey.Public(), root, rootKey)
	inter := parse(interDER)
	otherKey := generate(compositemldsa.MLDSA65ECDSAP256SHA512)
	impostor := parse(issue(ca("composite root", true), otherKey.Public(), nil, otherKey))
	notCAKey := generate(compositemldsa.MLDSA65ECDSAP256SHA512)
	notCADER := issue(ca("composite root", false), notCAKey.Public(), nil, notCAKey)

	tampered := issue(leaf, key.Public(), root, rootKey)
	tampered[len(tampered)-1] ^= 1
	for _, test := range []struct {
		name  string
		chain [][]byte
		valid bool
	}{
		{"composite root", [][]byte{issue(leaf, key.Public(), root, rootKey), rootDER}, true},
		{"composite intermediate", [][]byte{issue(leaf, key.Public(), inter, interKey), interDER, rootDER}, true},
		{"leaf only", [][]byte{issue(leaf, key.Public(), root, rootKey)}, true},
		{"other key under the root name", [][]byte{issue(leaf, key.Public(), impostor, otherKey), rootDER}, false},
		{"tampered signature", [][]byte{tampered, rootDER}, false},
		{"issuer is not a CA", [][]byte{issue(leaf, key.Public(), parse(notCADER), notCAKey), notCADER}, false},
		{"intermediate out of order", [][]byte{issue(leaf, key.Public(), inter, interKey), rootDER, interDER}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			order := &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "a.test"}}}
			_, err := checkChain(test.chain, csr, order, now)
			if (err == nil) != test.valid {
				t.Fatalf("checkChain = %v, valid = %v", err, test.valid)
			}
		})
	}
}
