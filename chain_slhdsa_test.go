package acmeserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"

	"github.com/misiektoja/go-acme-server/internal/slhdsaspki"
	"github.com/misiektoja/go-acme-server/internal/slhdsatest"
)

// Accepts chains signed with SLH-DSA CA keys, also mixed with ECDSA, and rejects links that do not verify.
func TestChainChecksSLHDSASignatures(t *testing.T) {
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
	generate := func(id slhdsa.ID) (slhdsa.PrivateKey, []byte) {
		_, private, err := slhdsa.GenerateKey(rand.Reader, id)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := slhdsaspki.Marshal(private.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		return private, spki
	}
	// Issues a certificate for spki signed by the SLH-DSA key signer under parent, or self-signed when parent is nil.
	issue := func(tmpl *x509.Certificate, spki []byte, parent *x509.Certificate, signer slhdsa.PrivateKey) []byte {
		if parent == nil {
			parent = tmpl
		}
		der, err := slhdsatest.CreateCertificateSignedBy(tmpl, parent, spki, signer)
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
	leafSPKI, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	rootKey, rootSPKI := generate(slhdsa.SHA2_128f)
	rootDER := issue(ca("SLH-DSA root", true), rootSPKI, nil, rootKey)
	root := parse(rootDER)
	otherKey, otherSPKI := generate(slhdsa.SHA2_128f)
	impostor := parse(issue(ca("SLH-DSA root", true), otherSPKI, nil, otherKey))
	notCAKey, notCASPKI := generate(slhdsa.SHAKE_128f)
	notCADER := issue(ca("SLH-DSA root", false), notCASPKI, nil, notCAKey)
	noCertSignKey, noCertSignSPKI := generate(slhdsa.SHAKE_128f)
	noCertSign := ca("SLH-DSA root", true)
	noCertSign.KeyUsage = x509.KeyUsageDigitalSignature
	noCertSignDER := issue(noCertSign, noCertSignSPKI, nil, noCertSignKey)

	// An ECDSA root certifies an SLH-DSA intermediate, which signs the leaf.
	ecRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecRootDER, err := x509.CreateCertificate(rand.Reader, ca("ECDSA root", true), ca("ECDSA root", true), &ecRootKey.PublicKey, ecRootKey)
	if err != nil {
		t.Fatal(err)
	}
	interKey, interSPKI := generate(slhdsa.SHAKE_128f)
	interDER, err := slhdsatest.CreateCertificate(ca("SLH-DSA intermediate", true), parse(ecRootDER), interSPKI, ecRootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter := parse(interDER)

	tampered := issue(leaf, leafSPKI, root, rootKey)
	tampered[len(tampered)-1] ^= 1
	for _, test := range []struct {
		name  string
		chain [][]byte
		valid bool
	}{
		{"SLH-DSA root", [][]byte{issue(leaf, leafSPKI, root, rootKey), rootDER}, true},
		{"SLH-DSA intermediate under ECDSA root", [][]byte{issue(leaf, leafSPKI, inter, interKey), interDER, ecRootDER}, true},
		{"leaf only", [][]byte{issue(leaf, leafSPKI, root, rootKey)}, true},
		{"other key under the root name", [][]byte{issue(leaf, leafSPKI, impostor, otherKey), rootDER}, false},
		{"tampered signature", [][]byte{tampered, rootDER}, false},
		{"issuer is not a CA", [][]byte{issue(leaf, leafSPKI, parse(notCADER), notCAKey), notCADER}, false},
		{"issuer may not sign certificates", [][]byte{issue(leaf, leafSPKI, parse(noCertSignDER), noCertSignKey), noCertSignDER}, false},
		{"intermediate out of order", [][]byte{issue(leaf, leafSPKI, inter, interKey), ecRootDER, interDER}, false},
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
