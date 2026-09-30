package acmeserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

// Verifies composite ML-DSA proofs of both components and the usual identifier checks.
func TestCompositeCSR(t *testing.T) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{Key: accountKey.Public()}
	order := &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "composite.example.test"}}}
	for _, alg := range []compositemldsa.Algorithm{
		compositemldsa.MLDSA44RSA2048PSSSHA256,
		compositemldsa.MLDSA65ECDSAP256SHA512,
		compositemldsa.MLDSA87ECDSAP521SHA512,
	} {
		t.Run(alg.String(), func(t *testing.T) {
			key, err := compositemldsa.GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			der, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"composite.example.test"}}, key)
			if err != nil {
				t.Fatal(err)
			}
			csr, problem := checkCSR(der, order, account)
			if problem != nil {
				t.Fatal(problem)
			}
			if string(csr.Raw) != string(der) {
				t.Fatal("accepted CSR differs from the submitted one")
			}
			if _, problem := checkCSR(der, &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "other.example.test"}}}, account); problem == nil {
				t.Fatal("mismatched identity accepted")
			}

			// The signature BIT STRING ends the request. Its last byte belongs to the traditional
			// component and its first bytes to ML-DSA, so both halves are checked.
			parsed, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatal(err)
			}
			for name, offset := range map[string]int{"traditional": len(der) - 1, "ML-DSA": len(der) - len(parsed.Signature)} {
				tampered := append([]byte(nil), der...)
				tampered[offset] ^= 1
				if _, problem := checkCSR(tampered, order, account); problem == nil || problem.Type != ErrorBadCSR {
					t.Fatalf("invalid %s signature accepted: %v", name, problem)
				}
			}
		})
	}
}
