package acmeserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

// Verifies ML-DSA proof and identifier checks without using certificate keys as JWS account keys.
func TestMLDSACSR(t *testing.T) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{Key: accountKey.Public()}
	order := &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "pqc.example.test"}}}
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"pqc.example.test"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, problem := checkCSR(der, order, account); problem != nil {
			t.Fatal(problem)
		}
		if _, problem := checkCSR(der, &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "other.example.test"}}}, account); problem == nil {
			t.Fatal("mismatched identity accepted")
		}
		if _, problem := checkCSR(der, order, &Account{Key: key.Public()}); problem == nil {
			t.Fatal("account key reused as certificate key")
		}
		der[len(der)-1] ^= 1
		if _, problem := checkCSR(der, order, account); problem == nil {
			t.Fatal("invalid proof accepted")
		}
	}
}
