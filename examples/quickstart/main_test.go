package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Signs classical and composite ML-DSA requests with the requested key.
func TestDevCAIssue(t *testing.T) {
	ca, err := newDevCA()
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compositeKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"ecdsa": ecKey, "composite": compositeKey} {
		t.Run(name, func(t *testing.T) {
			der, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"quickstart.example.test"}}, key)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatal(err)
			}
			result, err := ca.Issue(t.Context(), acmeserver.IssueRequest{
				OperationID: "op-" + name,
				CSR:         csr,
				CSRDER:      der,
				Identifiers: []acmeserver.Identifier{{Type: acmeserver.IdentifierDNS, Value: "quickstart.example.test"}},
				Deadline:    time.Now().Add(time.Hour),
			})
			if err != nil || result.Rejected != nil || len(result.Chain) != 2 {
				t.Fatalf("Issue = %+v, %v", result, err)
			}
			leaf, err := x509.ParseCertificate(result.Chain[0])
			if err != nil {
				t.Fatal(err)
			}
			if string(leaf.RawSubjectPublicKeyInfo) != string(csr.RawSubjectPublicKeyInfo) {
				t.Fatal("certificate key differs from the request key")
			}
			if err := compositex509.CheckSignatureFrom(leaf, ca.root); err != nil {
				t.Fatal(err)
			}
		})
	}
}
