package acmeserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"

	"github.com/misiektoja/go-acme-server/internal/slhdsaspki"
	"github.com/misiektoja/go-acme-server/internal/slhdsatest"
)

// Verifies SLH-DSA proofs and the usual identifier checks for the fast parameter sets of both hash families.
func TestSLHDSACSR(t *testing.T) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{Key: accountKey.Public()}
	order := &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "slh-dsa.example.test"}}}
	for _, id := range []slhdsa.ID{slhdsa.SHA2_128f, slhdsa.SHAKE_128f, slhdsa.SHA2_192f, slhdsa.SHAKE_256f} {
		t.Run(id.String(), func(t *testing.T) {
			_, key, err := slhdsa.GenerateKey(rand.Reader, id)
			if err != nil {
				t.Fatal(err)
			}
			der, err := slhdsatest.CreateCertificateRequest(&x509.CertificateRequest{DNSNames: []string{"slh-dsa.example.test"}}, key)
			if err != nil {
				t.Fatal(err)
			}
			csr, problem := checkCSR(der, order, account, nil)
			if problem != nil {
				t.Fatal(problem)
			}
			if string(csr.Raw) != string(der) {
				t.Fatal("accepted CSR differs from the submitted one")
			}
			if _, problem := checkCSR(der, &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "other.example.test"}}}, account, nil); problem == nil {
				t.Fatal("mismatched identity accepted")
			}
			tampered := append([]byte(nil), der...)
			tampered[len(tampered)-1] ^= 1
			if _, problem := checkCSR(tampered, order, account, nil); problem == nil || problem.Type != ErrorBadCSR {
				t.Fatalf("invalid signature accepted: %v", problem)
			}
		})
	}
}

// Rejects SLH-DSA requests with algorithm parameters, another parameter set or HashSLH-DSA.
func TestSLHDSACSRRejections(t *testing.T) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{Key: accountKey.Public()}
	order := &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "slh-dsa.example.test"}}}
	_, key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	der, err := slhdsatest.CreateCertificateRequest(&x509.CertificateRequest{DNSNames: []string{"slh-dsa.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	type algorithmIdentifier struct {
		OID    asn1.ObjectIdentifier
		Params asn1.RawValue `asn1:"optional"`
	}
	other, _ := slhdsaspki.OID(slhdsa.SHAKE_128f)
	own, _ := slhdsaspki.OID(slhdsa.SHA2_128f)
	// RFC 9909 names HashSLH-DSA-SHA2-128s with SHA-256 by this identifier.
	hashSLHDSA := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 35}
	for name, alg := range map[string][]byte{
		"NULL parameters":       mustMarshal(t, algorithmIdentifier{OID: own, Params: asn1.NullRawValue}),
		"another parameter set": mustMarshal(t, algorithmIdentifier{OID: other}),
		"HashSLH-DSA":           mustMarshal(t, algorithmIdentifier{OID: hashSLHDSA}),
	} {
		t.Run(name, func(t *testing.T) {
			var request struct {
				Info      asn1.RawValue
				Algorithm asn1.RawValue
				Signature asn1.BitString
			}
			if _, err := asn1.Unmarshal(der, &request); err != nil {
				t.Fatal(err)
			}
			request.Algorithm = asn1.RawValue{FullBytes: alg}
			changed := mustMarshal(t, request)
			if _, problem := checkCSR(changed, order, account, nil); problem == nil || problem.Type != ErrorBadCSR {
				t.Fatalf("CSR accepted: %v", problem)
			}
		})
	}
}

// Accepts an SLH-DSA-SHAKE-128s request that OpenSSL 4.0.3 created.
func TestSLHDSAOpenSSLCSR(t *testing.T) {
	data, err := os.ReadFile("testdata/slhdsa-shake-128s.csr")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block")
	}
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	order := &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "slh-dsa.example.test"}}}
	csr, problem := checkCSR(block.Bytes, order, &Account{Key: accountKey.Public()}, nil)
	if problem != nil {
		t.Fatal(problem)
	}
	key, err := parseCSRKey(csr.RawSubjectPublicKeyInfo)
	if err != nil || key.(slhdsa.PublicKey).ID != slhdsa.SHAKE_128s {
		t.Fatalf("key = %v, %v", key, err)
	}
}

// Encodes value as DER or fails the test.
func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
