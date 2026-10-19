package acmeserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

// Checks that checkCSR refuses every malformed request with badCSR and that its SLH-DSA verdict
// agrees with an independent reading of RFC 9909.
func FuzzCheckCSR(f *testing.F) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	account := &Account{Key: accountKey.Public()}
	order := &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "slh-dsa.example.test"}}}
	template := &x509.CertificateRequest{DNSNames: []string{"slh-dsa.example.test"}}
	_, key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		f.Fatal(err)
	}
	der, err := slhdsatest.CreateCertificateRequest(template, key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(der)
	// The SLH-DSA-SHAKE-128s request that OpenSSL created.
	data, err := os.ReadFile("testdata/slhdsa-shake-128s.csr")
	if err != nil {
		f.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		f.Fatal("no PEM block")
	}
	f.Add(block.Bytes)
	classical, err := x509.CreateCertificateRequest(rand.Reader, template, accountKey)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(classical)
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		accepted, problem := checkCSR(der, order, account, nil)
		if (accepted == nil) == (problem == nil) {
			t.Fatalf("checkCSR returned %v and %v", accepted, problem)
		}
		if problem != nil && problem.Type != ErrorBadCSR {
			t.Fatalf("checkCSR refused with %s", problem.Type)
		}
		if accepted != nil && string(accepted.Raw) != string(der) {
			t.Fatal("accepted CSR differs from the submitted one")
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			if accepted != nil {
				t.Fatalf("accepted a CSR crypto/x509 cannot parse: %v", err)
			}
			return
		}
		signatureErr := checkCSRSignature(csr)
		if accepted != nil && signatureErr != nil {
			t.Fatalf("accepted a CSR whose signature check fails: %v", signatureErr)
		}
		involved, valid := slhdsaVerdict(csr.Raw, csr.RawSubjectPublicKeyInfo)
		if involved && (signatureErr == nil) != valid {
			t.Fatalf("SLH-DSA signature check = %v, independent verdict = %v", signatureErr, valid)
		}
	})
}

// Decides apart from the code under test whether the key in signerSPKI signed a certificate or
// certificate request in pure SLH-DSA as RFC 9909 requires: exact algorithm encodings without
// parameters, the key's own parameter set and an empty context. It reads DER with encoding/asn1
// instead of cryptobyte. involved reports that the signature algorithm or the key is SLH-DSA.
func slhdsaVerdict(signed, signerSPKI []byte) (involved, valid bool) {
	var parts struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(signed, &parts); err != nil {
		return false, false
	}
	var algorithm pkix.AlgorithmIdentifier
	_, err := asn1.Unmarshal(parts.Algorithm.FullBytes, &algorithm)
	id, signedWithSLHDSA := slhdsaspki.FromOID(algorithm.Algorithm)
	signedWithSLHDSA = signedWithSLHDSA && err == nil
	var keyInfo struct{ Algorithm pkix.AlgorithmIdentifier }
	_, err = asn1.Unmarshal(signerSPKI, &keyInfo)
	keyID, slhdsaKey := slhdsaspki.FromOID(keyInfo.Algorithm.Algorithm)
	slhdsaKey = slhdsaKey && err == nil
	if !signedWithSLHDSA || !slhdsaKey || id != keyID {
		return signedWithSLHDSA || slhdsaKey, false
	}
	// Comparing with fresh encodings catches parameters and the trailing SEQUENCE elements that
	// encoding/asn1 ignores.
	exact, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: algorithm.Algorithm})
	if err != nil || !bytes.Equal(parts.Algorithm.FullBytes, exact) {
		return true, false
	}
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(signerSPKI, &spki)
	if err != nil || !bytes.Equal(spki.Algorithm.FullBytes, exact) || spki.PublicKey.BitLength%8 != 0 {
		return true, false
	}
	if again, err := asn1.Marshal(spki); err != nil || !bytes.Equal(again, signerSPKI) {
		return true, false
	}
	key := slhdsa.PublicKey{ID: id}
	if key.UnmarshalBinary(spki.PublicKey.Bytes) != nil {
		return true, false
	}
	// crypto/x509 right-aligns the signature BIT STRING, so the verdict does the same.
	return true, slhdsa.Verify(&key, slhdsa.NewMessage(parts.TBS.FullBytes), parts.Signature.RightAlign(), nil)
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
