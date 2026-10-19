package acmeserver

import (
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-acme-server/internal/slhdsaspki"
)

// Parses a CSR key. crypto/x509 leaves PublicKey nil for SLH-DSA and composite ML-DSA keys.
func parseCSRKey(spki []byte) (crypto.PublicKey, error) {
	key, isSLHDSA, err := slhdsaspki.Parse(spki)
	if err != nil {
		return nil, err
	}
	if isSLHDSA {
		return key, nil
	}
	return compositex509.ParsePKIXPublicKey(spki)
}

// Checks the CSR self signature, including SLH-DSA signatures in pure mode with an empty context.
func checkCSRSignature(csr *x509.CertificateRequest) error {
	s := cryptobyte.String(csr.Raw)
	var request cryptobyte.String
	if !s.ReadASN1(&request, cbasn1.SEQUENCE) || !request.SkipASN1(cbasn1.SEQUENCE) {
		return errors.New("malformed certificate request")
	}
	oid, absent, ok := slhdsaspki.ReadAlgorithm(&request)
	id, isSLHDSA := slhdsaspki.FromOID(oid)
	if !ok || !isSLHDSA {
		return compositex509.CheckCertificateRequestSignature(csr)
	}
	if !absent {
		return errors.New("SLH-DSA signature parameters must be absent")
	}
	key, isKey, err := slhdsaspki.Parse(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	if !isKey || key.ID != id {
		return errors.New("CSR key does not match the SLH-DSA signature algorithm")
	}
	if !slhdsa.Verify(&key, slhdsa.NewMessage(csr.RawTBSCertificateRequest), csr.Signature, nil) {
		return errors.New("SLH-DSA signature verification failed")
	}
	return nil
}

// Checks that parent signed cert. A parent with an SLH-DSA key must sign in pure mode with an empty
// context. Other signatures go to compositex509, which passes classical ones to crypto/x509.
func checkSignatureFrom(cert, parent *x509.Certificate) error {
	key, isSLHDSA, err := slhdsaspki.Parse(parent.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	if !isSLHDSA {
		return compositex509.CheckSignatureFrom(cert, parent)
	}
	// The basic constraints and key usage rules of RFC 5280 that crypto/x509 applies to every issuer.
	if parent.Version == 3 && !parent.BasicConstraintsValid || parent.BasicConstraintsValid && !parent.IsCA {
		return x509.ConstraintViolationError{}
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}
	s := cryptobyte.String(cert.Raw)
	var signed cryptobyte.String
	if !s.ReadASN1(&signed, cbasn1.SEQUENCE) || !signed.SkipASN1(cbasn1.SEQUENCE) {
		return errors.New("malformed certificate")
	}
	oid, absent, ok := slhdsaspki.ReadAlgorithm(&signed)
	id, isSLHDSASignature := slhdsaspki.FromOID(oid)
	if !ok || !isSLHDSASignature || id != key.ID {
		return errors.New("certificate is not signed with the SLH-DSA key of its issuer")
	}
	if !absent {
		return errors.New("SLH-DSA signature parameters must be absent")
	}
	if !slhdsa.Verify(&key, slhdsa.NewMessage(cert.RawTBSCertificate), cert.Signature, nil) {
		return errors.New("SLH-DSA signature verification failed")
	}
	return nil
}
