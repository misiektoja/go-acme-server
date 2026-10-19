// Package slhdsatest creates SLH-DSA certificate requests and certificates for tests, which
// crypto/x509 cannot create.
package slhdsatest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/go-acme-server/internal/slhdsaspki"
)

// Works like x509.CreateCertificateRequest for an SLH-DSA key. The request is laid out with a
// placeholder key, which is then replaced before key signs it.
func CreateCertificateRequest(template *x509.CertificateRequest, key slhdsa.PrivateKey) ([]byte, error) {
	spki, err := slhdsaspki.Marshal(key.PublicKey())
	if err != nil {
		return nil, err
	}
	oid, _ := slhdsaspki.OID(key.ID)
	placeholder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, placeholder)
	if err != nil {
		return nil, err
	}
	laid, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	// version and subject come before subjectPKInfo.
	info, err := replaceSPKI(laid.RawTBSCertificateRequest, 2, spki)
	if err != nil {
		return nil, err
	}
	signature, err := key.Sign(rand.Reader, info, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(info)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
		})
		b.AddASN1BitString(signature)
	})
	return b.Bytes()
}

// Works like x509.CreateCertificate for the SubjectPublicKeyInfo spki, which may hold an SLH-DSA
// key. The issuer key must be an ECDSA P-256 key.
func CreateCertificate(template, parent *x509.Certificate, spki []byte, issuerKey crypto.Signer) ([]byte, error) {
	placeholder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &placeholder.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	laid, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if laid.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, errors.New("issuer key must be an ECDSA P-256 key")
	}
	// version [0], serialNumber, signature, issuer, validity and subject come first.
	tbs, err := replaceSPKI(laid.RawTBSCertificate, 6, spki)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tbs)
	signature, err := issuerKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	s := cryptobyte.String(der)
	var cert, sigAlg cryptobyte.String
	if !s.ReadASN1(&cert, cbasn1.SEQUENCE) || !cert.SkipASN1(cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&sigAlg, cbasn1.SEQUENCE) {
		return nil, errors.New("cannot read the laid-out certificate")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(sigAlg)
		b.AddASN1BitString(signature)
	})
	return b.Bytes()
}

// Returns a signed structure's to-be-signed part with the SubjectPublicKeyInfo that follows its
// first before fields replaced by spki.
func replaceSPKI(tbs []byte, before int, spki []byte) ([]byte, error) {
	s := cryptobyte.String(tbs)
	var fields cryptobyte.String
	if !s.ReadASN1(&fields, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid signed structure")
	}
	var b cryptobyte.Builder
	var err error
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for range before {
			var field cryptobyte.String
			var tag cbasn1.Tag
			if !fields.ReadAnyASN1Element(&field, &tag) {
				err = errors.New("truncated signed structure")
				return
			}
			b.AddBytes(field)
		}
		if !fields.SkipASN1(cbasn1.SEQUENCE) {
			err = errors.New("missing subjectPublicKeyInfo")
			return
		}
		b.AddBytes(spki)
		b.AddBytes(fields)
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes()
}
