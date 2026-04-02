package acmeserver

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// Rejects issuer results whose additional identities or validity escape the accepted order.
func TestChainChecksCompleteIdentityAndValidity(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ca := newSigner(t, "ES256").key
	key := newSigner(t, "ES256").key
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"a.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, ca.Public(), ca)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*x509.Certificate, *Order)
		valid  bool
	}{
		{"matching", func(*x509.Certificate, *Order) {}, true},
		{"extra common name", func(c *x509.Certificate, _ *Order) { c.Subject.CommonName = "other.test" }, false},
		{"email", func(c *x509.Certificate, _ *Order) { c.EmailAddresses = []string{"admin@other.test"} }, false},
		{"URI", func(c *x509.Certificate, _ *Order) { c.URIs = []*url.URL{{Scheme: "https", Host: "other.test"}} }, false},
		{"other SAN", func(c *x509.Certificate, _ *Order) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{48, 3, 136, 1, 42}}}
		}, false},
		{"future", func(c *x509.Certificate, _ *Order) { c.NotBefore = now.Add(time.Hour) }, false},
		{"expired", func(c *x509.Certificate, _ *Order) { c.NotAfter = now.Add(-time.Second) }, false},
		{"requested notBefore", func(_ *x509.Certificate, o *Order) { o.NotBefore = now.Add(-time.Hour) }, false},
		{"requested notAfter", func(_ *x509.Certificate, o *Order) { o.NotAfter = now.Add(time.Hour) }, false},
		{"accepted future", func(c *x509.Certificate, o *Order) { c.NotBefore = now.Add(time.Hour); o.NotBefore = c.NotBefore }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"a.test"},
				NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour)}
			order := &Order{Identifiers: []Identifier{{Type: IdentifierDNS, Value: "a.test"}}}
			test.mutate(leaf, order)
			der, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), ca)
			if err != nil {
				t.Fatal(err)
			}
			_, err = checkChain([][]byte{der, rootDER}, csr, order, now)
			if (err == nil) != test.valid {
				t.Fatalf("checkChain = %v, valid = %v", err, test.valid)
			}
		})
	}
}
