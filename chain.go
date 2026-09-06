package acmeserver

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Rejects SAN forms that the DNS and IP authorization model cannot cover.
func checkSANExtensions(extensions []pkix.Extension) error {
	for _, extension := range extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var names []asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &names)
		if err != nil || len(rest) != 0 {
			return errors.New("invalid subject alternative name extension")
		}
		for _, name := range names {
			if name.Class != asn1.ClassContextSpecific || name.IsCompound || (name.Tag != 2 && name.Tag != 7) {
				return errors.New("unsupported subject alternative name type")
			}
		}
	}
	return nil
}

// Returns the complete supported SAN set and checks the common name against it.
func certificateIdentifiers(leaf *x509.Certificate) ([]Identifier, error) {
	if err := checkSANExtensions(leaf.Extensions); err != nil {
		return nil, err
	}
	tnAuthList, hasTNAuthList, err := tnAuthListExtension(leaf.Extensions)
	if err != nil {
		return nil, err
	}
	names := make([]Identifier, 0, len(leaf.DNSNames)+len(leaf.IPAddresses)+1)
	if hasTNAuthList {
		names = append(names, tnAuthList)
	}
	for _, name := range leaf.DNSNames {
		names = append(names, Identifier{Type: IdentifierDNS, Value: name})
	}
	for _, ip := range leaf.IPAddresses {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, errors.New("invalid IP SAN")
		}
		names = append(names, Identifier{Type: IdentifierIP, Value: addr.Unmap().String()})
	}
	ids, err := NormalizeIdentifiers(names)
	if err != nil || len(ids) == 0 {
		return nil, errors.New("invalid certificate identifiers")
	}
	// A STIR certificate names a service provider in the common name, not one of its identifiers.
	if leaf.Subject.CommonName != "" && !hasTNAuthList {
		cn, err := commonNameIdentifier(leaf.Subject.CommonName).Normalize()
		if err != nil || !slices.Contains(ids, cn) {
			return nil, errors.New("common name is outside the SAN set")
		}
	}
	return ids, nil
}

// Interprets an IP common name as an IP identifier and every other value as DNS.
func commonNameIdentifier(name string) Identifier {
	if _, err := netip.ParseAddr(name); err == nil {
		return Identifier{Type: IdentifierIP, Value: name}
	}
	return Identifier{Type: IdentifierDNS, Value: name}
}

// Checks the issued key, identifiers, accepted validity and chain signatures before publication.
func checkChain(chain [][]byte, csr *x509.CertificateRequest, order *Order, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty chain")
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("chain element %d: %w", i, err)
		}
		certs[i] = cert
	}
	leaf := certs[0]
	if string(leaf.RawSubjectPublicKeyInfo) != string(csr.RawSubjectPublicKeyInfo) {
		return nil, errors.New("leaf public key does not match the CSR")
	}
	if !leaf.NotAfter.After(now) || !leaf.NotAfter.After(leaf.NotBefore) {
		return nil, errors.New("leaf certificate validity is invalid or expired")
	}
	if order.NotBefore.IsZero() && leaf.NotBefore.After(now) {
		return nil, errors.New("leaf certificate is not valid yet")
	}
	if !order.NotBefore.IsZero() && !leaf.NotBefore.Equal(order.NotBefore.Truncate(time.Second)) {
		return nil, errors.New("leaf notBefore differs from the accepted order")
	}
	if !order.NotAfter.IsZero() && !leaf.NotAfter.Equal(issuedNotAfter(order).Truncate(time.Second)) {
		return nil, errors.New("leaf notAfter differs from the requested validity")
	}
	if order.Issuance != nil {
		if bound := grantExpiry(order.Issuance.Validations); !bound.IsZero() && leaf.NotAfter.After(bound) {
			return nil, errors.New("leaf certificate outlives the authority token")
		}
	}
	ids, err := certificateIdentifiers(leaf)
	if err != nil || !sameIdentifiers(ids, order.Identifiers) {
		return nil, errors.New("leaf identifiers do not match the order")
	}
	if err := checkLeafCACertificate(leaf, csr, order); err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("chain element %d is not signed by element %d: %w", i, i+1, err)
		}
	}
	return leaf, nil
}

// Checks that an authority list certificate is a CA certificate exactly when the accepted request
// asked for one, see RFC 9448 section 6.
func checkLeafCACertificate(leaf *x509.Certificate, csr *x509.CertificateRequest, order *Order) error {
	if !slices.ContainsFunc(order.Identifiers, func(id Identifier) bool {
		return id.Type == IdentifierTNAuthList
	}) {
		return nil
	}
	requested, err := csrCACertificate(csr.Extensions)
	if err != nil {
		return err
	}
	if leaf.IsCA != requested {
		return errors.New("leaf CA basic constraint does not match the certificate request")
	}
	return nil
}
