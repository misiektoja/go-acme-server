package acmeserver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"slices"

	"github.com/misiektoja/go-acme-server/internal/jws"
)

// Parses a CSR and checks that it may finalize the order: a valid self signature, an accepted
// key that is not the account key and exactly the order's identifiers, see RFC 8555 section 7.4.
func checkCSR(der []byte, order *Order, account *Account) (*x509.CertificateRequest, *Problem) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, NewProblem(ErrorBadCSR, "CSR could not be parsed")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, NewProblem(ErrorBadCSR, "CSR signature is invalid")
	}
	if p := checkCSRKey(csr.PublicKey); p != nil {
		return nil, p
	}
	thumbprint, err := jws.Thumbprint(csr.PublicKey)
	if err != nil {
		return nil, NewProblem(ErrorBadCSR, "CSR key is not supported")
	}
	if thumbprint == account.KeyThumbprint {
		return nil, NewProblem(ErrorBadCSR, "CSR key must not be the account key")
	}
	if err := checkSANExtensions(csr.Extensions); err != nil {
		return nil, NewProblem(ErrorBadCSR, "CSR requests unsupported subject alternative name types")
	}
	requested, p := csrIdentifiers(csr)
	if p != nil {
		return nil, p
	}
	if !sameIdentifiers(requested, order.Identifiers) {
		return nil, NewProblem(ErrorBadCSR, "CSR identifiers do not match the order")
	}
	return csr, nil
}

// Rejects keys the server does not issue for.
func checkCSRKey(key any) *Problem {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < jws.MinRSABits || bits > jws.MaxRSABits {
			return Problemf(ErrorBadCSR, "CSR RSA key must have %d to %d bits", jws.MinRSABits, jws.MaxRSABits)
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return NewProblem(ErrorBadCSR, "CSR EC key uses an unsupported curve")
		}
	case ed25519.PublicKey:
	default:
		return NewProblem(ErrorBadCSR, "CSR key type is not supported")
	}
	return nil
}

// Returns the normalized identifiers a CSR requests through its SANs and common name.
func csrIdentifiers(csr *x509.CertificateRequest) ([]Identifier, *Problem) {
	var raw []Identifier
	if csr.Subject.CommonName != "" {
		raw = append(raw, commonNameIdentifier(csr.Subject.CommonName))
	}
	for _, name := range csr.DNSNames {
		raw = append(raw, Identifier{Type: IdentifierDNS, Value: name})
	}
	for _, ip := range csr.IPAddresses {
		raw = append(raw, Identifier{Type: IdentifierIP, Value: ip.String()})
	}
	if len(raw) == 0 {
		return nil, NewProblem(ErrorBadCSR, "CSR requests no identifiers")
	}
	var normalized []Identifier
	for _, id := range raw {
		n, err := id.Normalize()
		if err != nil {
			return nil, NewProblem(ErrorBadCSR, "CSR identifier "+id.String()+" is not acceptable")
		}
		if !slices.Contains(normalized, n) {
			normalized = append(normalized, n)
		}
	}
	return normalized, nil
}

// Reports whether two normalized identifier lists hold the same set.
func sameIdentifiers(a, b []Identifier) bool {
	if len(a) != len(b) {
		return false
	}
	for _, id := range a {
		if !slices.Contains(b, id) {
			return false
		}
	}
	return true
}
