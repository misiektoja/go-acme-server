package acmeserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// Returns a random 128-bit identifier in base64url form.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("acmeserver: random identifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Returns the certificate ID derived from the DER leaf certificate.
func certificateID(leafDER []byte) string {
	sum := sha256.Sum256(leafDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Bounds the two base64url parts of an RFC 9773 certificate identifier.
const maxRenewalIDLength = 2*maxIDLength + 1

// Returns the RFC 9773 section 4.1 identifier of a leaf, or an empty string without an
// authority key identifier.
func renewalID(leaf *x509.Certificate) string {
	if len(leaf.AuthorityKeyId) == 0 || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return ""
	}
	// The serial is the DER INTEGER content, so a leading one bit needs a zero byte.
	serial := leaf.SerialNumber.Bytes()
	if serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serial)
}

// Reports whether s has the shape of an RFC 9773 certificate identifier.
func validRenewalID(s string) bool {
	if len(s) > maxRenewalIDLength {
		return false
	}
	aki, serial, ok := strings.Cut(s, ".")
	return ok && validID(aki) && validID(serial)
}
