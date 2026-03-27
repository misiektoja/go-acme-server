package acmeserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
