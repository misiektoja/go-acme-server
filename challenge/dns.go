package challenge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Supplies bounded TXT lookups through a trusted host resolver or the provided Resolver.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Configures the TXT resolver and complete DNS-01 attempt timeout.
type DNSOptions struct {
	// Looks up TXT records. It is required.
	Resolver TXTResolver
	// Bounds the complete validation attempt and defaults to ten seconds.
	Timeout time.Duration
}

// Validates a DNS-01 digest while allowing concurrent TXT proofs at the same owner name.
type DNS01 struct {
	resolver TXTResolver
	timeout  time.Duration
}

// Constructs a DNS validator with a required resolver and a ten-second default timeout.
func NewDNS01(options DNSOptions) (*DNS01, error) {
	if options.Resolver == nil || options.Timeout < 0 {
		return nil, errors.New("challenge: DNS resolver is required and timeout must not be negative")
	}
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	return &DNS01{resolver: options.Resolver, timeout: options.Timeout}, nil
}

// Requires a matching TXT digest for a base or wildcard DNS identifier under RFC 8555 section 8.4.
func (v *DNS01) Validate(ctx context.Context, request acmeserver.ValidationRequest) error {
	id, err := checkRequest(request, acmeserver.ChallengeDNS01)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	records, err := v.resolver.LookupTXT(ctx, "_acme-challenge."+id.Value+".")
	if err != nil {
		return err
	}
	if len(records) > 64 {
		return dnsFailure("TXT response exceeds the record limit")
	}
	digest := sha256.Sum256([]byte(request.KeyAuthorization))
	expected := base64.RawURLEncoding.EncodeToString(digest[:])
	if slices.Contains(records, expected) {
		return nil
	}
	return incorrect("DNS challenge proof did not match")
}
