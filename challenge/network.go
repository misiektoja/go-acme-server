// Package challenge provides ACME network validators with explicit resolver and egress policy.
package challenge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Resolves validation destinations through a host-selected resolver.
type IPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Configures validation egress independently from access to the DNS resolver itself.
type NetworkOptions struct {
	// Resolves destination names. It is required.
	Resolver IPResolver
	// Adds explicitly permitted networks to the default public-address policy.
	AllowedNetworks []netip.Prefix
	// Bounds the complete validation attempt and defaults to ten seconds.
	Timeout time.Duration
	// Bounds addresses returned for one name and defaults to 32.
	MaxAddresses int
}

// Holds a validated immutable network configuration.
type networkPolicy struct {
	resolver     IPResolver
	allowed      []netip.Prefix
	timeout      time.Duration
	maxAddresses int
}

// Rejects invalid settings and copies the configured network permissions.
func newNetwork(options NetworkOptions) (networkPolicy, error) {
	if options.Resolver == nil || options.Timeout < 0 || options.MaxAddresses < 0 {
		return networkPolicy{}, errors.New("challenge: resolver is required and limits must not be negative")
	}
	for _, prefix := range options.AllowedNetworks {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return networkPolicy{}, errors.New("challenge: allowed networks must be valid unmapped prefixes")
		}
	}
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.MaxAddresses == 0 {
		options.MaxAddresses = 32
	}
	return networkPolicy{resolver: options.Resolver, allowed: slices.Clone(options.AllowedNetworks),
		timeout: options.Timeout, maxAddresses: options.MaxAddresses}, nil
}

// The conservative exclusions cover IANA special-purpose ranges and non-unicast destinations.
var specialNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
}

// Reports whether an address is ordinary public unicast under the conservative default policy.
func PublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || !address.IsGlobalUnicast() {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, prefix := range specialNetworks {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// Applies explicit network permissions after normalizing IPv4-mapped addresses.
func (p networkPolicy) permits(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	if PublicAddress(address) {
		return true
	}
	for _, prefix := range p.allowed {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// Resolves once and rejects the entire answer if any destination violates egress policy.
func (p networkPolicy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if address, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{address}
	} else {
		id, err := (acmeserver.Identifier{Type: acmeserver.IdentifierDNS, Value: host}).Normalize()
		if err != nil || id.IsWildcard() {
			return nil, incorrect("invalid validation hostname")
		}
		addresses, err = p.resolver.LookupNetIP(ctx, "ip", id.Value+".")
		if err != nil {
			return nil, fmt.Errorf("challenge: destination resolution: %w", err)
		}
	}
	if len(addresses) == 0 || len(addresses) > p.maxAddresses {
		return nil, incorrect("destination address count is outside the limit")
	}
	for _, address := range addresses {
		if !p.permits(address) {
			return nil, incorrect("validation destination is denied by egress policy")
		}
	}
	return addresses, nil
}

// Dials only numeric addresses from the approved resolution result.
func (p networkPolicy) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	addresses, err := p.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, address := range addresses {
		destination := net.JoinHostPort(address.Unmap().String(), strconv.Itoa(port))
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", destination)
		if err == nil {
			return connection, nil
		}
		last = err
	}
	return nil, fmt.Errorf("challenge: connection failed: %w", last)
}

// Checks identifier scope and the captured proof before any network access.
func checkRequest(req acmeserver.ValidationRequest, typ acmeserver.ChallengeType) (acmeserver.Identifier, error) {
	id, err := req.Identifier.Normalize()
	if err != nil {
		return acmeserver.Identifier{}, err
	}
	if req.Challenge.Type != typ || id.IsWildcard() || (req.Wildcard && typ != acmeserver.ChallengeDNS01) ||
		(id.Type == acmeserver.IdentifierIP && typ == acmeserver.ChallengeDNS01) {
		return acmeserver.Identifier{}, incorrect("identifier does not support this challenge")
	}
	if len(req.Challenge.Token) < 22 || len(req.Challenge.Token) > 256 || !base64URL(req.Challenge.Token) ||
		len(req.AccountKeyThumbprint) != 43 || !base64URL(req.AccountKeyThumbprint) ||
		req.KeyAuthorization != req.Challenge.Token+"."+req.AccountKeyThumbprint {
		return acmeserver.Identifier{}, incorrect("invalid captured key authorization")
	}
	return id, nil
}

// Checks the unpadded base64url alphabet without accepting whitespace.
func base64URL(value string) bool {
	for _, c := range value {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return value != ""
}

// Returns a terminal invalid-proof result without exposing fetched content.
func incorrect(detail string) *acmeserver.Problem {
	return acmeserver.NewProblem(acmeserver.ErrorIncorrectResponse, detail)
}
