package acmeserver

import (
	"net/netip"
	"strings"
)

// Names the kind of subject an order or authorization refers to.
type IdentifierType string

// Identifier types registered by RFC 8555 section 9.7.7, RFC 8738 and RFC 9448.
const (
	IdentifierDNS IdentifierType = "dns"
	IdentifierIP  IdentifierType = "ip"
	// A base64url encoded DER TN Authorization List, see RFC 8226 section 9.
	IdentifierTNAuthList IdentifierType = "TNAuthList"
)

// An ACME identifier object.
type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

// Returns the type and value joined by a colon.
func (id Identifier) String() string { return string(id.Type) + ":" + id.Value }

// Reports whether the identifier is a DNS name whose leftmost label is a wildcard.
func (id Identifier) IsWildcard() bool {
	return id.Type == IdentifierDNS && strings.HasPrefix(id.Value, "*.")
}

// Limits from RFC 1035 on the textual form of a domain name.
const (
	maxDNSNameLength  = 253
	maxDNSLabelLength = 63
)

// Validates the identifier syntax and returns its canonical form. Errors are *Problem values
// with type unsupportedIdentifier, malformed or rejectedIdentifier. Issuance policy is left to the host.
func (id Identifier) Normalize() (Identifier, error) {
	switch id.Type {
	case IdentifierDNS:
		return normalizeDNS(id.Value)
	case IdentifierIP:
		return normalizeIP(id.Value)
	case IdentifierTNAuthList:
		return normalizeTNAuthList(id.Value)
	}
	return Identifier{}, Problemf(ErrorUnsupportedIdentifier, "identifier type %q is not supported", string(id.Type))
}

// Normalizes every identifier and rejects duplicates in the normalized set.
func NormalizeIdentifiers(ids []Identifier) ([]Identifier, error) {
	out := make([]Identifier, 0, len(ids))
	seen := make(map[Identifier]struct{}, len(ids))
	for _, id := range ids {
		normalized, err := id.Normalize()
		if err != nil {
			return nil, err
		}
		if _, dup := seen[normalized]; dup {
			return nil, Problemf(ErrorMalformed, "identifier %s is listed more than once", normalized).WithIdentifier(normalized)
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

// Lowercases a DNS name and checks RFC 1123 host name syntax and the RFC 8555 wildcard rule.
func normalizeDNS(value string) (Identifier, error) {
	id := Identifier{Type: IdentifierDNS, Value: value}
	if value == "" {
		return Identifier{}, NewProblem(ErrorMalformed, "dns identifier value is empty")
	}
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return Identifier{}, rejected(id, "dns identifier must use ASCII labels; encode internationalized names as A-labels")
		}
	}
	name := strings.ToLower(value)
	if len(name) > maxDNSNameLength {
		return Identifier{}, rejected(id, "dns identifier exceeds 253 characters")
	}
	base := strings.TrimPrefix(name, "*.")
	if strings.Contains(base, "*") {
		return Identifier{}, rejected(id, "wildcard is only allowed as the complete leftmost label")
	}
	if base == "" {
		return Identifier{}, rejected(id, "dns identifier has no labels")
	}
	if _, err := netip.ParseAddr(base); err == nil {
		return Identifier{}, rejected(id, "IP addresses use the ip identifier type")
	}
	for label := range strings.SplitSeq(base, ".") {
		if reason := checkDNSLabel(label); reason != "" {
			return Identifier{}, rejected(id, reason)
		}
	}
	return Identifier{Type: IdentifierDNS, Value: name}, nil
}

// Returns why a lowercase label is not a valid host name label, or an empty string.
func checkDNSLabel(label string) string {
	if label == "" {
		return "dns identifier contains an empty label"
	}
	if len(label) > maxDNSLabelLength {
		return "dns identifier label exceeds 63 characters"
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return "dns identifier label starts or ends with a hyphen"
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return "dns identifier contains a character outside letters, digits and hyphens"
		}
	}
	return ""
}

// Parses an IP address and returns its RFC 5952 textual form.
func normalizeIP(value string) (Identifier, error) {
	id := Identifier{Type: IdentifierIP, Value: value}
	if value == "" {
		return Identifier{}, NewProblem(ErrorMalformed, "ip identifier value is empty")
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return Identifier{}, rejected(id, "ip identifier is not a valid IP address")
	}
	if addr.Zone() != "" {
		return Identifier{}, rejected(id, "ip identifier must not carry a zone")
	}
	if addr.Is4In6() {
		return Identifier{}, rejected(id, "IPv4-mapped IPv6 addresses must be given in IPv4 form")
	}
	if addr.IsUnspecified() || addr.IsMulticast() {
		return Identifier{}, rejected(id, "unspecified and multicast addresses cannot be issued")
	}
	return Identifier{Type: IdentifierIP, Value: addr.String()}, nil
}

// Returns a rejectedIdentifier problem that names the offending identifier.
func rejected(id Identifier, detail string) *Problem {
	return NewProblem(ErrorRejectedIdentifier, detail).WithIdentifier(id)
}
