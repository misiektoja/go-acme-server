package acmeserver

import (
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// Names the kind of subject an order or authorization refers to.
type IdentifierType string

// Identifier types registered by RFC 8555 section 9.7.7, RFC 8738, RFC 9448 and 3GPP TS 33.310
// Annex J, plus the uri type that only authority tokens grant.
const (
	IdentifierDNS IdentifierType = "dns"
	IdentifierIP  IdentifierType = "ip"
	// A base64url encoded DER TN Authorization List, see RFC 8226 section 9.
	IdentifierTNAuthList IdentifierType = "TNAuthList"
	// The UUID of a 5G network function instance, see 3GPP TS 33.310 clause J.3.3.2. A certificate
	// carries it as the URI name urn:uuid:<value>.
	IdentifierNfInstanceID IdentifierType = "NfInstanceId"
	// An https URI name that an authority token adds to a certificate, such as the API root of a
	// network function. No ACME specification registers it, so orders cannot request it.
	IdentifierURI IdentifierType = "uri"
)

// The URI prefix that carries an NfInstanceId in a certificate, see RFC 4122 section 3.
const nfInstanceURNPrefix = "urn:uuid:"

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
	case IdentifierNfInstanceID:
		return normalizeNfInstanceID(id.Value)
	case IdentifierURI:
		return normalizeURI(id.Value)
	}
	return Identifier{}, Problemf(ErrorUnsupportedIdentifier, "identifier type %q is not supported", string(id.Type))
}

// Returns the URI name a certificate carries for an NfInstanceId identifier, or an https URI
// identifier's value. Other identifier types have no URI form and return an empty string.
func (id Identifier) URI() string {
	switch id.Type {
	case IdentifierNfInstanceID:
		return nfInstanceURNPrefix + id.Value
	case IdentifierURI:
		return id.Value
	case IdentifierDNS, IdentifierIP, IdentifierTNAuthList:
	}
	return ""
}

// Returns the identifier a certificate URI name stands for: an NfInstanceId for urn:uuid and a
// uri identifier for an https URI. Errors are *Problem values like those of Normalize.
func uriNameIdentifier(name string) (Identifier, error) {
	if len(name) > len(nfInstanceURNPrefix) && strings.EqualFold(name[:len(nfInstanceURNPrefix)], nfInstanceURNPrefix) {
		return normalizeNfInstanceID(name[len(nfInstanceURNPrefix):])
	}
	return normalizeURI(name)
}

// Lowercases a UUID in the 8-4-4-4-12 hexadecimal form. TS 29.571 asks senders for version 4 in
// lower case and receivers to ignore case, so only the form is checked. The nil UUID names no
// instance and is refused.
func normalizeNfInstanceID(value string) (Identifier, error) {
	id := Identifier{Type: IdentifierNfInstanceID, Value: value}
	if value == "" {
		return Identifier{}, NewProblem(ErrorMalformed, "NfInstanceId identifier value is empty")
	}
	if len(value) != 36 {
		return Identifier{}, rejected(id, "NfInstanceId identifier is not a UUID")
	}
	lower := strings.ToLower(value)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return Identifier{}, rejected(id, "NfInstanceId identifier is not a UUID")
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return Identifier{}, rejected(id, "NfInstanceId identifier is not a UUID")
		}
	}
	if strings.Trim(lower, "0-") == "" {
		return Identifier{}, rejected(id, "NfInstanceId identifier is the nil UUID")
	}
	return Identifier{Type: IdentifierNfInstanceID, Value: lower}, nil
}

// Bounds the length of a uri identifier.
const maxURILength = 2048

// Checks an absolute https URI without user information or a fragment and returns it with the
// scheme and host in lower case, the form crypto/x509 reads back from a certificate.
func normalizeURI(value string) (Identifier, error) {
	id := Identifier{Type: IdentifierURI, Value: value}
	if value == "" {
		return Identifier{}, NewProblem(ErrorMalformed, "uri identifier value is empty")
	}
	if len(value) > maxURILength {
		return Identifier{}, rejected(id, "uri identifier exceeds 2048 characters")
	}
	for i := 0; i < len(value); i++ {
		if value[i] <= ' ' || value[i] >= 0x7f {
			return Identifier{}, rejected(id, "uri identifier must be ASCII without spaces or control characters")
		}
	}
	u, err := url.Parse(value)
	if err != nil || !strings.EqualFold(u.Scheme, schemeHTTPS) || u.Host == "" || u.User != nil || u.Fragment != "" ||
		u.Opaque != "" {
		return Identifier{}, rejected(id, "uri identifier must be an absolute https URI without user information "+
			"or a fragment")
	}
	u.Scheme, u.Host = schemeHTTPS, strings.ToLower(u.Host)
	return Identifier{Type: IdentifierURI, Value: u.String()}, nil
}

// Limits from RFC 9310 section 3 on one NFType string.
const maxNFTypeLength = 32

// Reports whether value is a valid RFC 9310 NFType: 1 to 32 printable ASCII characters without
// spaces. 3GPP TS 29.510 clause 6.1.6.3.3 lists the values in use, such as AMF or NRF, and keeps
// adding new ones, so the value is not compared with a list.
func ValidNFType(value string) bool {
	if value == "" || len(value) > maxNFTypeLength {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] <= ' ' || value[i] >= 0x7f {
			return false
		}
	}
	return true
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

// Returns why a lowercase label is not a valid host name label, or an empty string. A label
// starting with xn-- must be a properly encoded A-label, as RFC 8555 section 7.1.4 requires.
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
	if strings.HasPrefix(label, "xn--") && !validALabel(label) {
		return "dns identifier label " + label + " is not a valid A-label"
	}
	return ""
}

// Reports whether a label decodes as Punycode to a name the IDNA2008 registration rules allow
// and encodes back to the same label. The registration profile of golang.org/x/net/idna follows
// UTS 46, which also accepts a few symbols IDNA2008 itself disallows, such as emoji.
func validALabel(label string) bool {
	uLabel, err := idna.Registration.ToUnicode(label)
	if err != nil {
		return false
	}
	aLabel, err := idna.Registration.ToASCII(uLabel)
	return err == nil && aLabel == label
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
