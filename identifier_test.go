package acmeserver

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestIdentifierNormalize(t *testing.T) {
	cases := []struct {
		name    string
		in      Identifier
		want    Identifier
		wantErr ErrorType
	}{
		{name: "dns lowercase", in: Identifier{IdentifierDNS, "Example.COM"}, want: Identifier{IdentifierDNS, "example.com"}},
		{name: "dns wildcard", in: Identifier{IdentifierDNS, "*.Example.com"}, want: Identifier{IdentifierDNS, "*.example.com"}},
		{name: "dns single label", in: Identifier{IdentifierDNS, "localhost"}, want: Identifier{IdentifierDNS, "localhost"}},
		{name: "dns a-label", in: Identifier{IdentifierDNS, "xn--bcher-kva.example"}, want: Identifier{IdentifierDNS, "xn--bcher-kva.example"}},
		{name: "dns empty", in: Identifier{IdentifierDNS, ""}, wantErr: ErrorMalformed},
		{name: "dns trailing dot", in: Identifier{IdentifierDNS, "example.com."}, wantErr: ErrorRejectedIdentifier},
		{name: "dns leading dot", in: Identifier{IdentifierDNS, ".example.com"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns empty label", in: Identifier{IdentifierDNS, "a..b"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns bare wildcard", in: Identifier{IdentifierDNS, "*."}, wantErr: ErrorRejectedIdentifier},
		{name: "dns wildcard only", in: Identifier{IdentifierDNS, "*"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns inner wildcard", in: Identifier{IdentifierDNS, "a.*.example.com"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns partial wildcard", in: Identifier{IdentifierDNS, "*a.example.com"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns double wildcard", in: Identifier{IdentifierDNS, "*.*.example.com"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns hyphen edge", in: Identifier{IdentifierDNS, "-a.example.com"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns underscore", in: Identifier{IdentifierDNS, "_acme.example.com"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns space", in: Identifier{IdentifierDNS, "exa mple.com"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns non-ascii", in: Identifier{IdentifierDNS, "bücher.example"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns ipv4 literal", in: Identifier{IdentifierDNS, "192.0.2.1"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns ipv6 literal", in: Identifier{IdentifierDNS, "2001:db8::1"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns long label", in: Identifier{IdentifierDNS, string(make64('a')) + ".example"}, wantErr: ErrorRejectedIdentifier},
		{name: "dns long name", in: Identifier{IdentifierDNS, longName()}, wantErr: ErrorRejectedIdentifier},
		{name: "ip v4", in: Identifier{IdentifierIP, "192.0.2.1"}, want: Identifier{IdentifierIP, "192.0.2.1"}},
		{name: "ip v6 canonical", in: Identifier{IdentifierIP, "2001:0DB8:0000:0000:0000:0000:0000:0001"}, want: Identifier{IdentifierIP, "2001:db8::1"}},
		{name: "ip empty", in: Identifier{IdentifierIP, ""}, wantErr: ErrorMalformed},
		{name: "ip invalid", in: Identifier{IdentifierIP, "192.0.2.256"}, wantErr: ErrorRejectedIdentifier},
		{name: "ip hostname", in: Identifier{IdentifierIP, "example.com"}, wantErr: ErrorRejectedIdentifier},
		{name: "ip zone", in: Identifier{IdentifierIP, "fe80::1%eth0"}, wantErr: ErrorRejectedIdentifier},
		{name: "ip mapped", in: Identifier{IdentifierIP, "::ffff:192.0.2.1"}, wantErr: ErrorRejectedIdentifier},
		{name: "ip unspecified", in: Identifier{IdentifierIP, "0.0.0.0"}, wantErr: ErrorRejectedIdentifier},
		{name: "ip multicast", in: Identifier{IdentifierIP, "ff02::1"}, wantErr: ErrorRejectedIdentifier},
		{name: "nf instance lowercase", in: Identifier{IdentifierNfInstanceID, "4ACE9D34-2C69-4F99-92D5-A73A3FE8E23B"}, want: Identifier{IdentifierNfInstanceID, "4ace9d34-2c69-4f99-92d5-a73a3fe8e23b"}},
		{name: "nf instance any version", in: Identifier{IdentifierNfInstanceID, "4ace9d34-2c69-1f99-92d5-a73a3fe8e23b"}, want: Identifier{IdentifierNfInstanceID, "4ace9d34-2c69-1f99-92d5-a73a3fe8e23b"}},
		{name: "nf instance empty", in: Identifier{IdentifierNfInstanceID, ""}, wantErr: ErrorMalformed},
		{name: "nf instance braces", in: Identifier{IdentifierNfInstanceID, "{4ace9d34-2c69-4f99-92d5-a73a3fe8e23b}"}, wantErr: ErrorRejectedIdentifier},
		{name: "nf instance no hyphens", in: Identifier{IdentifierNfInstanceID, "4ace9d342c694f9992d5a73a3fe8e23b"}, wantErr: ErrorRejectedIdentifier},
		{name: "nf instance misplaced hyphen", in: Identifier{IdentifierNfInstanceID, "4ace9d3-42c69-4f99-92d5-a73a3fe8e23b"}, wantErr: ErrorRejectedIdentifier},
		{name: "nf instance not hex", in: Identifier{IdentifierNfInstanceID, "4ace9d34-2c69-4f99-92d5-a73a3fe8e23g"}, wantErr: ErrorRejectedIdentifier},
		{name: "nf instance urn", in: Identifier{IdentifierNfInstanceID, "urn:uuid:4ace9d34-2c69-4f99-92d5-a73a3fe8e23b"}, wantErr: ErrorRejectedIdentifier},
		{name: "nf instance nil", in: Identifier{IdentifierNfInstanceID, "00000000-0000-0000-0000-000000000000"}, wantErr: ErrorRejectedIdentifier},
		{name: "uri canonical host", in: Identifier{IdentifierURI, "HTTPS://NF.Example.test:8443/Api"}, want: Identifier{IdentifierURI, "https://nf.example.test:8443/Api"}},
		{name: "uri empty", in: Identifier{IdentifierURI, ""}, wantErr: ErrorMalformed},
		{name: "uri http", in: Identifier{IdentifierURI, "http://nf.example.test/"}, wantErr: ErrorRejectedIdentifier},
		{name: "uri relative", in: Identifier{IdentifierURI, "/api"}, wantErr: ErrorRejectedIdentifier},
		{name: "uri user info", in: Identifier{IdentifierURI, "https://u@nf.example.test/"}, wantErr: ErrorRejectedIdentifier},
		{name: "uri fragment", in: Identifier{IdentifierURI, "https://nf.example.test/#a"}, wantErr: ErrorRejectedIdentifier},
		{name: "uri space", in: Identifier{IdentifierURI, "https://nf.example.test/a b"}, wantErr: ErrorRejectedIdentifier},
		{name: "uri non-ascii", in: Identifier{IdentifierURI, "https://bücher.example/"}, wantErr: ErrorRejectedIdentifier},
		{name: "uri too long", in: Identifier{IdentifierURI, "https://nf.example.test/" + strings.Repeat("a", 2048)}, wantErr: ErrorRejectedIdentifier},
		{name: "unknown type", in: Identifier{IdentifierType("email"), "a@b.test"}, wantErr: ErrorUnsupportedIdentifier},
		{name: "empty type", in: Identifier{"", "example.com"}, wantErr: ErrorUnsupportedIdentifier},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.in.Normalize()
			if tc.wantErr != "" {
				p, ok := AsProblem(err)
				if !ok || p.Type != tc.wantErr {
					t.Fatalf("Normalize(%v) error = %v, want %s", tc.in, err, tc.wantErr)
				}
				if tc.wantErr == ErrorRejectedIdentifier && (p.Identifier == nil || *p.Identifier != tc.in) {
					t.Fatalf("rejected problem does not name the identifier: %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%v) error = %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Normalize(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeIdentifiers(t *testing.T) {
	got, err := NormalizeIdentifiers([]Identifier{{IdentifierDNS, "A.example"}, {IdentifierIP, "2001:DB8::1"}})
	if err != nil || len(got) != 2 || got[0].Value != "a.example" || got[1].Value != "2001:db8::1" {
		t.Fatalf("NormalizeIdentifiers = %v, %v", got, err)
	}
	_, err = NormalizeIdentifiers([]Identifier{{IdentifierDNS, "a.example"}, {IdentifierDNS, "A.EXAMPLE"}})
	p, ok := AsProblem(err)
	if !ok || p.Type != ErrorMalformed || p.Identifier == nil || p.Identifier.Value != "a.example" {
		t.Fatalf("duplicate error = %v", err)
	}
	_, err = NormalizeIdentifiers([]Identifier{{IdentifierDNS, "a.example"}, {IdentifierDNS, "bad..name"}})
	if p, ok := AsProblem(err); !ok || p.Type != ErrorRejectedIdentifier {
		t.Fatalf("rejected error = %v", err)
	}
	if !errors.As(err, new(*Problem)) {
		t.Fatalf("error is not a *Problem: %T", err)
	}
	if got, err := NormalizeIdentifiers(nil); err != nil || len(got) != 0 {
		t.Fatalf("NormalizeIdentifiers(nil) = %v, %v", got, err)
	}
}

func TestIdentifierHelpers(t *testing.T) {
	id := Identifier{IdentifierDNS, "*.example.com"}
	if !id.IsWildcard() || id.String() != "dns:*.example.com" {
		t.Fatalf("helpers = %v %q", id.IsWildcard(), id.String())
	}
	if (Identifier{IdentifierIP, "*.1"}).IsWildcard() {
		t.Fatal("ip identifier reported as wildcard")
	}
	nf := Identifier{IdentifierNfInstanceID, "4ace9d34-2c69-4f99-92d5-a73a3fe8e23b"}
	if nf.URI() != "urn:uuid:4ace9d34-2c69-4f99-92d5-a73a3fe8e23b" || id.URI() != "" {
		t.Fatalf("URI = %q and %q", nf.URI(), id.URI())
	}
	if got, err := uriNameIdentifier("URN:UUID:4ACE9D34-2C69-4F99-92D5-A73A3FE8E23B"); err != nil || got != nf {
		t.Fatalf("uriNameIdentifier(urn) = %v, %v", got, err)
	}
	if got, err := uriNameIdentifier("https://NF.example.test/api"); err != nil ||
		got != (Identifier{IdentifierURI, "https://nf.example.test/api"}) {
		t.Fatalf("uriNameIdentifier(https) = %v, %v", got, err)
	}
	if _, err := uriNameIdentifier("urn:isbn:0451450523"); err == nil {
		t.Fatal("an unsupported URI name was accepted")
	}
}

func TestValidNFType(t *testing.T) {
	for value, want := range map[string]bool{
		"AMF": true, "NRF": true, "5G_DDNMF": true, strings.Repeat("A", 32): true,
		"": false, "A MF": false, strings.Repeat("A", 33): false, "AMF\x7f": false, "ÅMF": false,
	} {
		if got := ValidNFType(value); got != want {
			t.Errorf("ValidNFType(%q) = %v, want %v", value, got, want)
		}
	}
}

// Returns 64 copies of c.
func make64(c byte) []byte {
	out := make([]byte, 64)
	for i := range out {
		out[i] = c
	}
	return out
}

// Returns a name with valid labels that exceeds 253 characters.
func longName() string {
	label := string(make64('b')[:60])
	return label + "." + label + "." + label + "." + label + "." + label + ".example"
}

// Checks that normalization is idempotent, keeps the documented syntax and fails with problems.
func FuzzIdentifierNormalize(f *testing.F) {
	f.Add("dns", "Example.COM")
	f.Add("dns", "*.example.com")
	f.Add("dns", "xn--bcher-kva.example")
	f.Add("dns", "a..b")
	f.Add("ip", "::FFFF:192.0.2.1")
	f.Add("ip", "2001:DB8::1")
	f.Add("ip", "fe80::1%eth0")
	f.Add("mail", "x")
	f.Add("NfInstanceId", "4ACE9D34-2C69-4F99-92D5-A73A3FE8E23B")
	f.Add("uri", "HTTPS://NF.example.test/api")
	f.Fuzz(func(t *testing.T, typ, value string) {
		id := Identifier{Type: IdentifierType(typ), Value: value}
		normalized, err := id.Normalize()
		if err != nil {
			p, ok := AsProblem(err)
			if !ok || (p.Type != ErrorUnsupportedIdentifier && p.Type != ErrorMalformed && p.Type != ErrorRejectedIdentifier) {
				t.Fatalf("Normalize returned %v", err)
			}
			return
		}
		again, err := normalized.Normalize()
		if err != nil || again != normalized {
			t.Fatalf("normalization is not idempotent: %v -> %v, %v", normalized, again, err)
		}
		checkNormalized(t, normalized, value)
	})
}

// Fails the test when an accepted identifier breaks the documented syntax of its type.
func checkNormalized(t *testing.T, normalized Identifier, value string) {
	t.Helper()
	switch normalized.Type {
	case IdentifierDNS:
		name := normalized.Value
		if name != strings.ToLower(value) || len(name) > maxDNSNameLength || normalized.IsWildcard() != strings.HasPrefix(name, "*.") {
			t.Fatalf("accepted DNS identifier %q from %q", name, value)
		}
		for label := range strings.SplitSeq(strings.TrimPrefix(name, "*."), ".") {
			if reason := checkDNSLabel(label); reason != "" {
				t.Fatalf("accepted label %q: %s", label, reason)
			}
		}
		if _, err := netip.ParseAddr(strings.TrimPrefix(name, "*.")); err == nil {
			t.Fatalf("accepted IP literal %q as a DNS identifier", name)
		}
	case IdentifierIP:
		address, err := netip.ParseAddr(normalized.Value)
		if err != nil || address.String() != normalized.Value || address.Zone() != "" || address.Is4In6() ||
			address.IsUnspecified() || address.IsMulticast() {
			t.Fatalf("accepted IP identifier %q from %q", normalized.Value, value)
		}
	case IdentifierTNAuthList:
		der, err := base64.RawURLEncoding.Strict().DecodeString(normalized.Value)
		if err != nil || normalized.Value != value || checkTNAuthList(der) != nil {
			t.Fatalf("accepted TNAuthList identifier %q from %q", normalized.Value, value)
		}
	case IdentifierNfInstanceID:
		if normalized.Value != strings.ToLower(value) || len(normalized.Value) != 36 {
			t.Fatalf("accepted NfInstanceId identifier %q from %q", normalized.Value, value)
		}
	case IdentifierURI:
		u, err := url.Parse(normalized.Value)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" ||
			len(normalized.Value) > maxURILength {
			t.Fatalf("accepted uri identifier %q from %q", normalized.Value, value)
		}
	default:
		t.Fatalf("accepted type %q", normalized.Type)
	}
}

// Normalizes granted names and refuses kinds that a certificate request cannot add to an order.
func TestCheckGrant(t *testing.T) {
	grant, err := checkGrant(ValidationGrant{NFType: "AMF", Names: []Identifier{
		{IdentifierDNS, "A.Test"}, {IdentifierDNS, "a.test"}, {IdentifierURI, "HTTPS://A.Test/api"}, {IdentifierIP, "192.0.2.1"},
	}})
	want := []Identifier{{IdentifierDNS, "a.test"}, {IdentifierURI, "https://a.test/api"}, {IdentifierIP, "192.0.2.1"}}
	if err != nil || len(grant.Names) != len(want) || grant.NFType != "AMF" {
		t.Fatalf("checkGrant = %+v, %v", grant, err)
	}
	for i := range want {
		if grant.Names[i] != want[i] {
			t.Fatalf("names = %v, want %v", grant.Names, want)
		}
	}
	for name, bad := range map[string]ValidationGrant{
		"authority list": {Names: []Identifier{{IdentifierTNAuthList, base64.RawURLEncoding.EncodeToString([]byte{0x30, 0x00})}}},
		"instance":       {Names: []Identifier{{IdentifierNfInstanceID, "4ace9d34-2c69-4f99-92d5-a73a3fe8e23b"}}},
		"invalid name":   {Names: []Identifier{{IdentifierDNS, "a..test"}}},
		"invalid type":   {NFType: "A MF"},
	} {
		if _, err := checkGrant(bad); err == nil {
			t.Errorf("checkGrant accepted the %s grant", name)
		}
	}
}
