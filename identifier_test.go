package acmeserver

import (
	"errors"
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
