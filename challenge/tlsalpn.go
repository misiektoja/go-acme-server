package challenge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The application protocol defined by RFC 8737.
const ALPNProtocol = "acme-tls/1"

// Configures TLS-ALPN-01 validation without ordinary website certificate trust.
type TLSALPNOptions struct {
	Network NetworkOptions
	// Overrides destination port 443 for local tests only.
	TestPort int
}

// Checks the negotiated protocol, exact SAN and critical proof extension.
type TLSALPN01 struct {
	network networkPolicy
	port    int
}

// Constructs a TLS-ALPN validator with an immutable egress configuration.
func NewTLSALPN01(options TLSALPNOptions) (*TLSALPN01, error) {
	network, err := newNetwork(options.Network)
	if err != nil {
		return nil, err
	}
	if options.TestPort < 0 || options.TestPort > 65535 {
		return nil, errors.New("challenge: invalid TLS test port")
	}
	port := options.TestPort
	if port == 0 {
		port = 443
	}
	return &TLSALPN01{network: network, port: port}, nil
}

// Validates DNS or IP proof using RFC 8737 and the reverse-mapping SNI rule of RFC 8738.
func (v *TLSALPN01) Validate(ctx context.Context, request acmeserver.ValidationRequest) error {
	id, err := checkRequest(request, acmeserver.ChallengeTLSALPN01)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, v.network.timeout)
	defer cancel()
	connection, err := v.network.dial(ctx, id.Value, v.port)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	sni := id.Value
	if id.Type == acmeserver.IdentifierIP {
		sni = reverseName(netip.MustParseAddr(id.Value))
	}
	client := tls.Client(&limitedConnection{Conn: connection, remaining: 256 << 10}, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: sni, NextProtos: []string{ALPNProtocol},
		InsecureSkipVerify: true, //nolint:gosec // RFC 8737 authenticates the critical proof extension.
		VerifyConnection: func(state tls.ConnectionState) error {
			return checkALPNProof(state, id, request.KeyAuthorization)
		},
	})
	if err := client.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("challenge: TLS validation: %w", err)
	}
	return nil
}

// Bounds TLS bytes before the handshake parser can allocate from an untrusted peer.
type limitedConnection struct {
	net.Conn
	remaining int
}

// Stops reads when the validation handshake exceeds its byte budget.
func (c *limitedConnection) Read(buffer []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, incorrect("TLS handshake exceeds the byte limit")
	}
	n, err := c.Conn.Read(buffer[:min(len(buffer), c.remaining)])
	c.remaining -= n
	return n, err
}

// Checks the RFC 8737 proof without applying ordinary X.509 trust or validity rules.
func checkALPNProof(state tls.ConnectionState, id acmeserver.Identifier, keyAuthorization string) error {
	if state.NegotiatedProtocol != ALPNProtocol || len(state.PeerCertificates) == 0 {
		return incorrect("TLS ALPN was not negotiated")
	}
	cert := state.PeerCertificates[0]
	if err := checkSingleSAN(cert, id); err != nil {
		return err
	}
	expected := sha256.Sum256([]byte(keyAuthorization))
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) {
			continue
		}
		var proof []byte
		rest, err := asn1.Unmarshal(extension.Value, &proof)
		if !extension.Critical || err != nil || len(rest) != 0 || string(proof) != string(expected[:]) {
			return incorrect("TLS proof extension did not match")
		}
		return nil
	}
	return incorrect("TLS proof extension is missing")
}

// Requires one SAN entry of the exact authorized identifier type and value.
func checkSingleSAN(cert *x509.Certificate, id acmeserver.Identifier) error {
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var names []asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &names)
		if err != nil || len(rest) != 0 || len(names) != 1 ||
			names[0].Class != asn1.ClassContextSpecific || names[0].IsCompound {
			return incorrect("TLS certificate must contain exactly one SAN")
		}
		name := names[0]
		if id.Type == acmeserver.IdentifierDNS && name.Tag == 2 && strings.EqualFold(string(name.Bytes), id.Value) {
			return nil
		}
		if id.Type == acmeserver.IdentifierIP && name.Tag == 7 {
			address, ok := netip.AddrFromSlice(name.Bytes)
			if ok && address == netip.MustParseAddr(id.Value) {
				return nil
			}
		}
		return incorrect("TLS certificate SAN did not match")
	}
	return incorrect("TLS certificate SAN is missing")
}

// Returns the reverse-mapping DNS name required for IP challenge SNI.
func reverseName(address netip.Addr) string {
	if address.Is4() {
		b := address.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	b := address.As16()
	digits := hex.EncodeToString(b[:])
	var name strings.Builder
	for i := len(digits) - 1; i >= 0; i-- {
		name.WriteByte(digits[i])
		name.WriteByte('.')
	}
	name.WriteString("ip6.arpa")
	return name.String()
}
