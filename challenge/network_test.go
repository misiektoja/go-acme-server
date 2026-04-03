package challenge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Rejects unsupported identifier scopes and malformed proofs before contacting a resolver.
func TestRequestValidationBeforeNetwork(t *testing.T) {
	network := localNetwork()
	network.Resolver = ipResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("unexpected lookup")
		return nil, nil
	})
	validator, err := NewHTTP01(HTTPOptions{Network: network})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*acmeserver.ValidationRequest){
		func(r *acmeserver.ValidationRequest) { r.Wildcard = true },
		func(r *acmeserver.ValidationRequest) { r.Identifier.Value = "*.a.test" },
		func(r *acmeserver.ValidationRequest) { r.Challenge.Type = acmeserver.ChallengeDNS01 },
		func(r *acmeserver.ValidationRequest) { r.Challenge.Token = "../other" },
		func(r *acmeserver.ValidationRequest) { r.AccountKeyThumbprint = "" },
		func(r *acmeserver.ValidationRequest) { r.KeyAuthorization += "x" },
	} {
		request := proofRequest(acmeserver.ChallengeHTTP01, "a.test")
		mutate(&request)
		if err := validator.Validate(t.Context(), request); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

// Enforces address bounds and denies special destinations even when a resolver returns mapped IPv4.
func TestDestinationBounds(t *testing.T) {
	for _, addresses := range [][]netip.Addr{
		nil, {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("::ffff:169.254.169.254")}, {netip.MustParseAddr("fe80::1%en0")},
		{netip.MustParseAddr("::1")}, {netip.Addr{}},
	} {
		network := localNetwork()
		network.MaxAddresses = 1
		network.Resolver = ipResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil })
		policy, err := newNetwork(network)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := policy.resolve(t.Context(), "a.test"); err == nil {
			t.Fatalf("addresses accepted: %v", addresses)
		}
	}
}

// Sends an IP identifier directly with the required Host field and no DNS lookup.
func TestHTTPIP(t *testing.T) {
	request := proofRequest(acmeserver.ChallengeHTTP01, "127.0.0.1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "127.0.0.1" {
			t.Errorf("Host = %q", r.Host)
		}
		w.Write([]byte(request.KeyAuthorization))
	}))
	defer server.Close()
	network := localNetwork()
	network.Resolver = ipResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("IP performed DNS lookup")
		return nil, nil
	})
	validator, err := NewHTTP01(HTTPOptions{Network: network, TestPort: listenerPort(t, server.Listener.Addr())})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(t.Context(), request); err != nil {
		t.Fatal(err)
	}
}

// Cancels a stalled TLS peer within the complete validation deadline.
func TestTLSHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 4096)
		for {
			if _, err := connection.Read(buffer); err != nil {
				return
			}
		}
	}()
	network := localNetwork()
	network.Timeout = 50 * time.Millisecond
	validator, err := NewTLSALPN01(TLSALPNOptions{Network: network, TestPort: listenerPort(t, listener.Addr())})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := validator.Validate(t.Context(), proofRequest(acmeserver.ChallengeTLSALPN01, "a.test")); err == nil {
		t.Fatal("stalled TLS peer accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("TLS attempt exceeded its deadline")
	}
	<-done
}

// Rejects invalid constructor limits instead of leaving unbounded or unusable validators.
func TestInvalidOptions(t *testing.T) {
	if _, err := NewHTTP01(HTTPOptions{}); err == nil {
		t.Fatal("missing resolver accepted")
	}
	if _, err := NewHTTP01(HTTPOptions{Network: localNetwork(), TestPort: 65536}); err == nil {
		t.Fatal("invalid port accepted")
	}
	if _, err := NewTLSALPN01(TLSALPNOptions{Network: localNetwork(), TestPort: -1}); err == nil {
		t.Fatal("negative port accepted")
	}
	if _, err := NewDNS01(DNSOptions{}); err == nil {
		t.Fatal("missing TXT resolver accepted")
	}
	if _, err := NewResolver(ResolverOptions{Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, MaxResponseBytes: 65536}); err == nil {
		t.Fatal("oversized DNS limit accepted")
	}
	network := localNetwork()
	network.AllowedNetworks = []netip.Prefix{netip.MustParsePrefix("::ffff:127.0.0.1/128")}
	if _, err := newNetwork(network); err == nil {
		t.Fatal("mapped network prefix accepted")
	}
	if base64URL(strings.Repeat("A", 22) + "=") {
		t.Fatal("padded token accepted")
	}
}
