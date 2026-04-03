package challenge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Resolves test hostnames without consulting external DNS.
type ipResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

// Calls the selected test resolver.
func (f ipResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

// Returns a complete captured proof for a normalized test identifier.
func proofRequest(typ acmeserver.ChallengeType, name string) acmeserver.ValidationRequest {
	thumb := strings.Repeat("A", 43)
	token := strings.Repeat("B", 43)
	id := acmeserver.Identifier{Type: acmeserver.IdentifierDNS, Value: name}
	if _, err := netip.ParseAddr(name); err == nil {
		id.Type = acmeserver.IdentifierIP
	}
	return acmeserver.ValidationRequest{Identifier: id, Challenge: acmeserver.Challenge{Type: typ, Token: token},
		AccountKeyThumbprint: thumb, KeyAuthorization: token + "." + thumb}
}

// Allows only the exact local test listener address in addition to public addresses.
func localNetwork() NetworkOptions {
	return NetworkOptions{Resolver: ipResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}), AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Timeout: time.Second}
}

// Extracts a listener's numeric port.
func listenerPort(t *testing.T, address net.Addr) int {
	t.Helper()
	_, raw, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// Fetches a real local proof while preserving the original host and ignoring environment proxies.
func TestHTTPProofAndRedirect(t *testing.T) {
	request := proofRequest(acmeserver.ChallengeHTTP01, "a.test")
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Host != "a.test" {
			t.Errorf("Host = %q", r.Host)
		}
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			http.Redirect(w, r, "/proof", http.StatusFound)
			return
		}
		fmt.Fprint(w, request.KeyAuthorization+" \t\r\n")
	}))
	defer server.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	validator, err := NewHTTP01(HTTPOptions{Network: localNetwork(), TestPort: listenerPort(t, server.Listener.Addr())})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("requests = %d", hits.Load())
	}
}

// Rejects incorrect bodies, unsafe redirects and slow or oversized responses from local servers.
func TestHTTPNegativeProofs(t *testing.T) {
	request := proofRequest(acmeserver.ChallengeHTTP01, "a.test")
	for _, name := range []string{"wrong", "leading whitespace", "large", "status", "loop", "port", "scheme", "credentials", "timeout"} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "wrong":
					fmt.Fprint(w, "wrong")
				case "leading whitespace":
					fmt.Fprint(w, " "+request.KeyAuthorization)
				case "large":
					fmt.Fprint(w, strings.Repeat("x", 5000))
				case "status":
					w.WriteHeader(http.StatusNotFound)
				case "loop":
					http.Redirect(w, r, "/loop", http.StatusFound)
				case "port":
					http.Redirect(w, r, "http://a.test:1234/proof", http.StatusFound)
				case "scheme":
					http.Redirect(w, r, "ftp://a.test/proof", http.StatusFound)
				case "credentials":
					http.Redirect(w, r, "http://user@a.test/proof", http.StatusFound)
				case "timeout":
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			network := localNetwork()
			network.Timeout = 100 * time.Millisecond
			validator, err := NewHTTP01(HTTPOptions{Network: network, TestPort: listenerPort(t, server.Listener.Addr()), MaxRedirects: 2})
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.Validate(t.Context(), request); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}

// Rechecks redirect destinations and refuses a DNS answer containing any denied address.
func TestHTTPRebindingAndMixedAnswers(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(strconv.FormatBool(mixed), func(t *testing.T) {
			var lookups, hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				http.Redirect(w, r, "/redirect", http.StatusFound)
			}))
			defer server.Close()
			network := localNetwork()
			network.Resolver = ipResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				n := lookups.Add(1)
				if mixed {
					return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::ffff:169.254.169.254")}, nil
				}
				if n > 1 {
					return []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.2")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			})
			validator, err := NewHTTP01(HTTPOptions{Network: network, TestPort: listenerPort(t, server.Listener.Addr())})
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.Validate(t.Context(), proofRequest(acmeserver.ChallengeHTTP01, "a.test")); err == nil {
				t.Fatal("denied destination accepted")
			}
			want := int32(1)
			if mixed {
				want = 0
			}
			if hits.Load() != want {
				t.Fatalf("requests = %d, want %d", hits.Load(), want)
			}
		})
	}
}

// Checks special-purpose IPv4, IPv6 and mapped-address exclusions.
func TestPublicAddress(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "192.0.2.1",
		"192.31.196.1", "192.52.193.1", "192.175.48.1",
		"198.18.0.1", "240.0.0.1", "::ffff:127.0.0.1", "fe80::1", "fc00::1", "2001:db8::1", "2002:7f00:1::", "3fff::1"} {
		if PublicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("special address allowed: %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !PublicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("public address denied: %s", raw)
		}
	}
}
