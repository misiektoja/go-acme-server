package challenge

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Gives a healthy fallback time to answer after transport failures and missing-name answers.
func TestResolverFailover(t *testing.T) {
	for _, mode := range []string{"silent", "refused", "SERVFAIL", "NXDOMAIN"} {
		t.Run(mode, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			primary := dnsServer(t, func(message *dnsmessage.Message) {
				switch mode {
				case "silent":
					<-release
				case "SERVFAIL":
					message.RCode = dnsmessage.RCodeServerFailure
				case "NXDOMAIN":
					message.RCode = dnsmessage.RCodeNameError
				}
			})
			if mode == "refused" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				primary = netip.MustParseAddrPort(listener.Addr().String())
				listener.Close()
			}
			var queries atomic.Int32
			backup := dnsServer(t, func(message *dnsmessage.Message) {
				queries.Add(1)
				message.Answers = []dnsmessage.Resource{
					dnsRecord(message.Questions[0].Name.String(), dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: []string{"proof"}}),
				}
			})
			resolver, err := NewResolver(ResolverOptions{Servers: []netip.AddrPort{primary, backup}, Timeout: 500 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			values, err := resolver.LookupTXT(t.Context(), "_acme-challenge.a.test")
			if err != nil || len(values) != 1 || values[0] != "proof" || queries.Load() != 1 {
				t.Fatalf("fallback: TXT=%v error=%v backup queries=%d", values, err, queries.Load())
			}
		})
	}
}

// Reports a name missing on every server as a retryable DNS failure, because a new TXT record
// may not have reached the resolvers yet.
func TestResolverMissingNameIsRetryable(t *testing.T) {
	missing := func(message *dnsmessage.Message) { message.RCode = dnsmessage.RCodeNameError }
	resolver, err := NewResolver(ResolverOptions{Servers: []netip.AddrPort{dnsServer(t, missing), dnsServer(t, missing)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.LookupTXT(t.Context(), "_acme-challenge.a.test")
	if _, terminal := acmeserver.AsProblem(err); terminal {
		t.Fatalf("missing name ended validation at once: %v", err)
	}
	retryable, ok := errors.AsType[*acmeserver.RetryableError](err)
	if !ok || retryable.Problem.Type != acmeserver.ErrorDNS {
		t.Fatalf("missing name error = %v, want a retryable dns problem", err)
	}
}

// Shares the caller's shorter deadline across all silent endpoints.
func TestResolverFailoverDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var queries atomic.Int32
	servers := make([]netip.AddrPort, 3)
	for i := range servers {
		servers[i] = dnsServer(t, func(*dnsmessage.Message) {
			queries.Add(1)
			<-release
		})
	}
	resolver, err := NewResolver(ResolverOptions{Servers: servers, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const budget = 600 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	start := time.Now()
	_, err = resolver.LookupTXT(ctx, "_acme-challenge.a.test")
	if err == nil || queries.Load() != 3 || time.Since(start) > 2*budget {
		t.Fatalf("bounded failover: error=%v queries=%d elapsed=%v", err, queries.Load(), time.Since(start))
	}
}

// Cancellation stops an active exchange without contacting a fallback.
func TestResolverFailoverCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	primary := dnsServer(t, func(*dnsmessage.Message) {
		cancel()
		<-release
	})
	var queries atomic.Int32
	backup := dnsServer(t, func(*dnsmessage.Message) { queries.Add(1) })
	resolver, err := NewResolver(ResolverOptions{Servers: []netip.AddrPort{primary, backup}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = resolver.LookupTXT(ctx, "_acme-challenge.a.test")
	if !errors.Is(err, context.Canceled) || queries.Load() != 0 || time.Since(start) > time.Second {
		t.Fatalf("canceled lookup: error=%v backup queries=%d elapsed=%v", err, queries.Load(), time.Since(start))
	}
}
