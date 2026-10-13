package challenge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Requires a retryable failure that reports the given problem type once attempts run out.
func assertRetryable(t *testing.T, err error, want acmeserver.ErrorType) {
	t.Helper()
	if _, terminal := acmeserver.AsProblem(err); terminal {
		t.Fatalf("error %v ended validation at once, want a retryable %s failure", err, want)
	}
	retryable, ok := errors.AsType[*acmeserver.RetryableError](err)
	if !ok || retryable.Problem == nil || retryable.Problem.Type != want {
		t.Fatalf("error %v, want a retryable %s failure", err, want)
	}
}

// Returns a TCP port on which nothing listens any more.
func closedPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listenerPort(t, listener.Addr())
	_ = listener.Close()
	return port
}

// Reports refused and silent HTTP destinations as connection problems after the retries.
func TestHTTPTransportFailuresAreConnectionProblems(t *testing.T) {
	request := proofRequest(acmeserver.ChallengeHTTP01, "a.test")
	t.Run("refused", func(t *testing.T) {
		validator, err := NewHTTP01(HTTPOptions{Network: localNetwork(), TestPort: closedPort(t)})
		if err != nil {
			t.Fatal(err)
		}
		assertRetryable(t, validator.Validate(t.Context(), request), acmeserver.ErrorConnection)
	})
	t.Run("silent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer server.Close()
		network := localNetwork()
		network.Timeout = 100 * time.Millisecond
		validator, err := NewHTTP01(HTTPOptions{Network: network, TestPort: listenerPort(t, server.Listener.Addr())})
		if err != nil {
			t.Fatal(err)
		}
		assertRetryable(t, validator.Validate(t.Context(), request), acmeserver.ErrorConnection)
	})
}

// Reports a destination that does not complete a TLS handshake as a TLS problem after the retries.
func TestTLSALPNHandshakeFailureIsATLSProblem(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = connection.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			_ = connection.Close()
		}
	}()
	validator, err := NewTLSALPN01(TLSALPNOptions{Network: localNetwork(), TestPort: listenerPort(t, listener.Addr())})
	if err != nil {
		t.Fatal(err)
	}
	err = validator.Validate(t.Context(), proofRequest(acmeserver.ChallengeTLSALPN01, "a.test"))
	assertRetryable(t, err, acmeserver.ErrorTLS)
}

// Reports a TLS-ALPN destination that refuses connections as a connection problem.
func TestTLSALPNRefusedIsAConnectionProblem(t *testing.T) {
	validator, err := NewTLSALPN01(TLSALPNOptions{Network: localNetwork(), TestPort: closedPort(t)})
	if err != nil {
		t.Fatal(err)
	}
	err = validator.Validate(t.Context(), proofRequest(acmeserver.ChallengeTLSALPN01, "a.test"))
	assertRetryable(t, err, acmeserver.ErrorConnection)
}

// A TXT resolver that always fails the way a host resolver reports a missing name.
type failingTXTResolver struct{}

// Returns the error net.Resolver gives for NXDOMAIN.
func (failingTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: "_acme-challenge.a.test", IsNotFound: true}
}

// Reports a failing custom TXT resolver as a retryable DNS problem rather than serverInternal.
func TestDNS01ResolverErrorIsADNSProblem(t *testing.T) {
	validator, err := NewDNS01(DNSOptions{Resolver: failingTXTResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	err = validator.Validate(t.Context(), proofRequest(acmeserver.ChallengeDNS01, "a.test"))
	assertRetryable(t, err, acmeserver.ErrorDNS)
}

// Reports a destination name that cannot be resolved as a DNS problem.
func TestUnresolvableDestinationIsADNSProblem(t *testing.T) {
	network := localNetwork()
	network.Resolver = ipResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "a.test", IsNotFound: true}
	})
	validator, err := NewHTTP01(HTTPOptions{Network: network})
	if err != nil {
		t.Fatal(err)
	}
	err = validator.Validate(t.Context(), proofRequest(acmeserver.ChallengeHTTP01, "a.test"))
	assertRetryable(t, err, acmeserver.ErrorDNS)
}
