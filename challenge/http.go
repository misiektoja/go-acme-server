package challenge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Configures bounded HTTP-01 validation as specified by RFC 8555 section 8.3.
type HTTPOptions struct {
	Network NetworkOptions
	// Overrides destination port 80 for local tests only.
	TestPort int
	// Bounds redirects and defaults to ten.
	MaxRedirects int
	// Bounds the proof body and defaults to 4096 bytes.
	MaxResponseBytes int64
}

// Validates HTTP-01 proofs without proxies or uncontrolled destination lookups.
type HTTP01 struct {
	network   networkPolicy
	testPort  int
	redirects int
	maxBody   int64
}

// Constructs an HTTP validator with an immutable egress configuration.
func NewHTTP01(options HTTPOptions) (*HTTP01, error) {
	network, err := newNetwork(options.Network)
	if err != nil {
		return nil, err
	}
	if options.TestPort < 0 || options.TestPort > 65535 || options.MaxRedirects < 0 || options.MaxResponseBytes < 0 {
		return nil, errors.New("challenge: HTTP limits are invalid")
	}
	if options.MaxRedirects == 0 {
		options.MaxRedirects = 10
	}
	if options.MaxResponseBytes == 0 {
		options.MaxResponseBytes = 4096
	}
	return &HTTP01{network: network, testPort: options.TestPort,
		redirects: options.MaxRedirects, maxBody: options.MaxResponseBytes}, nil
}

// Fetches and compares the proof through bounded HTTP or HTTPS redirects on ports 80 and 443.
func (v *HTTP01) Validate(ctx context.Context, request acmeserver.ValidationRequest) error {
	id, err := checkRequest(request, acmeserver.ChallengeHTTP01)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, v.network.timeout)
	defer cancel()
	host := id.Value
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	target := &url.URL{Scheme: "http", Host: host, Path: "/.well-known/acme-challenge/" + request.Challenge.Token}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10,
		DialContext: v.dial,
		// HTTPS redirects authenticate the challenge proof instead of the existing website certificate.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: true}, //nolint:gosec // The key authorization authenticates the response.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > v.redirects {
			return incorrect("HTTP redirect limit exceeded")
		}
		return checkHTTPURL(req.URL)
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("challenge: HTTP validation: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return incorrect("HTTP challenge response was not 200")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, v.maxBody+1))
	if err != nil {
		return fmt.Errorf("challenge: HTTP proof read: %w", err)
	}
	if int64(len(body)) > v.maxBody || strings.TrimRight(string(body), " \t\r\n") != request.KeyAuthorization {
		return incorrect("HTTP challenge proof did not match")
	}
	return nil
}

// Enforces the redirect scheme, authority and destination port policy before dialing.
func checkHTTPURL(target *url.URL) error {
	if (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil ||
		target.Opaque != "" || target.Fragment != "" {
		return incorrect("HTTP redirect target is not permitted")
	}
	port := target.Port()
	if port != "" && port != "80" && port != "443" {
		return incorrect("HTTP redirect port is not permitted")
	}
	return nil
}

// Resolves and checks the hostname again for every new connection.
func (v *HTTP01) dial(ctx context.Context, _ string, address string) (net.Conn, error) {
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || (port != 80 && port != 443) {
		return nil, incorrect("HTTP destination port is not permitted")
	}
	if v.testPort != 0 && port == 80 {
		port = v.testPort
	}
	return v.network.dial(ctx, host, port)
}
