package acmeserver

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// Bounds request bodies when Config.MaxRequestBody is zero.
const DefaultMaxRequestBody = 64 << 10

// The optional metadata object of the directory, see RFC 8555 section 7.1.1.
type DirectoryMeta struct {
	TermsOfService          string
	Website                 string
	CAAIdentities           []string
	ExternalAccountRequired bool
}

// Configures a Server. Store and Nonces are required.
type Config struct {
	// The absolute URL the handler is served under, including any path prefix.
	// It must use https unless AllowInsecureBaseURL is set.
	BaseURL string
	// Accepts an http BaseURL for tests and local examples.
	AllowInsecureBaseURL bool
	Store                Store
	Nonces               NonceManager
	// Defaults to the system clock.
	Clock Clock
	// Receives operational events. It defaults to a logger that discards everything.
	Logger *slog.Logger
	Meta   DirectoryMeta
	// Bounds the size of a request body in bytes. Zero selects DefaultMaxRequestBody.
	MaxRequestBody int64
}

// Validates the base URL and returns it with a trailing slash.
func normalizeBaseURL(raw string, allowInsecure bool) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("acmeserver: Config.BaseURL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("acmeserver: Config.BaseURL: %w", err)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowInsecure:
	case u.Scheme == "http":
		return nil, errors.New("acmeserver: Config.BaseURL must use https unless AllowInsecureBaseURL is set")
	default:
		return nil, errors.New("acmeserver: Config.BaseURL must be an absolute http or https URL")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" {
		return nil, errors.New("acmeserver: Config.BaseURL must have a host and no user info, query, fragment " +
			"or escaped path")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u, nil
}
