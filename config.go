package acmeserver

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// Defaults used when Config leaves a field zero.
const (
	DefaultMaxRequestBody        = 64 << 10
	DefaultOrderLifetime         = 7 * 24 * time.Hour
	DefaultAuthorizationLifetime = 30 * 24 * time.Hour
	DefaultMaxIdentifiers        = 100
)

// Configures Run. Zero values select the defaults.
type WorkerConfig struct {
	// The number of tasks processed at the same time. Defaults to 4.
	Concurrency int
	// How often an idle worker looks for work. Defaults to one second.
	PollInterval time.Duration
	// How long a claimed task stays leased. Defaults to two minutes.
	Lease time.Duration
	// The time limit of one validator or issuer call. Defaults to 30 seconds.
	TaskTimeout time.Duration
	// Limits validation and pre-dispatch policy retries to five by default without limiting issuance recovery.
	MaxAttempts int
	// The first retry delay, doubled on every further attempt. Defaults to five seconds.
	RetryDelay time.Duration
	// How long accepted work may wait unclaimed before Ready reports a problem. Defaults to
	// one minute.
	StaleAfter time.Duration
	// Marks that another process runs Run against the same store, which silences the warning
	// logged when work is accepted while Run is inactive here.
	External bool
}

// The optional metadata object of the directory, see RFC 8555 section 7.1.1.
type DirectoryMeta struct {
	TermsOfService          string
	Website                 string
	CAAIdentities           []string
	ExternalAccountRequired bool
}

// Configures a Server. Store, Nonces, Issuer, Revoker and at least one validator are required.
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
	Issuer         Issuer
	Revoker        Revoker
	// The challenge types offered to clients. Only configured types appear in authorizations.
	Validators map[ChallengeType]Validator
	// Verifies external account bindings. Required when Meta.ExternalAccountRequired is set.
	ExternalAccounts ExternalAccountKeys
	// Binds each external account key identifier to at most one account. The claim is committed
	// with the account, and a later newAccount with the same identifier and another key is refused.
	SingleUseExternalAccounts bool
	// Reviews new accounts and orders. Defaults to AllowAll.
	Policy Policy
	// Reviews current issuance policy before dispatch, with the accepted CSR and validation evidence.
	IssuancePolicy IssuancePolicy
	// Refuses new accounts that do not agree to Meta.TermsOfService.
	RequireTermsOfServiceAgreed bool
	// Accepts IP identifiers as specified in RFC 8738.
	IPIdentifiers bool
	// How long a new order and its pending authorizations stay valid.
	OrderLifetime time.Duration
	// How long a validated authorization stays valid.
	AuthorizationLifetime time.Duration
	// Bounds the identifiers of one order.
	MaxIdentifiers int
	Workers        WorkerConfig
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
