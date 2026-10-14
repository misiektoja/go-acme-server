package acmeserver

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Defaults used when Config leaves a field zero.
const (
	DefaultMaxRequestBody        = 64 << 10
	DefaultOrderLifetime         = 7 * 24 * time.Hour
	DefaultAuthorizationLifetime = 30 * 24 * time.Hour
	DefaultMaxIdentifiers        = 100
	DefaultDetachedWriteTimeout  = 30 * time.Second
)

// Configures Run. Zero values select the defaults.
type WorkerConfig struct {
	// The number of tasks processed at the same time. Defaults to 4.
	Concurrency int
	// How often an idle worker looks for work. Defaults to one second.
	PollInterval time.Duration
	// How long a claimed task stays leased. A task run never continues past its lease, so no other
	// worker can take the task while it runs. It must be at least twice TaskTimeout and defaults to
	// two minutes or twice TaskTimeout, whichever is longer.
	Lease time.Duration
	// Bounds each phase of a task separately: one validator or issuer call and the store
	// operations that record its outcome. A task run uses several of these budgets in
	// sequence within its lease. Defaults to 30 seconds or half the lease, whichever is shorter.
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
	// The URL of the current terms of service.
	TermsOfService string
	// The URL of the CA's website.
	Website string
	// The hostnames the CA recognizes in CAA issue and issuewild records.
	CAAIdentities []string
	// Tells clients that newAccount needs an external account binding.
	ExternalAccountRequired bool
}

// A certificate profile offered to clients, see draft-ietf-acme-profiles. The host decides what a
// profile means and receives the selected name in IssueRequest.Profile.
type Profile struct {
	// The name clients send in the newOrder profile member. It has 1 to 64 ASCII letters, digits,
	// dots, underscores or hyphens and starts with a letter or digit.
	Name string
	// A human-readable description the server publishes as plain text at <BaseURL>profiles/<Name>.
	Description string
	// An absolute https URL of a description published elsewhere. Exactly one of Description and
	// URL is set.
	URL string
}

// Configures a Server. Store, Nonces, Issuer, Revoker and at least one validator are required.
type Config struct {
	// The absolute URL the handler is served under, including any path prefix.
	// It must use https unless AllowInsecureBaseURL is set.
	BaseURL string
	// Accepts an http BaseURL for tests and local examples.
	AllowInsecureBaseURL bool
	// Persists resources and background work.
	Store Store
	// Issues and consumes the single-use request nonces.
	Nonces NonceManager
	// Defaults to the system clock.
	Clock Clock
	// Receives operational events. It defaults to a logger that discards everything.
	Logger *slog.Logger
	// Optional directory metadata. Nothing is advertised when it is empty.
	Meta DirectoryMeta
	// Bounds the size of a request body in bytes. Zero selects DefaultMaxRequestBody.
	MaxRequestBody int64
	// Signs certificates for finalized orders.
	Issuer Issuer
	// Revokes issued certificates.
	Revoker Revoker
	// The RFC 5280 reason codes clients may request. Empty allows unspecified (0),
	// keyCompromise (1), affiliationChanged (3), superseded (4) and cessationOfOperation (5).
	// Only 0 to 5, 9 and 10 may be listed, because an ACME revocation is final and cannot be a
	// certificateHold (6).
	RevocationReasons []int
	// Learns about authenticated finalize and revokeCert requests the server refuses. Optional.
	Refusals RefusalRecorder
	// Limits how often clients may get nonces, create accounts and place orders. Optional. Without
	// it nothing is limited.
	Limits Limiter
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
	// Accepts TNAuthList identifiers as specified in RFC 9448. It needs a tkauth-01 validator.
	TNAuthListIdentifiers bool
	// Lets a certificate issued for a TNAuthList identifier outlive the Authority Token, as
	// ATIS-1000080 clause 6.3.8 specifies for STIR/SHAKEN. The token must still be valid when
	// signing starts. By default the token expiry bounds the certificate, as RFC 9447 section 7
	// recommends.
	TNAuthListCertificatesOutliveTokens bool
	// Accepts NfInstanceId identifiers of 5G network functions as described in 3GPP TS 33.310
	// Annex J. It needs a tkauth-01 validator.
	NfInstanceIDIdentifiers bool
	// The https URL offered as token-authority on tkauth-01 challenges, see RFC 9447 section 3.
	// It is optional, and clients fall back to their own configuration when it is empty.
	TokenAuthority string
	// How long a new order and its pending authorizations stay valid.
	OrderLifetime time.Duration
	// How long a validated authorization stays valid.
	AuthorizationLifetime time.Duration
	// Bounds the identifiers of one order.
	MaxIdentifiers int
	// Bounds a store write that has to finish after the client request it belongs to has ended,
	// such as recording a revocation the Revoker already carried out. Zero selects
	// DefaultDetachedWriteTimeout.
	DetachedWriteTimeout time.Duration
	// The certificate profiles advertised in the directory meta and accepted on new orders, see
	// draft-ietf-acme-profiles. Empty leaves the extension off. A new order that names a profile is
	// then refused with invalidProfile.
	Profiles []Profile
	// The profile an order gets when the client names none. It is required when Profiles is set
	// and must be one of them.
	DefaultProfile string
	// Serves RFC 9773 renewal information and accepts replaces on new orders when set.
	// LifetimeRenewal is the built-in advisor. Nil leaves the extension off.
	RenewalInfo RenewalAdvisor
	// Tunes Run and Ready.
	Workers WorkerConfig
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
	case u.Scheme == schemeHTTPS:
	case u.Scheme == "http" && allowInsecure:
	case u.Scheme == "http":
		return nil, errors.New("acmeserver: Config.BaseURL must use https unless AllowInsecureBaseURL is set")
	default:
		return nil, errors.New("acmeserver: Config.BaseURL must be an absolute http or https URL")
	}
	// Signed request URLs are compared in escaped form, so a path that needs escaping could never match.
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.EscapedPath() != u.Path ||
		u.Opaque != "" {
		return nil, errors.New("acmeserver: Config.BaseURL must have a host and no user info, query, fragment " +
			"or path that needs percent-encoding")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u, nil
}

// The URL scheme that base URLs, profile URLs and uri identifiers use.
const schemeHTTPS = "https"

// Reports whether raw is an absolute https URL without user info or a fragment.
func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == schemeHTTPS && u.Host != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}

// Bounds a profile name so it stays short in URLs and order objects.
const maxProfileNameLength = 64

// Checks the profile names, descriptions and default of a Config.
func validateProfiles(profiles []Profile, defaultProfile string) error {
	if len(profiles) == 0 {
		if defaultProfile != "" {
			return errorf("Config.DefaultProfile needs Config.Profiles")
		}
		return nil
	}
	seen := make(map[string]bool, len(profiles))
	for _, p := range profiles {
		switch {
		case !validProfileName(p.Name):
			return errorf("Config.Profiles has the invalid name " + strconv.Quote(p.Name))
		case seen[p.Name]:
			return errorf("Config.Profiles names " + p.Name + " twice")
		case (p.Description == "") == (p.URL == ""):
			return errorf("Config.Profiles[" + p.Name + "] needs exactly one of Description and URL")
		case p.URL != "" && !isHTTPSURL(p.URL):
			return errorf("Config.Profiles[" + p.Name + "].URL must be an absolute https URL")
		case p.Description != "" && !utf8.ValidString(p.Description):
			return errorf("Config.Profiles[" + p.Name + "].Description must be valid UTF-8")
		}
		seen[p.Name] = true
	}
	if !seen[defaultProfile] {
		return errorf("Config.DefaultProfile must name one of Config.Profiles")
	}
	return nil
}

// Reports whether name is usable as a profile name. The character set keeps names safe in a URL
// path and in clients that parse the directory loosely.
func validProfileName(name string) bool {
	if name == "" || len(name) > maxProfileNameLength {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || c != '.' && c != '_' && c != '-') {
			return false
		}
	}
	return true
}
