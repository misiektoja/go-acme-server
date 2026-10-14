package acmeserver

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
)

// Names the request a Limiter is asked about.
type LimitKind string

// The requests a Limiter is asked about. More kinds may be added, so a Limiter should allow kinds
// it does not know.
const (
	// A newNonce request. LimitRequest.Account is nil.
	LimitNewNonce LimitKind = "newNonce"
	// A newAccount request that creates an account, asked after the contacts, the terms of service
	// agreement and any external account binding were checked. A request for an existing account
	// is not asked about.
	LimitNewAccount LimitKind = "newAccount"
	// A newOrder request, asked after its identifiers, profile and replaces member were checked and
	// before Policy.NewOrder.
	LimitNewOrder LimitKind = "newOrder"
)

// Describes a request a Limiter may refuse. The Limiter must not change Account.
type LimitRequest struct {
	Kind LimitKind
	// The address of the client connection, taken from http.Request.RemoteAddr with IPv4-mapped
	// IPv6 addresses unmapped. It is the zero Addr when RemoteAddr holds no IP address. Forwarded
	// headers are never read, because any client can set them. A host behind a trusted reverse
	// proxy can rewrite RemoteAddr before the request reaches the handler.
	Client netip.Addr
	// For newAccount the account the request would create, not yet stored. For newOrder the
	// account requesting the order.
	Account *Account
	// The normalized identifiers of a new order.
	Identifiers []Identifier
	// The certificate a new order replaces, checked against the account and the identifiers as
	// RFC 9773 section 5 requires. Empty when the order replaces nothing.
	Replaces string
}

// Limits how often clients may get nonces, create accounts and place orders. Allow is asked once
// for each such request and should count the request when it returns nil. A returned *Problem is
// sent to the client, normally rateLimited with WithRetryAfter so the client knows when to try
// again. Any other error is logged and answered with serverInternal, so a host that prefers to
// serve clients while its limit store is unavailable returns nil instead.
type Limiter interface {
	Allow(ctx context.Context, req LimitRequest) error
}

// Asks the Limiter about a request. It returns nil when no Limiter is configured.
func (s *Server) checkLimit(ctx context.Context, req LimitRequest) *Problem {
	if s.limits == nil {
		return nil
	}
	req.Identifiers = slices.Clone(req.Identifiers)
	return s.hostProblem(ctx, s.limits.Allow(ctx, req), "rate limit check")
}

// Returns the address of the client connection. It is the zero Addr when RemoteAddr holds none.
func clientAddr(r *http.Request) netip.Addr {
	if addrPort, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return addrPort.Addr().Unmap()
	}
	if addr, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return addr.Unmap()
	}
	return netip.Addr{}
}
