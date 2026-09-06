# go-acme-server

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-acme-server?style=flat-square&color=blue)](https://github.com/misiektoja/go-acme-server/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-acme-server.svg)](https://pkg.go.dev/github.com/misiektoja/go-acme-server)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-acme-server/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-acme-server/actions/workflows/test.yml)
[![Interoperability](https://github.com/misiektoja/go-acme-server/actions/workflows/interop.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-acme-server/actions/workflows/interop.yml)
[![Supply chain](https://github.com/misiektoja/go-acme-server/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-acme-server/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-acme-server&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-acme-server)

go-acme-server is a Go library for embedding an ACME server into CA and PKI applications.

The library owns the protocol: accounts, orders, authorizations, challenges, finalization,
certificate retrieval and revocation as specified in RFC 8555. The host application supplies the
parts that differ between deployments:

* a `Store` that persists resources and background work, with `memstore` for tests and examples
* an `Issuer` and a `Revoker` that call the host CA
* one `Validator` per challenge type, with HTTP-01, DNS-01, TLS-ALPN-01 and tkauth-01
  implementations in `challenge`
* optional policy hooks, external account binding keys and directory metadata

## Scope

| Standard | Coverage | Enabled by |
| --- | --- | --- |
| RFC 8555 ACME | Accounts, external account binding, key rollover, orders, HTTP-01, DNS-01, finalization, certificates, revocation | Always |
| RFC 8737 TLS-ALPN-01 | Challenge validation | A `ChallengeTLSALPN01` validator |
| RFC 8738 IP identifiers | IPv4 and IPv6 identifiers through HTTP-01 and TLS-ALPN-01 | `Config.IPIdentifiers` |
| RFC 9447 and RFC 9448 | tkauth-01 with TNAuthList identifiers | `Config.TNAuthListIdentifiers` |
| RFC 9773 | Renewal information and `replaces` | `Config.RenewalInfo` |

Account keys may use ES256, ES384, ES512, RS256 or EdDSA. External account bindings use HS256, HS384 or
HS512. Independent clients verify the behavior in the [interoperability module](test/interop/README.md).
The API may still change before v1.0.0 as described in the
[compatibility policy](CONTRIBUTING.md#compatibility).

### Limitations

* No pre-authorization. The directory omits `newAuthz` and every order receives fresh
  authorizations, so clients validate each identifier again for every order.
* No alternate chains. The certificate response carries one chain and no `rel="alternate"` link.
* No certificate profiles, `dns-account-01`, short-term automatic renewal, delegation, subdomain
  authorizations or email, onion and device identifiers. Working group drafts are not exposed in
  the public API.
* No rate limits. `Policy` and `IssuancePolicy` are the places to refuse accounts, orders or
  issuance.
* No TLS termination or CA. The host serves the handler behind its HTTPS origin, signs with its
  own CA and supplies durable storage. `memstore` keeps everything in memory.

## Getting started

Create a `Server`, mount it under its base URL and run its worker. Both the handler and `Run` are
required. Without `Run`, challenges are never validated and orders are never issued. `Ready`
reports work that has waited too long for a worker.

```go
srv, err := acmeserver.New(acmeserver.Config{
	BaseURL:    "https://ca.example.com/acme/",
	Store:      memstore.New(),
	Nonces:     nonce.New(nonce.Options{}),
	Issuer:     myCA,
	Revoker:    myCA,
	Validators: map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: myHTTP01},
})
if err != nil {
	log.Fatal(err)
}
go srv.Run(ctx)
http.Handle("/acme/", srv)
```

`BaseURL` must use https unless `AllowInsecureBaseURL` is set for local tests. Signed request URLs
must match it exactly, so run the handler behind the public origin it advertises.

The complete example is in `example_test.go`. Host store adapters can check their implementation
with the `storetest` package.

## Network validators

Configure resolver endpoints explicitly. This example uses a documentation address that the host
must replace with its recursive DNS resolver:

```go
resolver, err := challenge.NewResolver(challenge.ResolverOptions{
	Servers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")},
})
if err != nil {
	log.Fatal(err)
}
http01, err := challenge.NewHTTP01(challenge.HTTPOptions{
	Network: challenge.NetworkOptions{Resolver: resolver},
})
if err != nil {
	log.Fatal(err)
}
```

Register `http01` as the `ChallengeHTTP01` validator. `NewDNS01` takes the resolver through
`DNSOptions` and `NewTLSALPN01` takes the same `NetworkOptions` as HTTP-01. Custom resolvers must
honor context cancellation and bound their work.

The default egress policy allows public unicast destinations and denies special-purpose ranges.
`AllowedNetworks` adds explicit exceptions for private deployments. Every resolved address must
pass the policy, including IPv4-mapped addresses. Resolver access is separate from this policy.

Every validator bounds its network work. HTTP-01 ignores environment proxies, follows at most ten
redirects to HTTP or HTTPS on ports 80 and 443, rechecks each destination against the policy and
reads a 4096-byte proof. It accepts HTTPS redirects without a trusted website certificate. TLS-ALPN-01
checks the negotiated protocol, one matching SAN and the critical proof extension within a 256 KiB
handshake. The supplied resolver uses TCP and caps endpoints, CNAME hops, records and message
size. DNS-01 accepts any matching TXT record, so a wildcard and its base domain can be proved at
the same time. Each attempt times out after ten seconds by default. Transport failures are retried
and incorrect proofs are final. The option types document every limit.

`HTTPOptions.TestPort` and `TLSALPNOptions.TestPort` override destination ports 80 and 443 for
tests only. IP identifiers are validated through HTTP-01 or TLS-ALPN-01, never DNS-01.

## Authority Token challenges

`tkauth-01` proves authority over a list of telephone numbers instead of control of a network
resource. Enable it with `Config.TNAuthListIdentifiers` and a `ChallengeTKAuth01` validator. Orders
then accept one identifier of type `TNAuthList` whose value is the unpadded base64url encoding of a
DER `TNAuthorizationList` from RFC 8226. That identifier is offered `tkauth-01` alone and every other
identifier type keeps the network challenges.

A client answers the challenge with the Authority Token in a `tkauth` payload member. The validator
checks the token against the challenge identifier and the responding account key. It never fetches
the `x5u` URL. Trusting a Token Authority is a deployment decision, so the header reference goes to
a `TokenAuthorities` implementation that returns the certificate whose key must have signed the
token. `StaticTokenAuthorities` covers a fixed trust list.

```go
tkauth, err := challenge.NewTKAuth01(challenge.TKAuthOptions{
	Authorities: challenge.StaticTokenAuthorities{
		ByURL: map[string]*x509.Certificate{"https://authority.example.com/cert": authorityCert},
	},
})
```

`Config.TokenAuthority` sets the optional `token-authority` URL advertised on the challenge. The
token must carry `exp` and `jti`. Its `fingerprint` may use the account key thumbprint or the
`SHA256` hex form of the same digest and `tktype` is compared without regard to case, since RFC
9447 and RFC 9448 spell them differently. One minute of clock skew is tolerated by default.

The certificate request must carry the same authority list in its `id-pe-TNAuthList` extension
request. The subject common name normally counts as a requested identifier. It is exempt when the
authority list is the only identifier, so the request may name the service provider there. An
order that also covers DNS or IP identifiers keeps the normal rule. A token whose `atc` claim
sets `ca` authorizes a CA certificate. Every authorization of the order must have granted what
the request asks for, so a request for a CA certificate without the grant is refused as `badCSR`
and so is a request without the CA constraint after the grant. The issued certificate may not
outlive the token. The issuer receives the token expiry as the requested `notAfter` unless the
order asks for an earlier time. A leaf valid past the token expiry is refused and retained as an
unacceptable result.

## Renewal information

Set `Config.RenewalInfo` to serve RFC 9773 renewal information. The directory then advertises
`renewalInfo`, clients fetch a suggested renewal window with an unauthenticated GET on the
certificate identifier and new orders may name the certificate they replace. `LifetimeRenewal` is
the built-in advisor. It opens the window at two thirds of the lifetime, closes it at five sixths
and moves it to the revocation time for revoked certificates. Hosts implement `RenewalAdvisor` for
other schedules, an explanation URL or a different Retry-After, which defaults to six hours.

A `replaces` member must name a certificate of the same account that shares an identifier with the
new order. The store marks the certificate replaced when the order is created, so a second order
naming it is refused with `alreadyReplaced` until the first one is invalid. Stores keep
`Certificate.RenewalID` unique and look certificates up by it. Without `Config.RenewalInfo` the
member is ignored.

## Storage, issuance and revocation

`memstore` is for tests and examples. Hosts supply durable storage for production. Atomic
operations check resource revisions and task fences. The [interoperability module](test/interop/README.md)
contains a SQLite test adapter and runs the same contract suite as the memory store.

An issuer must deduplicate by `OperationID` and recover its original result after an uncertain
call. The server records authorization evidence and the earliest authorization or order deadline
before dispatch. `IssuancePolicy` can refuse that first dispatch. The issuer must enforce
`Deadline` and must never start signing when `RecoveryOnly` is true. It may shorten the requested
validity to its own lifetime policy, but a leaf that starts earlier or ends later than the order
asked for fails the publication check. So does a CA certificate for an order that carries no
authority list grant. Recovery continues after account deactivation, expiry or exhausted ordinary
retries because an external CA may already have issued a certificate. An accepted challenge that
the worker has not validated yet does not survive deactivation. It becomes invalid with its
authorization and no proof is fetched from the subscriber.

Chains that fail publication checks remain in `Order.UnpublishedResult` with the CA reference and
are never returned to clients. The host reconciles or revokes them.

A certificate can be revoked by its issuing account, its private key or another valid account
authorized for every identifier, including wildcard scope. The server stores a revocation
operation ID and reason before calling the `Revoker` and repeats the same request after an
uncertain answer, so the revoker must deduplicate by `OperationID`. A retry keeps the first
recorded reason.

External account bindings are verified with the keys from `ExternalAccounts`. With
`SingleUseExternalAccounts`, each key identifier binds at most one account. A retry with the same
account key returns that account and a different key is refused as unauthorized.

## More

* [Interoperability tests](test/interop/README.md) name the clients, versions and scenarios.
* [SUPPORT.md](SUPPORT.md) explains where to ask and what to include.
* [CONTRIBUTING.md](CONTRIBUTING.md) lists the development checks.
* [SECURITY.md](SECURITY.md) explains how to report a vulnerability.
* [DEPENDENCIES.md](DEPENDENCIES.md) lists third-party code and licenses.
* [RELEASE_NOTES.md](RELEASE_NOTES.md) records user-visible changes per release.

Licensed under [Apache-2.0](LICENSE).
