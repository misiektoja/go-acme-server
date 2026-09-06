# go-acme-server

go-acme-server is a Go library for embedding an ACME server into CA and PKI applications.

The library owns the protocol: accounts, orders, authorizations, challenges, finalization,
certificate retrieval and revocation as specified in RFC 8555. The host application supplies the
parts that differ between deployments:

* a `Store` that persists resources and background work, with `memstore` for tests and examples
* an `Issuer` and a `Revoker` that call the host CA
* one `Validator` per challenge type, with HTTP-01, DNS-01, TLS-ALPN-01 and tkauth-01 implementations
  in `challenge`
* optional policy hooks, external account binding keys and directory metadata

## Usage

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
`DNSOptions`. `NewTLSALPN01` takes the same `NetworkOptions` as HTTP-01. Custom resolvers must
honor context cancellation and bound their work.

The default egress policy allows public unicast destinations and denies special-purpose ranges.
`AllowedNetworks` adds explicit exceptions for private deployments. Every returned address must
pass the policy, including IPv4-mapped addresses. Resolver access is separate from this policy.

HTTP-01 disables environment proxies and rechecks destinations on redirects. Redirects may use
HTTP or HTTPS on ports 80 and 443. HTTPS redirects authenticate the challenge proof without requiring
a trusted website certificate. Defaults limit redirects to 10, the body to 4096 bytes and response
headers to 16 KiB. TLS-ALPN-01 checks the negotiated protocol, one matching SAN and the critical
proof extension, with a 256 KiB handshake limit.

The supplied resolver uses TCP, at most three numeric endpoints, eight CNAME hops, 64 records and
16 KiB messages by default. DNS-01 accepts any matching TXT record so concurrent base-domain and
wildcard proofs can coexist. Each validator has a ten-second default attempt timeout. Transport
failures are retryable. Incorrect proofs and policy refusals are terminal.

`HTTPOptions.TestPort` and `TLSALPNOptions.TestPort` override destination ports 80 and 443 for tests
only. The HTTP override applies to port 80 connections. Enable IP identifiers with
`Config.IPIdentifiers` and use HTTP-01 or TLS-ALPN-01. DNS-01 cannot validate IP identifiers.

## Authority Token challenges

`tkauth-01` proves authority over a list of telephone numbers instead of control of a network
resource, as specified in RFC 9447 and RFC 9448. Enable it with `Config.TNAuthListIdentifiers` and a
`ChallengeTKAuth01` validator. Orders then accept identifiers of type `TNAuthList` whose value is the
unpadded base64url encoding of a DER `TNAuthorizationList` from RFC 8226 section 9. Such an
identifier is offered `tkauth-01` alone, and every other identifier type keeps the network challenges.

A client answers the challenge by posting the Authority Token in a `tkauth` payload member. The
validator checks the token against the challenge identifier and the responding account key. It never
fetches the `x5u` URL, because trusting a Token Authority is a deployment decision: the header
reference is passed to a `TokenAuthorities` implementation that returns the certificate whose key
must have signed the token. `StaticTokenAuthorities` covers a fixed trust list with no network access.

```go
tkauth, err := challenge.NewTKAuth01(challenge.TKAuthOptions{
	Authorities: challenge.StaticTokenAuthorities{
		ByURL: map[string]*x509.Certificate{"https://authority.example.com/cert": authorityCert},
	},
})
```

`Config.TokenAuthority` sets the optional `token-authority` URL advertised on the challenge. The
`fingerprint` claim may use either the RFC 8555 account key thumbprint or the `SHA256` hex form of
the same digest, since RFC 9448 shows both. The `tktype` claim is compared without regard to case,
so tokens that follow the `TnAuthList` spelling of the RFC 9447 example are accepted. The token must
carry `exp` and `jti`, and a one-minute clock skew is tolerated by default.

Finalize such an order with a certificate request that carries the same authority list in its
`id-pe-TNAuthList` extension request. An order holds at most one `TNAuthList` identifier, because a
certificate has one such extension. A token whose `atc` claim sets `ca` authorizes a CA certificate
for delegation. Every authorization of the order must have granted what the request asks for: asking
for a CA certificate without that grant is refused as `badCSR`, and so is omitting it after the
grant, including when the order mixes the authority list with DNS names. Network challenges grant
nothing, so a request for a CA certificate is refused unless every challenge granted one.

The issued certificate may not outlive the token. The issuer receives the token expiry as the
requested `notAfter` when the order asks for nothing or for a later time, and a leaf that is valid
past the token expiry is refused and retained as an unacceptable result.

## Renewal information

Set `Config.RenewalInfo` to serve RFC 9773 renewal information. The directory then advertises
`renewalInfo`, clients fetch a suggested renewal window for a certificate with an unauthenticated
GET on its identifier and new orders may name the certificate they replace. `LifetimeRenewal` is
the built-in advisor. It opens the window at two thirds of the lifetime, closes it at five sixths
and moves it to the revocation time for revoked certificates. Hosts implement `RenewalAdvisor`
for other schedules, an explanation URL or a different Retry-After, which defaults to six hours.

A `replaces` member is checked against the stored predecessor. It must belong to the same account
and share an identifier with the new order. The store marks the certificate replaced when the
order is created, so a second order naming the same certificate is refused with `alreadyReplaced`
until the first one is invalid. Stores keep `Certificate.RenewalID` unique and look certificates up
by it. Without `Config.RenewalInfo` the member is ignored.

## Persistence and issuance

`memstore` is for tests and examples. Hosts must supply durable storage for production. Atomic
operations check resource revisions and task fences. The separate [interop module](test/interop/README.md)
contains a SQLite test adapter and the same contract suite used for memory storage.

An issuer must deduplicate by `OperationID` and recover its original result after an uncertain call.
The server records authorization evidence and the earliest authorization or order deadline before
dispatch. `IssuancePolicy` can refuse that first dispatch. The issuer must enforce `Deadline` and
must never start signing when `RecoveryOnly` is true. Recovery continues after account deactivation,
expiry or exhausted ordinary retries because an external CA may already have issued a certificate.

Chains that fail publication checks remain in `Order.UnpublishedResult` with the CA reference for
host reconciliation. They are never returned as successful orders. The host remains responsible for
reconciling or revoking them. A certificate can be revoked by its issuing account, its private key
or another valid account authorized for every complete identifier, including wildcard scope.
The server records a revocation operation ID and reason before calling the `Revoker` and repeats
the same request after an uncertain answer, so the revoker must deduplicate by `OperationID`.
A retried revocation keeps the first recorded reason.

External account bindings are verified with the keys from `ExternalAccounts`. With
`SingleUseExternalAccounts`, each key identifier binds at most one account. The claim is stored
with the account, a retry with the same account key returns that account and a different key is
refused as unauthorized.

Licensed under [Apache-2.0](LICENSE).
