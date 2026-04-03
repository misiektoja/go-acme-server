# go-acme-server

go-acme-server is a Go library for embedding an ACME server into CA and PKI applications.

The library owns the protocol: accounts, orders, authorizations, challenges, finalization,
certificate retrieval and revocation as specified in RFC 8555. The host application supplies the
parts that differ between deployments:

* a `Store` that persists resources and background work, with `memstore` for tests and examples
* an `Issuer` and a `Revoker` that call the host CA
* one `Validator` per challenge type, with HTTP-01, DNS-01 and TLS-ALPN-01 implementations in `challenge`
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

Licensed under [Apache-2.0](LICENSE).
