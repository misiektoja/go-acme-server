# Challenge validators

A validator proves that the client controls one identifier. The server offers a challenge type
only when `Config.Validators` holds a validator for it, so the map decides what clients see in
their authorizations. The `challenge` package implements the three network challenges of RFC 8555
and RFC 8737 and the Authority Token challenge of RFC 9447, described in [Authority Token challenges](authority-tokens.md).

```go
Validators: map[acmeserver.ChallengeType]acmeserver.Validator{
	acmeserver.ChallengeHTTP01:    http01,
	acmeserver.ChallengeDNS01:     dns01,
	acmeserver.ChallengeTLSALPN01: tlsalpn01,
},
```

| Identifier | Challenge types offered |
| --- | --- |
| DNS name | Every configured network type |
| Wildcard DNS name | `dns-01` only |
| IP address | `http-01` and `tls-alpn-01`, never `dns-01` |

## The resolver

The network validators never use the system resolver. You configure the recursive DNS endpoints
they may ask, which keeps validation traffic predictable and lets the deployment decide which view
of DNS counts.

```go
resolver, err := challenge.NewResolver(challenge.ResolverOptions{
	Servers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")},
})
```

Replace the documentation address with your recursive resolver. Up to three servers are accepted.
The resolver speaks TCP, accepts a response only when its ID and question match the query, follows
CNAMEs only from the answer owner and bounds the lookup time, the CNAME chain, the message size and
the record count. The defaults are ten seconds, eight hops, 16 KiB and 64 records.

A custom `IPResolver` or `TXTResolver` may replace it, for example a resolver that consults an
internal zone during tests. It must honor context cancellation and bound its own work, because the
validator's timeout is the only thing standing between a slow resolver and a stuck worker slot.

## Egress policy

HTTP-01 and TLS-ALPN-01 connect to whatever address the identifier resolves to. `NetworkOptions`
decides which addresses are acceptable:

```go
network := challenge.NetworkOptions{
	Resolver:        resolver,
	AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
}
```

By default only ordinary public unicast addresses are allowed. Loopback, private, link-local,
carrier-grade NAT, documentation, multicast and the other IANA special-purpose ranges are denied.
`AllowedNetworks` adds explicit exceptions for a CA that issues to private networks. Every resolved
address must pass, IPv4-mapped IPv6 addresses are unmapped before the check and a name that
resolves to more than `MaxAddresses` addresses is refused. The policy is applied again on every
redirect. `challenge.PublicAddress` exposes the default rule.

Access to the resolver itself is separate from this policy, so a private recursive resolver works
without an exception.

## HTTP-01

```go
http01, err := challenge.NewHTTP01(challenge.HTTPOptions{Network: network})
```

The validator fetches `http://<identifier>/.well-known/acme-challenge/<token>` on port 80, follows
at most ten redirects to `http` or `https` URLs on ports 80 and 443, rechecks the egress policy on
every hop, reads at most 4096 bytes and compares the trimmed body with the key authorization. It
ignores proxy environment variables. An HTTPS redirect target is not checked against the web PKI,
because the key authorization is the proof, not the website certificate.

`MaxRedirects` and `MaxResponseBytes` change the limits. `TestPort` replaces port 80 for local
tests only, which is how the [Getting started](../getting-started.md) program reaches a client on
port 5002.

## DNS-01

```go
dns01, err := challenge.NewDNS01(challenge.DNSOptions{Resolver: resolver})
```

The validator looks up TXT records at `_acme-challenge.<identifier>` and accepts the response when
any record equals the base64url SHA-256 digest of the key authorization. Accepting any matching
record is what lets a client prove a wildcard and its base name at the same owner name in one
order. A response with more than 64 records is a DNS failure.

DNS-01 is the only challenge offered for wildcard names and is never offered for IP identifiers.

## TLS-ALPN-01

```go
tlsalpn01, err := challenge.NewTLSALPN01(challenge.TLSALPNOptions{Network: network})
```

The validator opens a TLS connection to port 443 and offers only the `acme-tls/1` protocol. The
SNI is the identifier or the reverse-mapped name for an IP identifier as RFC 8738 requires. The
handshake is limited to 256 KiB. It then checks that `acme-tls/1` was negotiated, that the
certificate carries exactly one SAN equal to the identifier and that the critical `acmeIdentifier`
extension holds the SHA-256 digest of the key authorization. Ordinary certificate trust and
validity are not applied. `TestPort` replaces port 443 for tests.

## Timeouts, retries and outcomes

Each validator bounds one attempt to `NetworkOptions.Timeout` or `DNSOptions.Timeout`, ten seconds
by default. The worker adds its own `WorkerConfig.TaskTimeout`. The outcome decides what
happens next:

| The validator returns | Meaning | Server behavior |
| --- | --- | --- |
| `nil` | The proof matched | Challenge and authorization become valid |
| `*acmeserver.Problem` | The proof was wrong or the target refused | Final. Challenge and authorization become invalid, the problem is shown to the client |
| Any other error | A transport failure | Retried with exponential backoff until `WorkerConfig.MaxAttempts` or the authorization expiry |

The bundled validators return `incorrectResponse` for a wrong proof, `dns` for a resolver failure
that is unlikely to change and a plain error for connection failures. They never include fetched
content in the problem detail.

## Writing a validator

```go
type Validator interface {
	Validate(ctx context.Context, req ValidationRequest) error
}
```

`ValidationRequest` carries the challenge, the identifier with its wildcard flag, the key
authorization, the account key thumbprint captured when the client responded and, for
`tkauth-01`, the Authority Token. A custom validator should:

* check that `req.Challenge.Type` is the type it handles and that the identifier type is one it can prove
* return `*acmeserver.Problem` for a definitive failure and any other error for one worth retrying
* finish within the context deadline and never follow untrusted redirects or resolve names without a policy
* keep fetched content out of error details

A validator that also authorizes something beyond control of the identifier, such as a CA
certificate or a validity bound, implements `GrantingValidator`. The `tkauth-01` validator is the
example.

## Checklist

* `ResolverOptions.Servers` names your recursive resolvers.
* `AllowedNetworks` lists exactly the private ranges the CA issues into or nothing at all.
* `TestPort` is unset in production.
* At least one validator is configured for every identifier type you accept, including `dns-01` for wildcards.
