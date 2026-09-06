# Support matrix

What the library implements, what a configuration field turns on and what is out of scope. The
[known limitations](known-limitations.md) page explains the consequences of the gaps.

## Legend

| Status | Meaning |
| --- | --- |
| **Implemented** | Covered by the unit tests |
| **Interoperability tested** | Verified with at least one independent ACME client, see [Tested clients](interoperability/tested-clients.md) |
| **Unsupported** | Out of scope for the current release |

## Standards

| Standard | Coverage | Status | Enabled by |
| --- | --- | --- | --- |
| RFC 8555 ACME | Accounts, external account binding, key rollover, deactivation, orders, authorizations, HTTP-01, DNS-01, finalization, certificate download, revocation | Implemented, Interoperability tested | Always |
| RFC 8737 TLS-ALPN-01 | Challenge validation | Implemented, Interoperability tested | A `ChallengeTLSALPN01` validator |
| RFC 8738 IP identifiers | IPv4 and IPv6 identifiers through HTTP-01 and TLS-ALPN-01 | Implemented, Interoperability tested | `Config.IPIdentifiers` |
| RFC 9447 and RFC 9448 | `tkauth-01` with TNAuthList identifiers, CA certificates and token-bounded validity | Implemented, Interoperability tested with a go-jose client | `Config.TNAuthListIdentifiers` and a `ChallengeTKAuth01` validator |
| RFC 9773 | Renewal information and `replaces` on new orders | Implemented, Interoperability tested | `Config.RenewalInfo` |
| RFC 7638 | Account key thumbprints | Implemented, Interoperability tested | Always |

## Challenges and identifiers

| Identifier | Challenges offered | Notes |
| --- | --- | --- |
| `dns` | `http-01`, `dns-01`, `tls-alpn-01` from the configured validators | A wildcard name is offered `dns-01` alone |
| `ip` | `http-01` and `tls-alpn-01` from the configured validators | Needs `Config.IPIdentifiers`. Never `dns-01` |
| `TNAuthList` | `tkauth-01` alone | Needs `Config.TNAuthListIdentifiers`. One per order |

Only challenge types with a configured validator appear in authorizations. An order whose
identifier has no usable challenge type is refused.

## Keys and algorithms

| Use | Accepted |
| --- | --- |
| Account key signatures | ES256, ES384, ES512, RS256, EdDSA |
| External account binding MACs | HS256, HS384, HS512 |
| Account and CSR keys | RSA 2048 to 4096 bits, ECDSA P-256, P-384 and P-521, Ed25519 |
| Account contacts | `mailto` with one bare address, at most ten contacts |

The CSR key must differ from the account key.

## Host interfaces

| Interface | Required | Included implementation |
| --- | --- | --- |
| `Store` | Yes | `memstore` for tests and examples, `storetest` contract suite for your own adapter |
| `NonceManager` | Yes | `nonce` for a single process |
| `Issuer` and `Revoker` | Yes | None, they call your CA |
| `Validator` | At least one | `challenge.HTTP01`, `challenge.DNS01`, `challenge.TLSALPN01`, `challenge.TKAuth01` |
| `Policy` | No | `AllowAll` |
| `IssuancePolicy` | No | None |
| `ExternalAccountKeys` | With external account binding | None |
| `RenewalAdvisor` | No | `LifetimeRenewal` |
| `challenge.TokenAuthorities` | With `tkauth-01` | `challenge.StaticTokenAuthorities` |
| `Clock` | No | `SystemClock` |

## Not supported

| Capability | Status |
| --- | --- |
| Pre-authorization (`newAuthz`) and authorization reuse across orders | Unsupported |
| Alternate certificate chains | Unsupported |
| Certificate profiles, `dns-account-01`, short-term automatic renewal, delegation, subdomain authorizations | Unsupported, working group drafts are not exposed |
| `email`, `onion` and device identifiers | Unsupported |
| Rate limits | Unsupported, refuse in `Policy` or `IssuancePolicy` |
| TLS termination, a CA or durable storage | Provided by the host |

## Compatibility

The API may change before v1.0.0 as the [compatibility policy](reference/compatibility.md)
describes. Every release names the module version, the Go version and the tested client versions in
its release notes.
