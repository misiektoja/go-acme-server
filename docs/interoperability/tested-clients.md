# Tested clients

Independent ACME clients issue, revoke and replace certificates against the server in the
interoperability module under `test/interop`. Every run serves the library over HTTPS with the
SQLite test store and a test CA, so the clients see what a real deployment shows them. The module
and its versions are separate from the library. `make test-interop` is a release gate.

## Clients and versions

| Client | Version | Scenarios |
| --- | --- | --- |
| [acmez](https://github.com/mholt/acmez) | v3.1.6 | HTTP-01, DNS-01 with a wildcard and its base name, TLS-ALPN-01, an IP identifier next to a DNS name, renewal information and `replaces` |
| [Certbot](https://certbot.eff.org/) | 5.8.0 | Standalone HTTP-01, manual DNS-01 for a wildcard pair, revocation through the account, waiting out a pending order |
| [lego](https://go-acme.github.io/lego/) | v4.35.2 | HTTP-01, DNS-01 for a wildcard pair, TLS-ALPN-01, revocation with a reason code and `alreadyRevoked` on repeat, renewal information and `replaces`, waiting out a pending order |
| Go [crypto/acme](https://pkg.go.dev/golang.org/x/crypto/acme) | v0.56.0 | Contact update, key rollover, HTTP-01, revocation with the certificate key, account deactivation |
| [go-jose](https://github.com/go-jose/go-jose) raw client | v4.1.5 | Every signature algorithm, thumbprint cross-check, key change, external account binding, refused signatures, `tkauth-01`, repeated and concurrent requests |
| [cert-manager](https://cert-manager.io/) | v1.21.1 | Issuance and renewal through a `ClusterIssuer` in a kind cluster |

The Go clients run in process. Certbot runs from a pinned Python environment. cert-manager runs in
a throwaway kind cluster against the server from `test/interop/cmd/server`, weekly and on request
rather than on every push.

## What the scenarios establish

* **Correct certificates.** Each test checks the issued key, the exact identifier set, the validity, the chain and the stored resource state.
* **No issuance without proof.** An incorrect proof of any challenge type leaves the order invalid and the test CA records no call.
* **One CA call per operation.** The test CA records every issuance and revocation by operation ID, so retries and races are visible.
* **Idempotent clients.** Registering one key again or from several connections at once yields one account. Repeated and concurrent challenge responses validate once. Repeated finalizations with the same CSR issue once and a different CSR is refused.
* **Recovery.** Two processes share one SQLite store without processing any task twice. A worker killed after the CA committed but before publication is replaced by a new worker that recovers the identical certificate with one issuance across two CA calls.
* **Extensions.** IP identifiers are offered HTTP-01 alone and refused when the feature is off. Renewal information is read, a certificate is replaced and a second `replaces` claim is refused with `alreadyReplaced`. A `tkauth-01` order with an Authority Token from a local Token Authority issues a certificate bounded by the token expiry.

## What they do not establish

The scenarios cover the named clients and versions. They do not establish complete RFC
conformance. They do not cover alternate chain selection, which the library does not offer.
The validator tests in the `challenge` package separately check the proof and egress rules of
RFC 8555, RFC 8737, RFC 8738 and RFC 9448.

## Running them

[Testing](../development/testing.md) explains how to install the pinned Certbot
environment and run the gate locally. The module README at `test/interop/README.md` describes each
scenario and the SQLite adapter in detail.
