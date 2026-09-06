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

The result is an `http.Handler` mounted behind the host's HTTPS origin and a worker that runs next
to it. Standard ACME clients such as Certbot, lego, acmez and cert-manager then obtain certificates
from the host CA.

## Contents

* [Install](#install)
* [Scope](#scope)
* [Getting started](#getting-started)
* [Documentation](#documentation)
* [Support](#support)
* [License](#license)

## Install

```bash
go get github.com/misiektoja/go-acme-server
```

The module needs Go 1.26.8 or newer. The root package is imported as `acmeserver`, the bundled
validators live in `challenge`, the in-memory store in `memstore` and the single-process nonce
manager in `nonce`:

```go
import (
	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/challenge"
	"github.com/misiektoja/go-acme-server/memstore"
	"github.com/misiektoja/go-acme-server/nonce"
)
```

## Scope

| Standard | Coverage | Enabled by |
| --- | --- | --- |
| RFC 8555 ACME | Accounts, external account binding, key rollover, orders, HTTP-01, DNS-01, finalization, certificates, revocation | Always |
| RFC 8737 TLS-ALPN-01 | Challenge validation | A `ChallengeTLSALPN01` validator |
| RFC 8738 IP identifiers | IPv4 and IPv6 identifiers through HTTP-01 and TLS-ALPN-01 | `Config.IPIdentifiers` |
| RFC 9447 and RFC 9448 | tkauth-01 with TNAuthList identifiers | `Config.TNAuthListIdentifiers` |
| RFC 9773 | Renewal information and `replaces` | `Config.RenewalInfo` |

Account keys may use ES256, ES384, ES512, RS256 or EdDSA. External account bindings use HS256, HS384 or
HS512. Independent clients verify the behavior, see
[Tested clients](https://misiektoja.github.io/go-acme-server/interoperability/tested-clients/).
The API may still change before v1.0.0 as described in the
[compatibility policy](https://misiektoja.github.io/go-acme-server/reference/compatibility/).

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

[Known limitations](https://misiektoja.github.io/go-acme-server/known-limitations/) explains the
consequences of each gap.

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

The [getting started guide](https://misiektoja.github.io/go-acme-server/getting-started/) builds a
complete local server in one file, issues a certificate with lego and names what to replace before
production. The package example in `example_test.go` shows the same wiring in Go documentation form.

## Documentation

Full documentation is at
[misiektoja.github.io/go-acme-server](https://misiektoja.github.io/go-acme-server/).

* [Getting started](https://misiektoja.github.io/go-acme-server/getting-started/)
* [Support matrix](https://misiektoja.github.io/go-acme-server/support-matrix/)
* [Architecture](https://misiektoja.github.io/go-acme-server/architecture/)
* [Embedding the server](https://misiektoja.github.io/go-acme-server/guide/embedding/)
* [Storage](https://misiektoja.github.io/go-acme-server/guide/storage/)
* [Issuing certificates](https://misiektoja.github.io/go-acme-server/guide/issuance/) and [Revocation](https://misiektoja.github.io/go-acme-server/guide/revocation/)
* [Challenge validators](https://misiektoja.github.io/go-acme-server/guide/validators/)
* [Accounts and policy](https://misiektoja.github.io/go-acme-server/guide/accounts-and-policy/)
* [Authority Token challenges](https://misiektoja.github.io/go-acme-server/guide/authority-tokens/)
* [Renewal information](https://misiektoja.github.io/go-acme-server/guide/renewal-information/)
* [Configuration reference](https://misiektoja.github.io/go-acme-server/reference/configuration/)
* [Deployment](https://misiektoja.github.io/go-acme-server/operations/deployment/)
* [Troubleshooting](https://misiektoja.github.io/go-acme-server/operations/troubleshooting/)
* [Security model](https://misiektoja.github.io/go-acme-server/security/security-model/)

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-acme-server)
describes every exported type. Repository files:

* [SUPPORT.md](SUPPORT.md) explains where to ask and what to include.
* [CONTRIBUTING.md](CONTRIBUTING.md) lists the development checks.
* [SECURITY.md](SECURITY.md) explains how to report a vulnerability.
* [DEPENDENCIES.md](DEPENDENCIES.md) lists third-party code and licenses.
* [RELEASE_NOTES.md](RELEASE_NOTES.md) records user-visible changes per release.

## Support

[SUPPORT.md](SUPPORT.md) directs usage questions, bug reports, feature requests and security
reports. Check the
[troubleshooting page](https://misiektoja.github.io/go-acme-server/operations/troubleshooting/)
and gather the versions, the problem document and the server log before posting.

## License

Licensed under [Apache-2.0](LICENSE).
