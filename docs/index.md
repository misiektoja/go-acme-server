# go-acme-server

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-acme-server?style=flat-square&color=blue)](https://github.com/misiektoja/go-acme-server/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-acme-server.svg)](https://pkg.go.dev/github.com/misiektoja/go-acme-server)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/misiektoja/go-acme-server/blob/main/LICENSE)
[![Tests](https://github.com/misiektoja/go-acme-server/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-acme-server/actions/workflows/test.yml)
[![Interoperability](https://github.com/misiektoja/go-acme-server/actions/workflows/interop.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-acme-server/actions/workflows/interop.yml)
[![Supply chain](https://github.com/misiektoja/go-acme-server/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-acme-server/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-acme-server&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-acme-server)

go-acme-server is a Go library for embedding an ACME server into CA and PKI applications.

The library implements the ACME protocol of RFC 8555: accounts, orders, authorizations, challenges,
finalization, certificate retrieval and revocation. Your application supplies the parts that differ
between deployments through Go interfaces:

* a **store** that persists resources and background work
* an **issuer** and a **revoker** that call your CA
* one **validator** per challenge type, with HTTP-01, DNS-01, TLS-ALPN-01 and tkauth-01 included
* optional **policy hooks**, external account binding keys and directory metadata

The result is an `http.Handler` you mount behind your HTTPS origin and a worker you run next to it.
Standard ACME clients such as Certbot, lego, acmez and cert-manager then obtain certificates from your CA.

## Install

```bash
go get github.com/misiektoja/go-acme-server
```

The module needs Go 1.26.8 or newer. The root package is imported as `acmeserver`. The bundled
validators are in `challenge`, the in-memory store in `memstore`, the single-process nonce manager
in `nonce` and the store contract suite in `storetest`.

## Start here

**[Getting started](getting-started.md)** builds a complete local ACME server in one Go file and
issues a certificate with lego. The program is in the repository under `examples/quickstart`. Read it first, then replace each placeholder piece with your own
implementation by following the integration guide.

## Where to go next

| I want to | Page |
| --- | --- |
| Know which RFCs, algorithms and clients are covered | [Support matrix](support-matrix.md) |
| Understand how the handler, the worker and my code fit together | [Architecture](architecture.md) |
| Mount the handler and run the worker correctly | [Embedding the server](guide/embedding.md) |
| Persist accounts, orders and certificates in my database | [Storage](guide/storage.md) |
| Connect my CA | [Issuing certificates](guide/issuance.md) and [Revocation](guide/revocation.md) |
| Configure or write challenge validators | [Challenge validators](guide/validators.md) |
| Restrict who may register or order | [Accounts and policy](guide/accounts-and-policy.md) |
| Issue STIR certificates with Authority Tokens | [Authority Token challenges](guide/authority-tokens.md) |
| Tell clients when to renew | [Renewal information](guide/renewal-information.md) |
| Look up every configuration field | [Configuration](reference/configuration.md) |
| Configure a reverse proxy or health checks | [Deployment](operations/deployment.md) |
| Fix something that does not work | [Troubleshooting](operations/troubleshooting.md) |
| See which clients were tested | [Tested clients](interoperability/tested-clients.md) |
| Understand what is not implemented | [Known limitations](known-limitations.md) |
| Ask for help or report a problem | [Support](https://github.com/misiektoja/go-acme-server/blob/main/SUPPORT.md) |

## Design and security

* [Security model](security/security-model.md) - what the library protects against and what remains with the host
* [Compatibility policy](reference/compatibility.md) - what may change before v1.0.0 and how
* [Errors](reference/errors.md) - the problem types clients receive and what causes them

## Contributing

* [Development](development/development.md), [Testing](development/testing.md) and [Release process](development/release-process.md)
* Source and issues: [github.com/misiektoja/go-acme-server](https://github.com/misiektoja/go-acme-server)

## Support

[SUPPORT.md](https://github.com/misiektoja/go-acme-server/blob/main/SUPPORT.md) routes usage questions, bug reports, feature requests and private security reports. Check the [troubleshooting page](operations/troubleshooting.md) and collect sanitized diagnostics before posting.
