# Getting help

Start with the [README](README.md), which covers embedding, validators, Authority Token challenges, renewal information and the host storage and CA contracts. The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-acme-server) describes every exported type. The [interoperability guide](test/interop/README.md) names the clients and scenarios the release was tested with.

## Check your integration first

Most problems come from the host side of the contracts. Before asking, confirm that:

* `Run` is active in this or another process on the same `Store`. Without it, challenges stay pending and orders never issue. `Ready` reports work that no worker picks up.
* `Config.BaseURL` matches the origin clients use exactly, because signed request URLs are compared with it.
* The validator resolver and egress policy reach the client. Private networks need `AllowedNetworks`.
* The host `Issuer` and `Revoker` deduplicate by `OperationID` and the `Store` passes the `storetest` suite.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a usage question or discuss an idea | [Discussions](https://github.com/misiektoja/go-acme-server/discussions) |
| Report something broken | [Bug report](https://github.com/misiektoja/go-acme-server/issues/new?template=bug_report.yml) |
| Request a capability | [Feature request](https://github.com/misiektoja/go-acme-server/issues/new?template=feature_request.yml) |
| Report a vulnerability | [Private security advisory](https://github.com/misiektoja/go-acme-server/security/advisories/new), never a public issue |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the go-acme-server version, the Go version, the ACME client and its version, the challenge type and which host interfaces are your own implementations. Attach the problem document the client received and the relevant server log lines.

Never post account keys, private keys, external account binding secrets, full CSRs or production endpoint details. See [SECURITY.md](SECURITY.md).

## What to expect

This project is maintained in spare time, so replies are best effort with no response time attached. Only the latest release receives fixes, as [SECURITY.md](SECURITY.md) describes, so reproduce the problem on the current version before reporting it.
