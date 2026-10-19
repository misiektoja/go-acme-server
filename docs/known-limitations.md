# Known limitations

Behavior to plan around in the current release. Each item states what is missing and what it
means for clients or the host.

## Protocol scope

### No pre-authorization or authorization reuse

The directory omits `newAuthz` and every order receives fresh pending authorizations. A client that
renews the same name every week validates it again every week. Clients handle this without
configuration, but a CA that promised subscribers long-lived authorizations cannot keep that promise
with this library. A host can skip validation for names it approved in advance with a
[`PreApprover`](guide/accounts-and-policy.md#pre-approved-identifiers).

### One chain per certificate

The certificate response carries a single chain and no `rel="alternate"` link. A CA with several
roots picks one chain in its `Issuer` and clients cannot ask for another.

### Other ACME extensions are not implemented

`dns-account-01`, short-term automatic renewal, delegation, subdomain authorizations and `email`,
`onion` or device identifiers are not implemented. Unknown identifier types are refused with
`unsupportedIdentifier` and unknown directory or order members are ignored.

### Contacts are mailto only

An account contact must be a single `mailto` address without parameters. Other schemes are refused
with `unsupportedContact`.

## Host responsibilities

### No built-in rate limits

The library never answers `rateLimited` on its own. A host sets `Config.Limits` to limit nonces,
new accounts and new orders. `Policy` and `IssuancePolicy` can refuse other work. See
[Rate limits](guide/accounts-and-policy.md#rate-limits). The limiter is not asked about other
requests. An error response to any request carries a fresh nonce.

### No TLS termination, CA or durable storage

The host serves the handler behind its HTTPS origin, signs with its own CA and supplies durable
storage. `memstore` keeps everything in memory and forgets it on restart. The `nonce` package
coordinates nothing between processes, so replicas behind one origin need a shared implementation.
See [Deployment](operations/deployment.md).

### Unpublished results need reconciliation

A chain the CA returned but the server refused to publish stays in `Order.UnpublishedResult` with
the `CAReference`. The library never revokes it. The host must find these orders and revoke or
reconcile the certificates in its CA. See [Issuing certificates](guide/issuance.md#unpublished-results).

## Operational limits

| Limit | Default | Field |
| --- | --- | --- |
| Request body | 64 KiB | `Config.MaxRequestBody` |
| Identifiers per order | 100 | `Config.MaxIdentifiers` |
| Order lifetime | 7 days | `Config.OrderLifetime` |
| Authorization lifetime | 30 days | `Config.AuthorizationLifetime` |
| Validation and pre-dispatch policy attempts | 5 | `WorkerConfig.MaxAttempts` |
| Time per validator, issuer or store phase | 30 seconds | `WorkerConfig.TaskTimeout` |
| Time per task run | 2 minutes | `WorkerConfig.Lease` |
| Outstanding nonces in `nonce.Manager` | 100000 | `nonce.Options.Capacity` |

Issuance recovery has no attempt limit, because an uncertain CA answer may mean the certificate
already exists.
