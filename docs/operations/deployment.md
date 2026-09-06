# Deployment

This page covers what surrounds the library in production: TLS, reverse proxies, replicas, health
checks and shutdown. The host decides all of it. The library only requires that clients reach the
handler at the origin `Config.BaseURL` names.

## TLS

ACME clients require HTTPS. Either serve TLS in the host process or terminate it in front. The
library never inspects the connection, so both work. Use a certificate for the host name in the
base URL from a CA the clients trust. Clients such as lego and Certbot accept a private root through
their own options, which is how the [getting started](../getting-started.md) example works.

## Reverse proxies

Two rules keep signed requests valid behind a proxy:

* **Do not strip the path prefix.** If the base URL is `https://ca.example.com/acme/`, the handler must see `/acme/directory`, not `/directory`.
* **Do not change the origin.** The scheme, host and port in the base URL must be the ones the client used. The handler does not read `X-Forwarded-*` headers. The base URL is the single source of truth.

An nginx location that satisfies both:

```nginx
location /acme/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

With `proxy_pass` and no URI part, nginx forwards the original path unchanged. Timeouts on the proxy
should exceed the time a POST may take, which is the store round trip plus, for revocation, the
CA call.

Responses carry `Cache-Control: no-store`, so no cache configuration is needed. Request bodies are
limited by `Config.MaxRequestBody`, 64 KiB by default. A proxy body limit above that changes
nothing.

## Replicas

The handler and the worker communicate only through the store, which makes three layouts possible:

| Layout | Notes |
| --- | --- |
| One process with handler and worker | The simplest. `Ready` is the readiness probe |
| Several identical processes | Each runs the handler and `Run`. Workers share the store safely through leases and fences |
| Handler processes and separate worker processes | Set `WorkerConfig.External` in the handler processes to silence the warning logged when work is accepted with no local worker |

Two things are per process and need attention when there is more than one handler replica:

**Nonces.** `nonce.New` keeps nonces in memory. A nonce issued by one replica is unknown to
another, so a client whose requests land on different replicas gets `badNonce` and retries. Clients
handle `badNonce` by retrying with the nonce in the response, so a small number of replicas works
without coordination. For predictable behavior implement `NonceManager` over a shared store such as
Redis or use session affinity at the load balancer. A nonce must be valid exactly once.

**Store connections.** Every replica needs its own connection to the same database. The store
contract already handles concurrency.

## Health checks

`Server.Ready` reports whether accepted work is being claimed. Wire it into a readiness probe:

* In a single-process layout, a failing `Ready` means the worker is stuck or dead. Restart the process.
* In a split layout, `Ready` in a handler process reports the state of the workers. Route the alert accordingly rather than restarting the handler.

`WorkerConfig.StaleAfter` decides how long a task may wait before `Ready` fails, one minute by
default. Set it above the longest expected queue delay under load.

The directory endpoint is a cheap liveness check for the HTTP path. It needs no signature and
touches no store.

## Timeouts

| Setting | Default | Guidance |
| --- | --- | --- |
| `WorkerConfig.TaskTimeout` | 30 seconds | Above the slowest validator or CA call. Each phase gets the full budget |
| `WorkerConfig.Lease` | 2 minutes | Above the sum of the phases of one task, or a live worker loses tasks to its peers |
| `NetworkOptions.Timeout` | 10 seconds | Per validation attempt. Clients often need a few seconds to publish a DNS record |
| `Config.DetachedWriteTimeout` | 30 seconds | Above the store's worst-case write latency |
| HTTP server read and write timeouts | host choice | A POST completes within one store round trip, except revocation, which includes the CA call |

## Shutdown

1. Stop accepting connections and drain in-flight requests with the HTTP server's shutdown.
2. Cancel the worker context. Tasks already in flight complete their current phases.
3. Wait for `Run` to return or let the process exit and rely on leases. A task whose worker vanished is claimed again after `WorkerConfig.Lease`.

Give the process at least `Config.DetachedWriteTimeout` after the HTTP server stops, so a
revocation the CA already carried out is recorded.

## Logging and audit

Set `Config.Logger`. Errors name the order, challenge or operation ID involved and never include
keys, tokens or request bodies. For an audit trail of issued certificates read the store: every
`Certificate` carries the account, the order, the CA reference and the validation evidence.

Orders with `UnpublishedResult` set hold a chain the CA produced but the server refused to serve.
Query for them regularly and revoke or reconcile in the CA. See
[Issuing certificates](../guide/issuance.md#unpublished-results).

## Data retention

The library never deletes anything. Expired orders, invalid authorizations and finished tasks stay
in the store until the host removes them. A retention job should keep:

* certificates for as long as revocation and renewal information must work
* orders with an unpublished result until they are reconciled
* accounts for as long as their certificates exist

Everything else can go once its order has expired.
