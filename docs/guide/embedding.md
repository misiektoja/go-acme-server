# Embedding the server

This page covers the pieces every host needs regardless of its CA or database: constructing the
`Server`, mounting it, running the worker, checking readiness and shutting down. The
[getting started](../getting-started.md) program shows all of them together.

## Construct the server

```go
import (
	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/memstore"
	"github.com/misiektoja/go-acme-server/nonce"
)

srv, err := acmeserver.New(acmeserver.Config{
	BaseURL:    "https://ca.example.com/acme/",
	Store:      store,
	Nonces:     nonce.New(nonce.Options{}),
	Issuer:     myCA,
	Revoker:    myCA,
	Validators: map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: http01},
})
```

`New` validates the configuration and returns an error naming the first problem. It starts no
background work. `Store`, `Nonces`, `Issuer`, `Revoker` and at least one validator are required.
Every other field has a default listed in [Configuration](../reference/configuration.md).

## The base URL

`Config.BaseURL` is the absolute URL clients use to reach the handler, including any path prefix.
Every URL the server hands out is built from it and every signed request carries the URL the client
posted to, which the server compares with the one it expects. The two must match exactly, so:

* Use the public scheme, host and port that clients see, not the address the process listens on.
* Keep the path prefix in place through any reverse proxy. Do not strip it. See [Deployment](../operations/deployment.md).
* Use `https`. `AllowInsecureBaseURL` accepts `http` for local tests only.

A missing trailing slash is added. User info, a query string, a fragment or an escaped path are refused.

## Mount the handler

`Server` implements `http.Handler` and expects requests whose path starts with the base URL path:

```go
mux := http.NewServeMux()
mux.Handle("/acme/", srv)
```

Requests outside the base path receive a `404` problem document. The handler sets
`Cache-Control: no-store` and a `Link` to the directory on every protocol response, so a proxy in
front of it needs no special caching rules. The paths below the base URL are listed in
[Endpoints](../reference/endpoints.md).

The host owns TLS. Terminate it in the same process with `ListenAndServeTLS` or in front of it,
as long as the origin the client connects to is the one the base URL names.

## Run the worker

```go
go func() {
	if err := srv.Run(ctx); err != nil {
		log.Print(err)
	}
}()
```

`Run` claims validation and issuance tasks from the store and processes them until `ctx` is
canceled. It is not optional. Without a running worker challenges stay `processing` forever and
finalized orders never issue. `Run` returns an error if it is already active on the same `Server`.

The worker may live in another process than the handler as long as both use the same store. Set
`WorkerConfig.External` in the handler process so it does not warn every time work is accepted
while no local worker is running. Several workers may share one store. Leases and fences make
sure no task is processed twice at the same time and a worker that dies is replaced once its lease
lapses.

`WorkerConfig` tunes concurrency, poll interval, lease length, per-phase timeouts, retry policy
and the staleness threshold. The defaults are listed in
[Configuration](../reference/configuration.md#workerconfig).

## Readiness

```go
mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
	if err := srv.Ready(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
})
```

`Ready` counts tasks that have waited longer than `WorkerConfig.StaleAfter` without being claimed.
It returns an error when there are any, which means no worker is picking up work. It reports the
state of the store, so it is correct in the handler process even when the worker runs elsewhere.
Wire it into the readiness or liveness probe of whichever process should be restarted when work
stalls.

## Logging

`Config.Logger` takes a `*slog.Logger`. Without one, nothing is logged. The server logs failed
store, validator and CA calls at error level with the resource and operation IDs involved, and
retried validations at warn level. Problem documents sent to clients are not logged, so a host that
wants an audit trail of refusals wraps the handler.

## Time

`Config.Clock` supplies the current time. It defaults to the system clock. Tests use
`acmeserver.ClockFunc` to control expiry and retry timing.

## Shutdown

Stop accepting requests first, then cancel the worker context and wait for `Run` to return:

```go
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
_ = httpServer.Shutdown(shutdownCtx)
workerCancel()
<-workerDone
```

Canceling the context stops new claims but does not interrupt a task in flight. A validator or
issuer call that has already started runs to its `TaskTimeout`. The store operations that
record its outcome get their own budget. `Run` can therefore take several `TaskTimeout` periods to
return. Waiting is optional. A task whose worker disappears is leased. Another worker picks it
up once the lease ends.

A revocation the CA already carried out is recorded even if the client disconnects, within
`Config.DetachedWriteTimeout`. Give the process at least that long to exit after the HTTP server
stops.

## Checklist

* `BaseURL` is the public origin and path, over HTTPS.
* The handler is mounted at the base path and the prefix survives the proxy.
* `Run` is active in at least one process on the same store.
* A health check calls `Ready`.
* `Logger` is set in production.
* Shutdown cancels the worker after the HTTP server and waits.
