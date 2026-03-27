# go-acme-server

go-acme-server is a Go library for embedding an ACME server into CA and PKI applications.

The library owns the protocol: accounts, orders, authorizations, challenges, finalization,
certificate retrieval and revocation as specified in RFC 8555. The host application supplies the
parts that differ between deployments:

* a `Store` that persists resources and background work, with `memstore` for tests and examples
* an `Issuer` and a `Revoker` that call the host CA
* one `Validator` per challenge type the deployment offers
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

Licensed under [Apache-2.0](LICENSE).
