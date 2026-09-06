# Getting started

This page builds a complete local ACME server in one Go file and issues a certificate with an
independent client. Every placeholder in it maps to a page of the integration guide, so once it
runs you know exactly what to replace for production.

The server keeps everything in memory, signs with a throwaway root and validates HTTP-01 against
the loopback address. It runs over HTTPS because ACME clients such as lego refuse a plain HTTP directory.

## What you need

* Go 1.26.8 or newer, the minimum the module declares
* [lego](https://go-acme.github.io/lego/) as the client, run below with `go run`
* Ports 4000 and 5002 free on the local machine

## Step 1: create the program

Create a module and add the library:

```bash
mkdir acme-quickstart && cd acme-quickstart
go mod init example.com/acme-quickstart
go get github.com/misiektoja/go-acme-server
```

The same program is in the repository as
[examples/quickstart](https://github.com/misiektoja/go-acme-server/tree/main/examples/quickstart),
where `go run ./examples/quickstart` starts it without any setup. Save it as `main.go`:

```go
--8<-- "examples/quickstart/main.go"
```

The program has four parts and each one is a seam where your own code goes later:

| Part | What the quickstart does | What replaces it |
| --- | --- | --- |
| `devCA` | Signs with an in-process root and remembers results by operation ID | Your CA behind [`Issuer`](guide/issuance.md) and [`Revoker`](guide/revocation.md) |
| `memstore.New()` | Keeps accounts, orders and tasks in memory until the process exits | A durable [`Store`](guide/storage.md) over your database |
| `localResolver` and `TestPort` | Send HTTP-01 requests to the loopback address on port 5002 | A [resolver and egress policy](guide/validators.md) that reach real clients on port 80 |
| `nonce.New` | Single-process replay protection | A shared nonce manager when several replicas serve one origin, see [Deployment](operations/deployment.md) |

Two calls are required and easy to forget. `mux.Handle` serves the protocol and `srv.Run` processes
the validation and issuance work. Without the worker, challenges stay pending forever and orders never
issue. The `/healthz` handler calls `Ready`, which fails once accepted work has waited too long for a
worker.

## Step 2: run it

```bash
go run .
```

```text
level=INFO msg=serving directory=https://localhost:4000/acme/directory root=quickstart-root.pem
```

The server wrote its root certificate to `quickstart-root.pem`. Check the directory with that root:

```bash
curl --cacert quickstart-root.pem https://localhost:4000/acme/directory
```

```json
{"keyChange":"https://localhost:4000/acme/key-change","newAccount":"https://localhost:4000/acme/new-account","newNonce":"https://localhost:4000/acme/new-nonce","newOrder":"https://localhost:4000/acme/new-order","renewalInfo":"https://localhost:4000/acme/renewal-info","revokeCert":"https://localhost:4000/acme/revoke-cert"}
```

Every URL starts with the configured base URL. `renewalInfo` appears because the program set
`Config.RenewalInfo`.

## Step 3: issue a certificate

In a second terminal, from the same directory, run lego against the server. `LEGO_CA_CERTIFICATES`
makes lego trust the quickstart root for the HTTPS connection and `--http.port :5002` is where the
validator will look for the proof:

```bash
mkdir lego && cd lego
LEGO_CA_CERTIFICATES=../quickstart-root.pem go run github.com/go-acme/lego/v4/cmd/lego@v4.35.2 --server https://localhost:4000/acme/directory --email admin@example.test --accept-tos --http --http.port :5002 --domains quickstart.example.test --path . run
```

```text
[INFO] [quickstart.example.test] acme: Obtaining bundled SAN certificate
[INFO] [quickstart.example.test] acme: use http-01 solver
[INFO] [quickstart.example.test] acme: Trying to solve HTTP-01
[INFO] [quickstart.example.test] Served key authentication
[INFO] [quickstart.example.test] The server validated our request
[INFO] [quickstart.example.test] acme: Validations succeeded; requesting certificates
[INFO] [quickstart.example.test] Server responded with a certificate.
```

The certificate is in `certificates/quickstart.example.test.crt`, signed by the quickstart root:

```bash
openssl verify -CAfile ../quickstart-root.pem -untrusted certificates/quickstart.example.test.issuer.crt certificates/quickstart.example.test.crt
```

```text
certificates/quickstart.example.test.crt: OK
```

Revocation goes through the same account:

```bash
LEGO_CA_CERTIFICATES=../quickstart-root.pem go run github.com/go-acme/lego/v4/cmd/lego@v4.35.2 --server https://localhost:4000/acme/directory --email admin@example.test --accept-tos --domains quickstart.example.test --path . revoke --reason 1
```

```text
Certificate was revoked.
```

!!! note "Restarting the quickstart"
    The in-memory store forgets every account when the process exits. A client that kept its account
    from the previous run is refused with `accountDoesNotExist`. Delete the client's `accounts`
    directory or register again.

## What happens behind the scenes

1. lego registers an account and creates an order for `quickstart.example.test`.
2. The server creates one authorization for the name with an `http-01` challenge, because HTTP-01 is the only configured validator.
3. lego serves the key authorization on port 5002 and tells the server the challenge is ready.
4. The worker claims the validation task, resolves the name through `localResolver`, connects to `127.0.0.1:5002` and compares the proof.
5. lego finalizes the order with a CSR. The server checks the CSR against the order and enqueues issuance.
6. The worker records the dispatch decision in the store, calls `devCA.Issue`, checks the returned chain against the order and stores the certificate.
7. lego downloads the chain from the certificate URL.

[Architecture](architecture.md) describes these steps in detail, including what is persisted at each point and why.

## Before production

Work through these pages in order. Each one names the contract your implementation must meet and the
test suite or client that verifies it.

1. [Embedding the server](guide/embedding.md) - the base URL, the worker, readiness and shutdown
2. [Storage](guide/storage.md) - implement `Store` and run the `storetest` suite against it
3. [Issuing certificates](guide/issuance.md) - implement `Issuer` with operation ID deduplication
4. [Revocation](guide/revocation.md) - implement `Revoker` the same way
5. [Challenge validators](guide/validators.md) - configure a real resolver and decide the egress policy
6. [Accounts and policy](guide/accounts-and-policy.md) - external account binding, terms of service and order policy
7. [Deployment](operations/deployment.md) - TLS termination, replicas and health checks
