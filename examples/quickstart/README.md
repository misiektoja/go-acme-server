# Quickstart example

A complete local ACME server in one file: in-memory storage, a throwaway root that signs the issued
certificates and the HTTPS listener, and HTTP-01 validation against the loopback address on port
5002.

```bash
go run ./examples/quickstart
```

The server listens on `https://localhost:4000/acme/` and writes its root to `quickstart-root.pem`
in the working directory. Issue a certificate for `quickstart.example.test` with lego from another
directory:

```bash
LEGO_CA_CERTIFICATES=/path/to/quickstart-root.pem go run github.com/go-acme/lego/v4/cmd/lego@v4.35.2 --server https://localhost:4000/acme/directory --email admin@example.test --accept-tos --http --http.port :5002 --domains quickstart.example.test --path . run
```

Everything is forgotten when the process exits. [Getting started](https://misiektoja.github.io/go-acme-server/getting-started/) explains each
part and what replaces it in production.
