# Examples

Runnable programs that show how a host embeds go-acme-server. They are part of the root module, so
`go vet ./...` and `go test ./...` build them with the library.

| Example | Shows | Run |
| --- | --- | --- |
| [quickstart](quickstart/) | A complete local ACME server with in-memory storage, a throwaway CA and HTTP-01 over HTTPS | `go run ./examples/quickstart` |

[Getting started](https://misiektoja.github.io/go-acme-server/getting-started/) walks
through the quickstart and issues a certificate against it with lego.
