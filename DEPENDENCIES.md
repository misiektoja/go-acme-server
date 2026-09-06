# Dependencies

The implementation is original. Third-party code is consumed through versioned packages.

| Dependency | Use | License |
| --- | --- | --- |
| golang.org/x/net | Bounded DNS wire parsing in `challenge` | BSD-3-Clause |
| modernc.org/sqlite | Durable storage in the separate interoperability module | BSD-3-Clause |
| github.com/mholt/acmez/v3 | Independent Go client tests | Apache-2.0 |
| github.com/go-jose/go-jose/v4 | Independent JWS signing in the interoperability tests | Apache-2.0 |
| github.com/go-acme/lego/v4 | Independent Go client tests | MIT |
| golang.org/x/crypto | Independent Go client tests through its `acme` package | BSD-3-Clause |
| Certbot and acme | Independent Python client tests | Apache-2.0 with component notices |
| cert-manager | Independent Kubernetes client tests in a kind cluster | Apache-2.0 |

Exact Go versions and checksums are in each module's `go.mod` and `go.sum`. The Python test
environment is pinned in `test/interop/requirements.txt`. Each dependency retains its own license
and notices in the downloaded module or distribution. Those requirements also apply to any
distribution that includes the dependencies.
