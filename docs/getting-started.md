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

Save the following as `main.go`:

```go
// A local ACME server for trying go-acme-server: in-memory storage, a throwaway CA and HTTP-01.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/challenge"
	"github.com/misiektoja/go-acme-server/memstore"
	"github.com/misiektoja/go-acme-server/nonce"
)

// A throwaway CA. It remembers every result by operation ID, which is what a real CA must do too.
type devCA struct {
	key  *ecdsa.PrivateKey
	root *x509.Certificate

	mu      sync.Mutex
	issued  map[string][]byte
	revoked map[string]bool
}

// Generates a self-signed root that lives as long as the process.
func newDevCA() (*devCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-acme-server quickstart root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &devCA{key: key, root: root, issued: map[string][]byte{}, revoked: map[string]bool{}}, nil
}

// Signs one certificate per operation ID and returns the same chain on every retry.
func (ca *devCA) Issue(_ context.Context, req acmeserver.IssueRequest) (acmeserver.IssueResult, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if der, ok := ca.issued[req.OperationID]; ok {
		return acmeserver.IssueResult{Chain: [][]byte{der, ca.root.Raw}}, nil
	}
	// The server forbids new signing after the deadline or during recovery of an earlier attempt.
	if req.RecoveryOnly || !req.Deadline.After(time.Now()) {
		return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorUnauthorized,
			"the signing deadline has passed")}, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	now := time.Now().Truncate(time.Second)
	leaf := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// The issued leaf must stay inside the validity the order asked for.
	if !req.NotBefore.IsZero() {
		leaf.NotBefore = req.NotBefore
	}
	if !req.NotAfter.IsZero() && req.NotAfter.Before(leaf.NotAfter) {
		leaf.NotAfter = req.NotAfter
	}
	for _, id := range req.Identifiers {
		switch id.Type {
		case acmeserver.IdentifierDNS:
			leaf.DNSNames = append(leaf.DNSNames, id.Value)
		case acmeserver.IdentifierIP:
			leaf.IPAddresses = append(leaf.IPAddresses, net.ParseIP(id.Value))
		default:
			return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier,
				"unsupported identifier type")}, nil
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, req.CSR.PublicKey, ca.key)
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	ca.issued[req.OperationID] = der
	return acmeserver.IssueResult{Chain: [][]byte{der, ca.root.Raw}}, nil
}

// Signs a TLS server certificate for localhost so clients can reach the directory over HTTPS.
func (ca *devCA) serverCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.root, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.root.Raw}, PrivateKey: key}, nil
}

// Records the revocation. A real CA publishes it through its CRL or OCSP responder.
func (ca *devCA) Revoke(_ context.Context, req acmeserver.RevokeRequest) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.revoked[req.OperationID] = true
	return nil
}

// Answers the quickstart name with the loopback address instead of asking DNS.
type localResolver struct{}

// Resolves quickstart.example.test to 127.0.0.1 and refuses every other name.
func (localResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if strings.TrimSuffix(host, ".") != "quickstart.example.test" {
		return nil, errors.New("unknown host " + host)
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, err := newDevCA()
	if err != nil {
		logger.Error("create CA", "error", err)
		os.Exit(1)
	}
	// Clients trust this file so they can talk to the server and verify the issued chain.
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})
	if err := os.WriteFile("quickstart-root.pem", rootPEM, 0o600); err != nil {
		logger.Error("write root", "error", err)
		os.Exit(1)
	}
	serverCert, err := ca.serverCertificate()
	if err != nil {
		logger.Error("create server certificate", "error", err)
		os.Exit(1)
	}
	// Loopback is denied by the default egress policy, so the quickstart allows it explicitly.
	// TestPort sends HTTP-01 requests to port 5002 instead of port 80.
	http01, err := challenge.NewHTTP01(challenge.HTTPOptions{
		Network: challenge.NetworkOptions{
			Resolver:        localResolver{},
			AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		},
		TestPort: 5002,
	})
	if err != nil {
		logger.Error("create validator", "error", err)
		os.Exit(1)
	}
	srv, err := acmeserver.New(acmeserver.Config{
		BaseURL: "https://localhost:4000/acme/",
		Store:   memstore.New(),
		Nonces:  nonce.New(nonce.Options{}),
		Issuer:  ca,
		Revoker: ca,
		Validators: map[acmeserver.ChallengeType]acmeserver.Validator{
			acmeserver.ChallengeHTTP01: http01,
		},
		RenewalInfo: acmeserver.LifetimeRenewal{},
		Logger:      logger,
	})
	if err != nil {
		logger.Error("create server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// The worker validates challenges and issues certificates. Without it nothing progresses.
	go func() {
		if err := srv.Run(ctx); err != nil {
			logger.Error("worker", "error", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/acme/", srv)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.Ready(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	httpServer := &http.Server{
		Addr:              "localhost:4000",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}},
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	logger.Info("serving", "directory", "https://localhost:4000/acme/directory", "root", "quickstart-root.pem")
	if err := httpServer.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}
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
