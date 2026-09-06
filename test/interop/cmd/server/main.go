// Serves go-acme-server with a self-contained test CA for cluster-based client tests.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/challenge"
	"github.com/misiektoja/go-acme-server/nonce"
	"github.com/misiektoja/go-acme-server/test/interop/sqlitestore"
)

// Names the credential files kept in the state directory.
const (
	rootCertFile = "root.pem"
	rootKeyFile  = "root-key.pem"
	tlsCertFile  = "tls.crt"
	tlsKeyFile   = "tls.key"
)

// Collects repeated name=value flags.
type pairs map[string]string

// Records one name=value pair.
func (p pairs) Set(value string) error {
	name, target, ok := strings.Cut(value, "=")
	if !ok || name == "" || target == "" {
		return errors.New("expected name=value")
	}
	p[strings.ToLower(strings.TrimSuffix(name, "."))] = target
	return nil
}

// Renders the pairs for flag help.
func (p pairs) String() string { return fmt.Sprint(map[string]string(p)) }

// Answers only the names given on the command line with their fixed addresses.
type staticResolver map[string]netip.Addr

// Refuses every name without a configured address instead of consulting DNS.
func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addr, ok := r[strings.ToLower(strings.TrimSuffix(host, "."))]
	if !ok {
		return nil, errors.New("no validation address configured for " + host)
	}
	return []netip.Addr{addr}, nil
}

// Signs accepted requests once per operation ID and records revocations durably.
type signer struct {
	key  *ecdsa.PrivateKey
	root *x509.Certificate
	db   *sql.DB
}

// Returns the certificate recorded for the operation or signs and records a new one.
func (s *signer) Issue(ctx context.Context, req acmeserver.IssueRequest) (acmeserver.IssueResult, error) {
	var der []byte
	err := s.db.QueryRowContext(ctx, `SELECT der FROM issuance WHERE operation = ?`, req.OperationID).Scan(&der)
	if err == nil {
		return acmeserver.IssueResult{Chain: [][]byte{der, s.root.Raw}}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return acmeserver.IssueResult{}, err
	}
	if req.RecoveryOnly || !req.Deadline.After(time.Now()) {
		return acmeserver.IssueResult{
			Rejected: acmeserver.NewProblem(acmeserver.ErrorUnauthorized, "signing deadline elapsed")}, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	now := time.Now().Truncate(time.Second)
	leaf := &x509.Certificate{SerialNumber: serial, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if !req.NotBefore.IsZero() {
		leaf.NotBefore = req.NotBefore
	}
	if !req.NotAfter.IsZero() {
		leaf.NotAfter = req.NotAfter
	}
	for _, id := range req.Identifiers {
		switch id.Type {
		case acmeserver.IdentifierDNS:
			leaf.DNSNames = append(leaf.DNSNames, id.Value)
		case acmeserver.IdentifierIP:
			leaf.IPAddresses = append(leaf.IPAddresses, net.ParseIP(id.Value))
		case acmeserver.IdentifierTNAuthList:
			return acmeserver.IssueResult{
				Rejected: acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier, "unsupported identifier")}, nil
		}
	}
	if der, err = x509.CreateCertificate(rand.Reader, leaf, s.root, req.CSR.PublicKey, s.key); err != nil {
		return acmeserver.IssueResult{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO issuance (operation, der) VALUES (?, ?)`, req.OperationID, der)
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	// A concurrent worker may have recorded the operation first, so the stored result wins.
	err = s.db.QueryRowContext(ctx, `SELECT der FROM issuance WHERE operation = ?`, req.OperationID).Scan(&der)
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	return acmeserver.IssueResult{Chain: [][]byte{der, s.root.Raw}}, nil
}

// Records the revocation once per operation ID.
func (s *signer) Revoke(ctx context.Context, req acmeserver.RevokeRequest) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO revocation (operation, serial, reason) VALUES (?, ?, ?)`,
		req.OperationID, req.Certificate.SerialNumber.Text(16), req.Reason)
	return err
}

// Writes a PEM block readable only by the current user.
func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}

// Reads one PEM block of the expected type.
func readPEM(path, typ string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // The path comes from the operator's command line.
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("%s: expected a %s block", path, typ)
	}
	return block.Bytes, nil
}

// Creates the root and the HTTPS credentials for the given server names in the state directory.
func initState(state string, names []string) error {
	if err := os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ACME interoperability root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, name)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &tlsKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	rootKeyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return err
	}
	tlsKeyDER, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name, typ string
		der       []byte
	}{{rootCertFile, "CERTIFICATE", rootDER}, {rootKeyFile, "EC PRIVATE KEY", rootKeyDER},
		{tlsCertFile, "CERTIFICATE", leafDER}, {tlsKeyFile, "EC PRIVATE KEY", tlsKeyDER}} {
		if err := writePEM(filepath.Join(state, f.name), f.typ, f.der); err != nil {
			return err
		}
	}
	return nil
}

// Opens the signer over the root credentials with its SQLite record in the state directory.
func openSigner(ctx context.Context, credentials, state string) (*signer, error) {
	keyDER, err := readPEM(filepath.Join(credentials, rootKeyFile), "EC PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	rootDER, err := readPEM(filepath.Join(credentials, rootCertFile), "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	location := url.URL{Scheme: "file", Path: filepath.Join(state, "ca.sqlite")}
	location.RawQuery = url.Values{"_pragma": {"journal_mode(WAL)", "synchronous(FULL)", "busy_timeout(5000)"},
		"_txlock": {"immediate"}}.Encode()
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS issuance (operation TEXT PRIMARY KEY, der BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS revocation (
			operation TEXT PRIMARY KEY, serial TEXT NOT NULL, reason INTEGER NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return nil, errors.Join(err, db.Close())
		}
	}
	return &signer{key: key, root: root, db: db}, nil
}

// Names where credentials are read and where SQLite state is kept.
type paths struct {
	credentials string
	state       string
}

// Builds the HTTP-01 server over the given directories with the fixed validation addresses.
func newServer(ctx context.Context, dirs paths, baseURL string, resolve pairs, allowed []netip.Prefix, logger *slog.Logger) (*acmeserver.Server, func(), error) {
	resolver := staticResolver{}
	for name, target := range resolve {
		addr, err := netip.ParseAddr(target)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve %s: %w", name, err)
		}
		resolver[name] = addr
	}
	network := challenge.NetworkOptions{Resolver: resolver, AllowedNetworks: allowed}
	validator, err := challenge.NewHTTP01(challenge.HTTPOptions{Network: network})
	if err != nil {
		return nil, nil, err
	}
	ca, err := openSigner(ctx, dirs.credentials, dirs.state)
	if err != nil {
		return nil, nil, err
	}
	store, err := sqlitestore.Open(ctx, filepath.Join(dirs.state, "acme.sqlite"))
	if err != nil {
		return nil, nil, errors.Join(err, ca.db.Close())
	}
	closeAll := func() {
		if err := errors.Join(store.Close(), ca.db.Close()); err != nil {
			logger.Error("closing state", "error", err)
		}
	}
	server, err := acmeserver.New(acmeserver.Config{BaseURL: baseURL, Store: store, Nonces: nonce.New(nonce.Options{}),
		Issuer: ca, Revoker: ca, Logger: logger,
		Validators: map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: validator},
		Workers: acmeserver.WorkerConfig{PollInterval: 200 * time.Millisecond, RetryDelay: 2 * time.Second,
			TaskTimeout: 15 * time.Second}})
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	return server, closeAll, nil
}

// Serves HTTPS and runs the worker until a termination signal arrives.
func serve(ctx context.Context, listen, credentials string, server *acmeserver.Server, logger *slog.Logger) error {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(credentials, tlsCertFile),
		filepath.Join(credentials, tlsKeyFile))
	if err != nil {
		return err
	}
	https := &http.Server{Addr: listen, Handler: server, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- server.Run(ctx) }()
	go func() {
		logger.Info("serving", "listen", listen)
		if err := https.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	var first error
	select {
	case <-ctx.Done():
	case first = <-errs:
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := https.Shutdown(shutdown); err != nil && first == nil {
		first = err
	}
	return first
}

// Parses the flags and runs the requested mode.
func run() error {
	initialize := flag.Bool("init", false, "create the root and HTTPS credentials in -state, then exit")
	state := flag.String("state", "", "directory for SQLite files, which -init also fills with credentials")
	credentials := flag.String("credentials", "", "directory holding the credentials, defaults to -state")
	names := flag.String("names", "", "comma-separated HTTPS server names or addresses for -init")
	listen := flag.String("listen", ":8443", "HTTPS listen address")
	baseURL := flag.String("base-url", "", "public ACME base URL ending in /acme/")
	resolve := pairs{}
	flag.Var(resolve, "resolve", "name=address answered for HTTP-01 validation, repeatable")
	var allowed []netip.Prefix
	allowUsage := "network prefix validation may reach besides public addresses, repeatable"
	flag.Func("allow", allowUsage, func(value string) error {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		allowed = append(allowed, prefix)
		return nil
	})
	flag.Parse()
	if *state == "" {
		return errors.New("-state is required")
	}
	if *initialize {
		if *names == "" {
			return errors.New("-init needs -names")
		}
		return initState(*state, strings.Split(*names, ","))
	}
	if *baseURL == "" || len(resolve) == 0 {
		return errors.New("-base-url and at least one -resolve are required")
	}
	if *credentials == "" {
		*credentials = *state
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dirs := paths{credentials: *credentials, state: *state}
	server, closeAll, err := newServer(ctx, dirs, *baseURL, resolve, allowed, logger)
	if err != nil {
		return err
	}
	defer closeAll()
	return serve(ctx, *listen, *credentials, server, logger)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "acme-server:", err)
		os.Exit(1)
	}
}
