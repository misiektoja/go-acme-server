package interop

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Keeps signing keys and idempotent issuance results across worker process deaths.
type durableCA struct {
	key  *ecdsa.PrivateKey
	root *x509.Certificate
	db   *sql.DB
}

// Generates an ephemeral P-256 key for a test identity.
func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Writes a retained private artifact with permissions restricted to the current user.
func writePrivate(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// Generates the CA and HTTPS credentials before any worker process starts.
func createCA(t *testing.T, directory string) {
	t.Helper()
	key := newKey(t)
	now := time.Now().Truncate(time.Second)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ACME interoperability root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(directory, "ca-key.der"), keyDER)
	writePrivate(t, filepath.Join(directory, "ca-cert.der"), der)
}

// Opens the independent CA database with serializable deduplication by operation ID.
func openCA(t *testing.T, directory string) *durableCA {
	t.Helper()
	keyDER, err := os.ReadFile(filepath.Join(directory, "ca-key.der"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	der, err := os.ReadFile(filepath.Join(directory, "ca-cert.der"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	location := url.URL{Scheme: "file", Path: filepath.Join(directory, "ca.sqlite")}
	location.RawQuery = url.Values{"_pragma": {"journal_mode(WAL)", "synchronous(FULL)", "busy_timeout(5000)"}, "_txlock": {"immediate"}}.Encode()
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	_, err = db.ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS issuance (operation TEXT PRIMARY KEY, csr_hash BLOB NOT NULL, der BLOB NOT NULL, calls INTEGER NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS revocation (operation TEXT PRIMARY KEY, serial TEXT UNIQUE NOT NULL, reason INTEGER NOT NULL, calls INTEGER NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	return &durableCA{key: key, root: root, db: db}
}

// Signs once per operation and returns the same DER after a process restart.
func (ca *durableCA) Issue(ctx context.Context, req acmeserver.IssueRequest) (acmeserver.IssueResult, error) {
	tx, err := ca.db.BeginTx(ctx, nil)
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	defer tx.Rollback()
	digest := sha256.Sum256(req.CSRDER)
	var der, storedHash []byte
	err = tx.QueryRowContext(ctx, "SELECT der, csr_hash FROM issuance WHERE operation = ?", req.OperationID).Scan(&der, &storedHash)
	if err == nil {
		if !bytes.Equal(digest[:], storedHash) {
			return acmeserver.IssueResult{}, errors.New("operation changed its CSR")
		}
		_, err = tx.ExecContext(ctx, "UPDATE issuance SET calls = calls + 1 WHERE operation = ?", req.OperationID)
	} else if errors.Is(err, sql.ErrNoRows) {
		if req.RecoveryOnly || !req.Deadline.After(time.Now()) {
			return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorUnauthorized, "signing deadline elapsed")}, nil
		}
		der, err = ca.sign(req)
		if err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO issuance VALUES (?, ?, ?, 1)", req.OperationID, digest[:], der)
		}
	}
	if err != nil {
		return acmeserver.IssueResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return acmeserver.IssueResult{}, err
	}
	return acmeserver.IssueResult{Chain: [][]byte{der, ca.root.Raw}, CAReference: req.OperationID}, nil
}

// The id-pe-TNAuthList certificate extension of RFC 8226 section 9.
var tnAuthListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26}

// Issues only the identifiers and validity accepted by the server.
func (ca *durableCA) sign(req acmeserver.IssueRequest) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
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
			value, err := base64.RawURLEncoding.DecodeString(id.Value)
			if err != nil {
				return nil, err
			}
			leaf.ExtraExtensions = append(leaf.ExtraExtensions, pkix.Extension{Id: tnAuthListOID, Value: value})
		}
	}
	return x509.CreateCertificate(rand.Reader, leaf, ca.root, req.CSR.PublicKey, ca.key)
}

// Records the revocation durably once per operation ID, counting repeated calls. A second
// operation for an already revoked serial fails because the server must not start one.
func (ca *durableCA) Revoke(ctx context.Context, req acmeserver.RevokeRequest) error {
	if req.OperationID == "" {
		return errors.New("revocation without an operation ID")
	}
	_, err := ca.db.ExecContext(ctx, `INSERT INTO revocation VALUES (?, ?, ?, 1) ON CONFLICT(operation) DO UPDATE SET calls = calls + 1`,
		req.OperationID, req.Certificate.SerialNumber.String(), req.Reason)
	return err
}
