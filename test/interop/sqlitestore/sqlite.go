// Package sqlitestore implements the ACME storage contract for durable interoperability tests.
package sqlitestore

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"modernc.org/sqlite"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Serializes writes through one connection while WAL permits reads from other processes.
type Store struct{ db *sql.DB }

// Holds the account key as portable DER instead of an interface-valued cryptographic object.
type storedAccount struct {
	Account acmeserver.Account
	Key     []byte
}

// Opens a durable database with full synchronization, foreign keys and immediate write transactions.
func Open(ctx context.Context, path string) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	location := url.URL{Scheme: "file", Path: absolute}
	query := url.Values{}
	for _, pragma := range []string{"journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(ON)", "busy_timeout(5000)"} {
		query.Add("_pragma", pragma)
	}
	location.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	err = store.transaction(ctx, true, func(connection *sql.Conn) error {
		_, err := connection.ExecContext(ctx, schema)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Closes the database connections without deleting persisted state.
func (s *Store) Close() error { return s.db.Close() }

// Defines resource ownership, unique account keys and indexes used for claims and authorization checks.
const schema = `
CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, key_thumbprint TEXT
UNIQUE NOT NULL, external_claim TEXT UNIQUE, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS orders (sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
account_id TEXT NOT NULL REFERENCES accounts(id), revision INTEGER NOT NULL, data BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS account_orders ON orders(account_id, sequence);
CREATE TABLE IF NOT EXISTS authorizations (id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES
accounts(id), order_id TEXT NOT NULL REFERENCES orders(id), scope TEXT NOT NULL, status TEXT NOT NULL, expires
INTEGER NOT NULL, revision INTEGER NOT NULL, data BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS authorization_scope ON authorizations(account_id, scope, status, expires);
CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL REFERENCES
authorizations(id), revision INTEGER NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS certificates (id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id),
revision INTEGER NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS tasks (sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, run_at
INTEGER NOT NULL, lease_until INTEGER NOT NULL, fence INTEGER NOT NULL, attempts INTEGER NOT NULL, data BLOB
NOT NULL);
CREATE INDEX IF NOT EXISTS runnable_tasks ON tasks(run_at, lease_until, sequence);
`

// Commits one consistent operation or rolls it back without exposing partial caller revisions.
func (s *Store) transaction(ctx context.Context, write bool, operation func(*sql.Conn) error) error {
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return storageError(err)
	}
	defer func() { _ = connection.Close() }()
	begin := "BEGIN"
	if write {
		begin = "BEGIN IMMEDIATE"
	}
	if _, err := connection.ExecContext(ctx, begin); err != nil {
		return storageError(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, _ = connection.ExecContext(cleanup, "ROLLBACK")
	}()
	if err := operation(connection); err != nil {
		return storageError(err)
	}
	_, err = connection.ExecContext(ctx, "COMMIT")
	return storageError(err)
}

// Maps absence, uniqueness and temporary SQLite lock conflicts to distinct storage outcomes.
func storageError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return acmeserver.ErrNotFound
	}
	if sqliteError, ok := errors.AsType[*sqlite.Error](err); ok {
		switch sqliteError.Code() {
		case 1555, 2067:
			return acmeserver.ErrConflict
		}
		if code := sqliteError.Code() & 255; code == 5 || code == 6 {
			return acmeserver.ErrRevisionMismatch
		}
	}
	return err
}

// Encodes a resource while preserving error metadata and structural ownership.
func encode(value any) ([]byte, error) {
	if account, ok := value.(*acmeserver.Account); ok {
		key, err := x509.MarshalPKIXPublicKey(account.Key)
		if err != nil {
			return nil, err
		}
		copyOf := *account
		copyOf.Key = nil
		value = &storedAccount{Account: copyOf, Key: key}
	}
	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(value)
	return buffer.Bytes(), err
}

// Decodes a resource into an owned value and restores account public keys from DER.
func decode(data []byte, value any) error {
	if account, ok := value.(*acmeserver.Account); ok {
		var stored storedAccount
		if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&stored); err != nil {
			return err
		}
		key, err := x509.ParsePKIXPublicKey(stored.Key)
		if err != nil {
			return err
		}
		*account = stored.Account
		account.Key = key
		return nil
	}
	return gob.NewDecoder(bytes.NewReader(data)).Decode(value)
}

// Provides the query operations shared by connections and the database handle.
type reader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Loads an owned resource from a fixed internal table name.
func read(ctx context.Context, query reader, table, id string, value any) error {
	var data []byte
	if err := query.QueryRowContext(ctx, "SELECT data FROM "+table+" WHERE id = ?", id).Scan(&data); err != nil {
		return storageError(err)
	}
	return decode(data, value)
}

// Requires an existing resource at the caller's expected revision.
func checkRevision(ctx context.Context, query reader, table, id string, revision uint64) error {
	var current uint64
	if err := query.QueryRowContext(ctx, "SELECT revision FROM "+table+" WHERE id = ?", id).Scan(&current); err != nil {
		return storageError(err)
	}
	if current != revision {
		return acmeserver.ErrRevisionMismatch
	}
	return nil
}

// Inserts an encoded resource using internal SQL and bound values.
func insert(ctx context.Context, connection *sql.Conn, statement string, value any, args ...any) error {
	data, err := encode(value)
	if err != nil {
		return err
	}
	_, err = connection.ExecContext(ctx, statement, append(args, data)...)
	return err
}

// Updates the encoded resource after its revision was checked within the immediate transaction.
func update(ctx context.Context, connection *sql.Conn, table, id string, revision uint64, value any) error {
	if err := checkRevision(ctx, connection, table, id, revision); err != nil {
		return err
	}
	data, err := encode(value)
	if err != nil {
		return err
	}
	// Table names are internal constants and every caller value is bound.
	//nolint:gosec
	_, err = connection.ExecContext(ctx, "UPDATE "+table+" SET revision = ?, data = ? WHERE id = ?", revision+1, data, id)
	return err
}

// Returns a stable index value for the complete authorization scope.
func scope(identifier acmeserver.Identifier, wildcard bool) string {
	if wildcard {
		identifier.Value = "*." + identifier.Value
	}
	return identifier.String()
}

// Encodes unset lease times as zero for runnable-task comparisons.
func timestamp(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
}

// Verifies that this adapter supplies every public storage operation.
var _ acmeserver.Store = (*Store)(nil)

// Returns the configured SQLite pragmas for reproducibility checks.
func (s *Store) Settings(ctx context.Context) (string, error) {
	var journal string
	var synchronous, foreignKeys, busy int
	for _, item := range []struct {
		query string
		value any
	}{
		{"PRAGMA journal_mode", &journal}, {"PRAGMA synchronous", &synchronous},
		{"PRAGMA foreign_keys", &foreignKeys}, {"PRAGMA busy_timeout", &busy},
	} {
		if err := s.db.QueryRowContext(ctx, item.query).Scan(item.value); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("journal=%s synchronous=%d foreign_keys=%d busy_timeout=%d",
		journal, synchronous, foreignKeys, busy), nil
}
