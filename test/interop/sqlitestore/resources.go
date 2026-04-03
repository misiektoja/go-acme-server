package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Atomically registers one account and its unique public-key thumbprint.
func (s *Store) CreateAccount(ctx context.Context, account *acmeserver.Account) error {
	if account.ID == "" || account.KeyThumbprint == "" {
		return errors.New("sqlitestore: account ID and thumbprint are required")
	}
	copyOf := *account
	copyOf.Revision = 1
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		return insert(ctx, c,
			insertAccountSQL, &copyOf, copyOf.ID, 1, copyOf.KeyThumbprint)
	})
	if err == nil {
		account.Revision = 1
	}
	return err
}

// Loads an account by opaque ID.
func (s *Store) Account(ctx context.Context, id string) (*acmeserver.Account, error) {
	var account acmeserver.Account
	err := read(ctx, s.db, "accounts", id, &account)
	return &account, err
}

// Loads an account by its unique current thumbprint.
func (s *Store) AccountByKey(ctx context.Context, thumbprint string) (*acmeserver.Account, error) {
	var account acmeserver.Account
	var data []byte
	if err := s.db.QueryRowContext(ctx, accountByKeySQL, thumbprint).Scan(&data); err != nil {
		return nil, storageError(err)
	}
	err := decode(data, &account)
	return &account, err
}

// Replaces account state and its unique key index at the expected revision.
func (s *Store) UpdateAccount(ctx context.Context, account *acmeserver.Account) error {
	copyOf := *account
	copyOf.Revision++
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		if err := update(ctx, c, "accounts", account.ID, account.Revision, &copyOf); err != nil {
			return err
		}
		_, err := c.ExecContext(ctx, updateAccountKeySQL, account.KeyThumbprint, account.ID)
		return err
	})
	if err == nil {
		account.Revision = copyOf.Revision
	}
	return err
}

// Creates an order and every authorization and challenge in one immediate transaction.
func (s *Store) CreateOrder(ctx context.Context, order *acmeserver.Order, authzs []*acmeserver.Authorization, challenges []*acmeserver.Challenge) error {
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		copyOf := *order
		copyOf.Revision = 1
		if err := insert(ctx, c, insertOrderSQL, &copyOf, order.ID, order.AccountID, 1); err != nil {
			return err
		}
		for _, a := range authzs {
			copyOf := *a
			copyOf.Revision = 1
			if err := insert(ctx, c, insertAuthorizationSQL,
				&copyOf, a.ID, a.AccountID, a.OrderID, scope(a.Identifier, a.Wildcard),
				string(a.Status), timestamp(a.Expires), 1); err != nil {
				return err
			}
		}
		for _, ch := range challenges {
			copyOf := *ch
			copyOf.Revision = 1
			if err := insert(ctx, c, insertChallengeSQL, &copyOf, ch.ID, ch.AuthorizationID, 1); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		order.Revision = 1
		for _, a := range authzs {
			a.Revision = 1
		}
		for _, ch := range challenges {
			ch.Revision = 1
		}
	}
	return err
}

// Loads an owned order including its durable issuance decision and unpublished result.
func (s *Store) Order(ctx context.Context, id string) (*acmeserver.Order, error) {
	var order acmeserver.Order
	err := read(ctx, s.db, "orders", id, &order)
	return &order, err
}

// Lists account order IDs in insertion order with an account-bound cursor.
func (s *Store) OrderIDs(ctx context.Context, accountID, after string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, errors.New("sqlitestore: limit must be positive")
	}
	ids := []string{}
	err := s.transaction(ctx, false, func(c *sql.Conn) error {
		sequence := int64(0)
		if after != "" {
			if err := c.QueryRowContext(ctx, orderCursorSQL, after, accountID).Scan(&sequence); err != nil {
				return err
			}
		}
		rows, err := c.QueryContext(ctx, accountOrdersSQL, accountID, sequence, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// Loads an owned authorization.
func (s *Store) Authorization(ctx context.Context, id string) (*acmeserver.Authorization, error) {
	var authorization acmeserver.Authorization
	err := read(ctx, s.db, "authorizations", id, &authorization)
	return &authorization, err
}

// Updates authorization state and invalidates any order that has not dispatched issuance.
func (s *Store) UpdateAuthorization(ctx context.Context, a *acmeserver.Authorization) error {
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		if err := saveAuthorization(ctx, c, a); err != nil {
			return err
		}
		if !a.Status.Terminal() {
			return nil
		}
		var order acmeserver.Order
		if err := read(ctx, c, "orders", a.OrderID, &order); err != nil {
			return err
		}
		if order.Status.Terminal() || order.Issuance != nil {
			return nil
		}
		order.Status = acmeserver.OrderInvalid
		return saveOrder(ctx, c, &order)
	})
	if err == nil {
		a.Revision++
	}
	return err
}

// Checks all requested scopes in one consistent read transaction.
func (s *Store) AuthorizedFor(ctx context.Context, accountID string, identifiers []acmeserver.Identifier, now time.Time) (bool, error) {
	allowed := len(identifiers) > 0
	err := s.transaction(ctx, false, func(c *sql.Conn) error {
		var account acmeserver.Account
		if err := read(ctx, c, "accounts", accountID, &account); errors.Is(err, acmeserver.ErrNotFound) {
			allowed = false
			return nil
		} else if err != nil {
			return err
		}
		if account.Status != acmeserver.AccountValid {
			allowed = false
			return nil
		}
		for _, id := range identifiers {
			var found int
			err := c.QueryRowContext(ctx, authorizedScopeSQL,
				accountID, scope(id, false), string(acmeserver.AuthorizationValid), timestamp(now)).Scan(&found)
			if errors.Is(err, sql.ErrNoRows) {
				allowed = false
				return nil
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	return allowed, err
}

// Loads an owned challenge.
func (s *Store) Challenge(ctx context.Context, id string) (*acmeserver.Challenge, error) {
	var challenge acmeserver.Challenge
	err := read(ctx, s.db, "challenges", id, &challenge)
	return &challenge, err
}

// Loads an owned certificate and its revocation metadata.
func (s *Store) Certificate(ctx context.Context, id string) (*acmeserver.Certificate, error) {
	var certificate acmeserver.Certificate
	err := read(ctx, s.db, "certificates", id, &certificate)
	return &certificate, err
}

// Replaces certificate metadata at the expected revision.
func (s *Store) UpdateCertificate(ctx context.Context, certificate *acmeserver.Certificate) error {
	copyOf := *certificate
	copyOf.Revision++
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		return update(ctx, c, "certificates", certificate.ID, certificate.Revision, &copyOf)
	})
	if err == nil {
		certificate.Revision++
	}
	return err
}

// Saves order state without changing the caller until its transaction commits.
func saveOrder(ctx context.Context, c *sql.Conn, order *acmeserver.Order) error {
	copyOf := *order
	copyOf.Revision++
	return update(ctx, c, "orders", order.ID, order.Revision, &copyOf)
}

// Saves challenge state without changing the caller until its transaction commits.
func saveChallenge(ctx context.Context, c *sql.Conn, challenge *acmeserver.Challenge) error {
	copyOf := *challenge
	copyOf.Revision++
	return update(ctx, c, "challenges", challenge.ID, challenge.Revision, &copyOf)
}

// Saves authorization state and its current proof-scope index together.
func saveAuthorization(ctx context.Context, c *sql.Conn, a *acmeserver.Authorization) error {
	copyOf := *a
	copyOf.Revision++
	if err := update(ctx, c, "authorizations", a.ID, a.Revision, &copyOf); err != nil {
		return err
	}
	_, err := c.ExecContext(ctx, updateAuthorizationIndexSQL, scope(a.Identifier, a.Wildcard),
		string(a.Status), timestamp(a.Expires), a.ID)
	return err
}
