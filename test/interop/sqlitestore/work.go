package sqlitestore

import (
	"context"
	"database/sql"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Accepts a challenge and its validation task atomically.
func (s *Store) AcceptChallenge(ctx context.Context, challenge *acmeserver.Challenge, task *acmeserver.Task) error {
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		if err := saveChallenge(ctx, c, challenge); err != nil {
			return err
		}
		return insertTask(ctx, c, task)
	})
	if err == nil {
		challenge.Revision++
		resetTask(task)
	}
	return err
}

// Accepts an immutable CSR and issuance task in the same transaction.
func (s *Store) FinalizeOrder(ctx context.Context, order *acmeserver.Order, task *acmeserver.Task) error {
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		if err := saveOrder(ctx, c, order); err != nil {
			return err
		}
		return insertTask(ctx, c, task)
	})
	if err == nil {
		order.Revision++
		resetTask(task)
	}
	return err
}

// Persists the first dispatch only if the fenced authorization snapshot is still current.
func (s *Store) BeginIssuance(ctx context.Context, task *acmeserver.Task, order *acmeserver.Order, account *acmeserver.Account, authzs []*acmeserver.Authorization) error {
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		if err := checkTask(ctx, c, task); err != nil {
			return err
		}
		if err := checkRevision(ctx, c, "accounts", account.ID, account.Revision); err != nil {
			return err
		}
		var currentAccount acmeserver.Account
		if err := read(ctx, c, "accounts", account.ID, &currentAccount); err != nil {
			return err
		}
		var currentOrder acmeserver.Order
		if err := read(ctx, c, "orders", order.ID, &currentOrder); err != nil {
			return err
		}
		if currentAccount.Status != acmeserver.AccountValid || currentOrder.Status != acmeserver.OrderProcessing ||
			currentOrder.Issuance != nil || order.Issuance == nil || len(authzs) != len(order.AuthorizationIDs) {
			return acmeserver.ErrRevisionMismatch
		}
		for i, a := range authzs {
			if err := checkRevision(ctx, c, "authorizations", a.ID, a.Revision); err != nil {
				return err
			}
			if a.ID != order.AuthorizationIDs[i] || a.Status != acmeserver.AuthorizationValid ||
				!a.Expires.After(order.Issuance.AuthorizedAt) {
				return acmeserver.ErrRevisionMismatch
			}
		}
		return saveOrder(ctx, c, order)
	})
	if err == nil {
		order.Revision++
	}
	return err
}

// Claims the earliest runnable task and advances its persistent fence under a write lock.
func (s *Store) ClaimTask(ctx context.Context, now, leaseUntil time.Time) (*acmeserver.Task, error) {
	var task acmeserver.Task
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		var data []byte
		var fence uint64
		var attempts int
		if err := c.QueryRowContext(ctx, claimTaskSQL,
			timestamp(now), timestamp(now)).Scan(&data, &fence, &attempts); err != nil {
			return err
		}
		if err := decode(data, &task); err != nil {
			return err
		}
		task.Fence = fence + 1
		task.Attempts = attempts + 1
		task.LeaseUntil = leaseUntil
		data, err := encode(&task)
		if err != nil {
			return err
		}
		_, err = c.ExecContext(ctx, updateClaimSQL,
			task.Fence, task.Attempts, timestamp(leaseUntil), data, task.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &task, nil
}

// Releases the current lease while retaining its fence and retry schedule.
func (s *Store) RescheduleTask(ctx context.Context, task *acmeserver.Task) error {
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		if err := checkTask(ctx, c, task); err != nil {
			return err
		}
		var stored acmeserver.Task
		if err := read(ctx, c, "tasks", task.ID, &stored); err != nil {
			return err
		}
		stored.RunAt = task.RunAt
		stored.LeaseUntil = time.Time{}
		data, err := encode(&stored)
		if err != nil {
			return err
		}
		_, err = c.ExecContext(ctx, rescheduleTaskSQL, timestamp(task.RunAt), data, task.ID)
		return err
	})
	if err == nil {
		task.LeaseUntil = time.Time{}
	}
	return err
}

// Removes work only when its fence still belongs to the caller.
func (s *Store) FinishTask(ctx context.Context, task *acmeserver.Task) error {
	return s.transaction(ctx, true, func(c *sql.Conn) error { return finishTask(ctx, c, task) })
}

// Completes validation and all dependent resource revisions atomically under the task fence.
func (s *Store) CompleteValidation(ctx context.Context, task *acmeserver.Task, challenge *acmeserver.Challenge, authz *acmeserver.Authorization, order *acmeserver.Order) error {
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		if err := checkTask(ctx, c, task); err != nil {
			return err
		}
		if err := saveChallenge(ctx, c, challenge); err != nil {
			return err
		}
		if err := saveAuthorization(ctx, c, authz); err != nil {
			return err
		}
		if err := saveOrder(ctx, c, order); err != nil {
			return err
		}
		return finishTask(ctx, c, task)
	})
	if err == nil {
		challenge.Revision++
		authz.Revision++
		order.Revision++
	}
	return err
}

// Persists the issued certificate or retained unpublished result with the final order state.
func (s *Store) CompleteIssuance(ctx context.Context, task *acmeserver.Task, order *acmeserver.Order, cert *acmeserver.Certificate) error {
	err := s.transaction(ctx, true, func(c *sql.Conn) error {
		if err := checkTask(ctx, c, task); err != nil {
			return err
		}
		if cert != nil {
			copyOf := *cert
			copyOf.Revision = 1
			err := insert(ctx, c, insertCertificateSQL, &copyOf, cert.ID, cert.OrderID, renewalKey(cert.RenewalID), 1)
			if err != nil {
				return err
			}
		}
		if err := saveOrder(ctx, c, order); err != nil {
			return err
		}
		return finishTask(ctx, c, task)
	})
	if err == nil {
		order.Revision++
		if cert != nil {
			cert.Revision = 1
		}
	}
	return err
}

// Counts work that was already due and unleased at the readiness cutoff.
func (s *Store) PendingTasks(ctx context.Context, before time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, pendingTasksSQL, timestamp(before), timestamp(before)).Scan(&count)
	return count, storageError(err)
}

// Initializes task lease metadata without changing its identity or schedule.
func resetTask(task *acmeserver.Task) {
	task.Fence = 0
	task.Attempts = 0
	task.LeaseUntil = time.Time{}
}

// Inserts a new unclaimed task and rejects duplicate operation IDs.
func insertTask(ctx context.Context, c *sql.Conn, task *acmeserver.Task) error {
	copyOf := *task
	resetTask(&copyOf)
	return insert(ctx, c, insertTaskSQL, &copyOf, task.ID, timestamp(task.RunAt))
}

// Rejects stale workers after another process has reclaimed the lease.
func checkTask(ctx context.Context, c *sql.Conn, task *acmeserver.Task) error {
	var fence uint64
	if err := c.QueryRowContext(ctx, taskFenceSQL, task.ID).Scan(&fence); err != nil {
		return err
	}
	if fence != task.Fence {
		return acmeserver.ErrRevisionMismatch
	}
	return nil
}

// Deletes a task only after verifying its current fence.
func finishTask(ctx context.Context, c *sql.Conn, task *acmeserver.Task) error {
	if err := checkTask(ctx, c, task); err != nil {
		return err
	}
	_, err := c.ExecContext(ctx, "DELETE FROM tasks WHERE id = ?", task.ID)
	return err
}
