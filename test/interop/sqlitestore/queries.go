package sqlitestore

// Fixed SQL statements bind every resource value supplied by callers.
const (
	insertAccountSQL = `INSERT INTO accounts(id, revision, key_thumbprint, external_claim, data)
VALUES (?, ?, ?, ?, ?)`
	accountByKeySQL        = `SELECT data FROM accounts WHERE key_thumbprint = ?`
	updateAccountKeySQL    = `UPDATE accounts SET key_thumbprint = ?, external_claim = ? WHERE id = ?`
	insertOrderSQL         = `INSERT INTO orders(id, account_id, revision, data) VALUES (?, ?, ?, ?)`
	insertAuthorizationSQL = `INSERT INTO authorizations
(id, account_id, order_id, scope, status, expires, revision, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	insertChallengeSQL = `INSERT INTO challenges(id, authorization_id, revision, data) VALUES (?, ?, ?, ?)`
	orderCursorSQL     = `SELECT sequence FROM orders WHERE id = ? AND account_id = ?`
	accountOrdersSQL   = `SELECT id FROM orders WHERE account_id = ? AND sequence > ? ORDER BY sequence LIMIT ?`
	authorizedScopeSQL = `SELECT 1 FROM authorizations
WHERE account_id = ? AND scope = ? AND status = ? AND expires > ? LIMIT 1`
	updateAuthorizationIndexSQL = `UPDATE authorizations SET scope = ?, status = ?, expires = ? WHERE id = ?`
	claimTaskSQL                = `SELECT data, fence, attempts FROM tasks
WHERE run_at <= ? AND lease_until <= ? ORDER BY run_at, sequence LIMIT 1`
	updateClaimSQL          = `UPDATE tasks SET fence = ?, attempts = ?, lease_until = ?, data = ? WHERE id = ?`
	rescheduleTaskSQL       = `UPDATE tasks SET run_at = ?, lease_until = 0, data = ? WHERE id = ?`
	insertCertificateSQL    = `INSERT INTO certificates(id, order_id, renewal_id, revision, data) VALUES (?, ?, ?, ?, ?)`
	certificateByRenewalSQL = `SELECT id, revision, data FROM certificates WHERE renewal_id = ?`
	pendingTasksSQL         = `SELECT count(*) FROM tasks WHERE run_at <= ? AND lease_until <= ?`
	insertTaskSQL           = `INSERT INTO tasks(id, run_at, lease_until, fence, attempts, data) VALUES (?, ?, 0, 0, 0, ?)`
	taskFenceSQL            = `SELECT fence FROM tasks WHERE id = ?`
)
