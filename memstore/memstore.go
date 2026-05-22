// Package memstore provides an in-memory acmeserver.Store for tests and examples.
package memstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math/big"
	"slices"
	"sync"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// An in-memory Store. The zero value is not usable, call New.
type Store struct {
	mu           sync.RWMutex
	accounts     map[string]*acmeserver.Account
	accountByKey map[string]string
	// Maps single-use external account claims to account IDs.
	accountByClaim map[string]string
	orders         map[string]*acmeserver.Order
	orderIDs       map[string][]string
	authzs         map[string]*acmeserver.Authorization
	authzIndex     map[authorizationKey][]string
	challenges     map[string]*acmeserver.Challenge
	certificates   map[string]*acmeserver.Certificate
	tasks          map[string]*acmeserver.Task
	taskSequence   uint64
	taskInsertion  map[string]uint64
}

// Indexes authorizations by account and complete identifier, including wildcard scope.
type authorizationKey struct {
	accountID  string
	identifier acmeserver.Identifier
}

// Returns an empty Store.
func New() *Store {
	return &Store{
		accounts:       make(map[string]*acmeserver.Account),
		accountByKey:   make(map[string]string),
		accountByClaim: make(map[string]string),
		orders:         make(map[string]*acmeserver.Order),
		orderIDs:       make(map[string][]string),
		authzs:         make(map[string]*acmeserver.Authorization),
		authzIndex:     make(map[authorizationKey][]string),
		challenges:     make(map[string]*acmeserver.Challenge),
		certificates:   make(map[string]*acmeserver.Certificate),
		tasks:          make(map[string]*acmeserver.Task),
		taskInsertion:  make(map[string]uint64),
	}
}

// Stores a copy of the account with revision 1.
func (s *Store) CreateAccount(ctx context.Context, account *acmeserver.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if account.ID == "" || account.KeyThumbprint == "" {
		return errors.New("memstore: account needs an ID and a key thumbprint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[account.ID]; exists {
		return acmeserver.ErrConflict
	}
	if _, exists := s.accountByKey[account.KeyThumbprint]; exists {
		return acmeserver.ErrConflict
	}
	if _, exists := s.accountByClaim[account.ExternalAccountClaim]; exists && account.ExternalAccountClaim != "" {
		return acmeserver.ErrConflict
	}
	account.Revision = 1
	s.accounts[account.ID] = cloneAccount(account)
	s.accountByKey[account.KeyThumbprint] = account.ID
	if account.ExternalAccountClaim != "" {
		s.accountByClaim[account.ExternalAccountClaim] = account.ID
	}
	return nil
}

// Returns a copy of the account with the given ID.
func (s *Store) Account(ctx context.Context, id string) (*acmeserver.Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	account, ok := s.accounts[id]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return cloneAccount(account), nil
}

// Returns a copy of the account whose key has the given thumbprint.
func (s *Store) AccountByKey(ctx context.Context, thumbprint string) (*acmeserver.Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.accountByKey[thumbprint]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return cloneAccount(s.accounts[id]), nil
}

// Replaces the stored account when the revision matches.
func (s *Store) UpdateAccount(ctx context.Context, account *acmeserver.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if account.KeyThumbprint == "" {
		return errors.New("memstore: account needs a key thumbprint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.accounts[account.ID]
	if !ok {
		return acmeserver.ErrNotFound
	}
	if stored.Revision != account.Revision {
		return acmeserver.ErrRevisionMismatch
	}
	if account.KeyThumbprint != stored.KeyThumbprint {
		if owner, exists := s.accountByKey[account.KeyThumbprint]; exists && owner != account.ID {
			return acmeserver.ErrConflict
		}
	}
	if account.ExternalAccountClaim != stored.ExternalAccountClaim && account.ExternalAccountClaim != "" {
		if owner, exists := s.accountByClaim[account.ExternalAccountClaim]; exists && owner != account.ID {
			return acmeserver.ErrConflict
		}
	}
	delete(s.accountByKey, stored.KeyThumbprint)
	s.accountByKey[account.KeyThumbprint] = account.ID
	delete(s.accountByClaim, stored.ExternalAccountClaim)
	if account.ExternalAccountClaim != "" {
		s.accountByClaim[account.ExternalAccountClaim] = account.ID
	}
	account.Revision++
	s.accounts[account.ID] = cloneAccount(account)
	return nil
}

// Stores the order, its authorizations and its challenges at revision 1.
func (s *Store) CreateOrder(ctx context.Context, order *acmeserver.Order, authzs []*acmeserver.Authorization,
	challenges []*acmeserver.Challenge) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if order.ID == "" || order.AccountID == "" {
		return errors.New("memstore: order needs an ID and an account ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.orders[order.ID]; exists {
		return acmeserver.ErrConflict
	}
	for _, a := range authzs {
		if _, exists := s.authzs[a.ID]; exists || a.ID == "" {
			return acmeserver.ErrConflict
		}
	}
	for _, c := range challenges {
		if _, exists := s.challenges[c.ID]; exists || c.ID == "" {
			return acmeserver.ErrConflict
		}
	}
	order.Revision = 1
	s.orders[order.ID] = cloneOrder(order)
	s.orderIDs[order.AccountID] = append(s.orderIDs[order.AccountID], order.ID)
	for _, a := range authzs {
		a.Revision = 1
		s.authzs[a.ID] = cloneAuthorization(a)
		key := authorizationIndexKey(a)
		s.authzIndex[key] = append(s.authzIndex[key], a.ID)
	}
	for _, c := range challenges {
		c.Revision = 1
		s.challenges[c.ID] = cloneChallenge(c)
	}
	return nil
}

// Returns a copy of the order with the given ID.
func (s *Store) Order(ctx context.Context, id string) (*acmeserver.Order, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	order, ok := s.orders[id]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return cloneOrder(order), nil
}

// Returns up to limit order IDs of the account after the given ID.
func (s *Store) OrderIDs(ctx context.Context, accountID, after string, limit int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, errors.New("memstore: limit must be positive")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.orderIDs[accountID]
	start := 0
	if after != "" {
		pos := slices.Index(ids, after)
		if pos < 0 {
			return nil, acmeserver.ErrNotFound
		}
		start = pos + 1
	}
	end := min(start+limit, len(ids))
	return slices.Clone(ids[start:end]), nil
}

// Returns a copy of the authorization with the given ID.
func (s *Store) Authorization(ctx context.Context, id string) (*acmeserver.Authorization, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	authz, ok := s.authzs[id]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return cloneAuthorization(authz), nil
}

// Replaces the stored authorization when the revision matches.
func (s *Store) UpdateAuthorization(ctx context.Context, authz *acmeserver.Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkAuthorization(authz); err != nil {
		return err
	}
	authz.Revision++
	s.authzs[authz.ID] = cloneAuthorization(authz)
	if authz.Status.Terminal() {
		order := s.orders[authz.OrderID]
		if order != nil && (order.Status == acmeserver.OrderPending || order.Status == acmeserver.OrderReady ||
			(order.Status == acmeserver.OrderProcessing && order.Issuance == nil)) {
			order.Status = acmeserver.OrderInvalid
			order.Revision++
		}
	}
	return nil
}

// Records a fenced dispatch only while the account, order and authorizations match the checked snapshot.
func (s *Store) BeginIssuance(ctx context.Context, task *acmeserver.Task, order *acmeserver.Order, account *acmeserver.Account, authzs []*acmeserver.Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.checkTask(task); err != nil {
		return err
	}
	if err := s.checkOrder(order); err != nil {
		return err
	}
	stored := s.accounts[account.ID]
	if stored == nil || stored.Revision != account.Revision || stored.Status != acmeserver.AccountValid {
		return acmeserver.ErrRevisionMismatch
	}
	if order.Issuance == nil || s.orders[order.ID].Status != acmeserver.OrderProcessing ||
		s.orders[order.ID].Issuance != nil || len(authzs) != len(order.AuthorizationIDs) {
		return acmeserver.ErrRevisionMismatch
	}
	for i, a := range authzs {
		if err := s.checkAuthorization(a); err != nil {
			return err
		}
		if a.ID != order.AuthorizationIDs[i] || a.Status != acmeserver.AuthorizationValid ||
			!a.Expires.After(order.Issuance.AuthorizedAt) {
			return acmeserver.ErrRevisionMismatch
		}
	}
	order.Revision++
	s.orders[order.ID] = cloneOrder(order)
	return nil
}

// Returns the index key for the complete scope of an authorization.
func authorizationIndexKey(a *acmeserver.Authorization) authorizationKey {
	id := a.Identifier
	if a.Wildcard {
		id.Value = "*." + id.Value
	}
	return authorizationKey{accountID: a.AccountID, identifier: id}
}

// Checks every identifier against one consistent snapshot of current authorization state.
func (s *Store) AuthorizedFor(ctx context.Context, accountID string, identifiers []acmeserver.Identifier, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	account, ok := s.accounts[accountID]
	if !ok || account.Status != acmeserver.AccountValid || len(identifiers) == 0 {
		return false, nil
	}
	for _, identifier := range identifiers {
		valid := false
		for _, id := range s.authzIndex[authorizationKey{accountID: accountID, identifier: identifier}] {
			a := s.authzs[id]
			if a.Status == acmeserver.AuthorizationValid && a.Expires.After(now) {
				valid = true
				break
			}
		}
		if !valid {
			return false, nil
		}
	}
	return true, nil
}

// Returns a copy of the challenge with the given ID.
func (s *Store) Challenge(ctx context.Context, id string) (*acmeserver.Challenge, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	challenge, ok := s.challenges[id]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return cloneChallenge(challenge), nil
}

// Returns a copy of the certificate with the given ID.
func (s *Store) Certificate(ctx context.Context, id string) (*acmeserver.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, ok := s.certificates[id]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	return cloneCertificate(cert), nil
}

// Replaces the stored certificate when the revision matches.
func (s *Store) UpdateCertificate(ctx context.Context, cert *acmeserver.Certificate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.certificates[cert.ID]
	if !ok {
		return acmeserver.ErrNotFound
	}
	if stored.Revision != cert.Revision {
		return acmeserver.ErrRevisionMismatch
	}
	cert.Revision++
	s.certificates[cert.ID] = cloneCertificate(cert)
	return nil
}

// Stores the challenge and enqueues the task together.
func (s *Store) AcceptChallenge(ctx context.Context, challenge *acmeserver.Challenge, task *acmeserver.Task) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkChallenge(challenge); err != nil {
		return err
	}
	if err := s.checkNewTask(task); err != nil {
		return err
	}
	challenge.Revision++
	s.challenges[challenge.ID] = cloneChallenge(challenge)
	s.insertTask(task)
	return nil
}

// Stores the order and enqueues the task together.
func (s *Store) FinalizeOrder(ctx context.Context, order *acmeserver.Order, task *acmeserver.Task) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrder(order); err != nil {
		return err
	}
	if err := s.checkNewTask(task); err != nil {
		return err
	}
	order.Revision++
	s.orders[order.ID] = cloneOrder(order)
	s.insertTask(task)
	return nil
}

// Leases the runnable task with the earliest RunAt.
func (s *Store) ClaimTask(ctx context.Context, now, leaseUntil time.Time) (*acmeserver.Task, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *acmeserver.Task
	for _, t := range s.tasks {
		if t.RunAt.After(now) || (!t.LeaseUntil.IsZero() && t.LeaseUntil.After(now)) {
			continue
		}
		if best == nil || t.RunAt.Before(best.RunAt) ||
			(t.RunAt.Equal(best.RunAt) && s.taskInsertion[t.ID] < s.taskInsertion[best.ID]) {
			best = t
		}
	}
	if best == nil {
		return nil, acmeserver.ErrNotFound
	}
	best.LeaseUntil = leaseUntil
	best.Fence++
	best.Attempts++
	return cloneTask(best), nil
}

// Releases the lease and stores the next run time.
func (s *Store) RescheduleTask(ctx context.Context, task *acmeserver.Task) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.checkTask(task)
	if err != nil {
		return err
	}
	stored.RunAt = task.RunAt
	stored.LeaseUntil = time.Time{}
	task.LeaseUntil = time.Time{}
	return nil
}

// Removes the task.
func (s *Store) FinishTask(ctx context.Context, task *acmeserver.Task) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.checkTask(task); err != nil {
		return err
	}
	s.removeTask(task.ID)
	return nil
}

// Stores the validation outcome and removes the task together.
func (s *Store) CompleteValidation(ctx context.Context, task *acmeserver.Task, challenge *acmeserver.Challenge,
	authz *acmeserver.Authorization, order *acmeserver.Order) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.checkTask(task); err != nil {
		return err
	}
	if err := s.checkChallenge(challenge); err != nil {
		return err
	}
	if err := s.checkAuthorization(authz); err != nil {
		return err
	}
	if err := s.checkOrder(order); err != nil {
		return err
	}
	challenge.Revision++
	authz.Revision++
	order.Revision++
	s.challenges[challenge.ID] = cloneChallenge(challenge)
	s.authzs[authz.ID] = cloneAuthorization(authz)
	s.orders[order.ID] = cloneOrder(order)
	s.removeTask(task.ID)
	return nil
}

// Stores the issuance outcome and removes the task together.
func (s *Store) CompleteIssuance(ctx context.Context, task *acmeserver.Task, order *acmeserver.Order,
	cert *acmeserver.Certificate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.checkTask(task); err != nil {
		return err
	}
	if err := s.checkOrder(order); err != nil {
		return err
	}
	if cert != nil {
		if cert.ID == "" {
			return errors.New("memstore: certificate needs an ID")
		}
		if _, exists := s.certificates[cert.ID]; exists {
			return acmeserver.ErrConflict
		}
		cert.Revision = 1
		s.certificates[cert.ID] = cloneCertificate(cert)
	}
	order.Revision++
	s.orders[order.ID] = cloneOrder(order)
	s.removeTask(task.ID)
	return nil
}

// Counts runnable tasks without an active lease.
func (s *Store) PendingTasks(ctx context.Context, before time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, t := range s.tasks {
		if !t.RunAt.After(before) && (t.LeaseUntil.IsZero() || !t.LeaseUntil.After(before)) {
			n++
		}
	}
	return n, nil
}

// Checks that the order exists at the given revision.
func (s *Store) checkOrder(order *acmeserver.Order) error {
	stored, ok := s.orders[order.ID]
	if !ok {
		return acmeserver.ErrNotFound
	}
	if stored.Revision != order.Revision {
		return acmeserver.ErrRevisionMismatch
	}
	return nil
}

// Checks that the authorization exists at the given revision.
func (s *Store) checkAuthorization(authz *acmeserver.Authorization) error {
	stored, ok := s.authzs[authz.ID]
	if !ok {
		return acmeserver.ErrNotFound
	}
	if stored.Revision != authz.Revision {
		return acmeserver.ErrRevisionMismatch
	}
	return nil
}

// Checks that the challenge exists at the given revision.
func (s *Store) checkChallenge(challenge *acmeserver.Challenge) error {
	stored, ok := s.challenges[challenge.ID]
	if !ok {
		return acmeserver.ErrNotFound
	}
	if stored.Revision != challenge.Revision {
		return acmeserver.ErrRevisionMismatch
	}
	return nil
}

// Checks that a task can be enqueued.
func (s *Store) checkNewTask(task *acmeserver.Task) error {
	if task.ID == "" {
		return errors.New("memstore: task needs an ID")
	}
	if _, exists := s.tasks[task.ID]; exists {
		return acmeserver.ErrConflict
	}
	return nil
}

// Returns the stored task when the fence matches.
func (s *Store) checkTask(task *acmeserver.Task) (*acmeserver.Task, error) {
	stored, ok := s.tasks[task.ID]
	if !ok {
		return nil, acmeserver.ErrNotFound
	}
	if stored.Fence != task.Fence {
		return nil, acmeserver.ErrRevisionMismatch
	}
	return stored, nil
}

// Stores a new task in insertion order.
func (s *Store) insertTask(task *acmeserver.Task) {
	task.Fence = 0
	task.Attempts = 0
	task.LeaseUntil = time.Time{}
	s.taskSequence++
	s.taskInsertion[task.ID] = s.taskSequence
	s.tasks[task.ID] = cloneTask(task)
}

// Deletes a task and its ordering record.
func (s *Store) removeTask(id string) {
	delete(s.tasks, id)
	delete(s.taskInsertion, id)
}

// Returns a copy that shares no mutable state with the original.
func cloneAccount(a *acmeserver.Account) *acmeserver.Account {
	c := *a
	c.Contact = slices.Clone(a.Contact)
	c.Key = clonePublicKey(a.Key)
	return &c
}

// Returns a copy of the order with its own slices.
func cloneOrder(o *acmeserver.Order) *acmeserver.Order {
	c := *o
	c.Identifiers = slices.Clone(o.Identifiers)
	c.AuthorizationIDs = slices.Clone(o.AuthorizationIDs)
	c.CSR = slices.Clone(o.CSR)
	c.Error = cloneProblem(o.Error)
	if o.Issuance != nil {
		state := *o.Issuance
		state.Validations = slices.Clone(state.Validations)
		c.Issuance = &state
	}
	if o.UnpublishedResult != nil {
		result := *o.UnpublishedResult
		result.Chain = cloneChain(result.Chain)
		result.Rejected = cloneProblem(result.Rejected)
		c.UnpublishedResult = &result
	}
	return &c
}

// Returns a copy of the authorization with its own slices.
func cloneAuthorization(a *acmeserver.Authorization) *acmeserver.Authorization {
	c := *a
	c.ChallengeIDs = slices.Clone(a.ChallengeIDs)
	return &c
}

// Returns a copy of the challenge with its own error.
func cloneChallenge(ch *acmeserver.Challenge) *acmeserver.Challenge {
	c := *ch
	c.Error = cloneProblem(ch.Error)
	return &c
}

// Returns a copy of the certificate with its own chain.
func cloneCertificate(cert *acmeserver.Certificate) *acmeserver.Certificate {
	c := *cert
	c.Chain = cloneChain(cert.Chain)
	c.Validations = slices.Clone(cert.Validations)
	return &c
}

// Copies every certificate byte slice in a chain.
func cloneChain(chain [][]byte) [][]byte {
	copyOf := make([][]byte, len(chain))
	for i, der := range chain {
		copyOf[i] = slices.Clone(der)
	}
	return copyOf
}

// Returns a copy of the task.
func cloneTask(t *acmeserver.Task) *acmeserver.Task {
	c := *t
	return &c
}

// Returns a deep copy of a problem, or nil.
func cloneProblem(p *acmeserver.Problem) *acmeserver.Problem {
	if p == nil {
		return nil
	}
	c := *p
	if p.Identifier != nil {
		id := *p.Identifier
		c.Identifier = &id
	}
	c.Algorithms = slices.Clone(p.Algorithms)
	if p.Subproblems != nil {
		c.Subproblems = make([]*acmeserver.Problem, len(p.Subproblems))
		for i, sub := range p.Subproblems {
			c.Subproblems[i] = cloneProblem(sub)
		}
	}
	return &c
}

// Copies a public key so callers cannot mutate stored state through it.
func clonePublicKey(key crypto.PublicKey) crypto.PublicKey {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			return key
		}
		copied, err := ecdsa.ParseUncompressedPublicKey(k.Curve, point)
		if err != nil {
			return key
		}
		return copied
	case *rsa.PublicKey:
		return &rsa.PublicKey{N: new(big.Int).Set(k.N), E: k.E}
	case ed25519.PublicKey:
		return slices.Clone(k)
	default:
		return key
	}
}
