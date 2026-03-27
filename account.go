package acmeserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/misiektoja/go-acme-server/internal/jws"
)

// Limits on account requests.
const (
	maxContacts    = 10
	ordersPageSize = 100
)

// The newAccount payload of RFC 8555 section 7.3.
type newAccountJSON struct {
	Contact                []string        `json:"contact"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
}

// The account update payload of RFC 8555 sections 7.3.2 and 7.3.6.
type accountUpdateJSON struct {
	Contact *[]string `json:"contact"`
	Status  *string   `json:"status"`
}

// The key change payload of RFC 8555 section 7.3.5.
type keyChangeJSON struct {
	Account string          `json:"account"`
	OldKey  json.RawMessage `json:"oldKey"`
}

// Creates an account or returns the one owning the signing key.
func (s *Server) serveNewAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.meta.TermsOfService != "" {
		w.Header().Add("Link", `<`+s.meta.TermsOfService+`>;rel="terms-of-service"`)
	}
	req, p := s.readSignedRequest(r, resourceNewAccount, keyModeEmbedded)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	var payload newAccountJSON
	if p := decodePayload(req.Payload, &payload); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	thumbprint, err := jws.Thumbprint(req.Key)
	if err != nil {
		s.writeProblem(ctx, w, NewProblem(ErrorBadPublicKey, "account key cannot be thumbprinted"))
		return
	}
	existing, err := s.store.AccountByKey(ctx, thumbprint)
	switch {
	case err == nil:
		s.writeExistingAccount(ctx, w, existing)
		return
	case !errors.Is(err, ErrNotFound):
		s.logError(ctx, "account lookup failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "account lookup failed"))
		return
	case payload.OnlyReturnExisting:
		s.writeProblem(ctx, w, NewProblem(ErrorAccountDoesNotExist, "no account owns this key"))
		return
	}
	account, p := s.buildAccount(ctx, req, thumbprint, &payload)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	err = s.store.CreateAccount(ctx, account)
	switch {
	case errors.Is(err, ErrConflict):
		existing, lookupErr := s.store.AccountByKey(ctx, thumbprint)
		if lookupErr != nil {
			s.logError(ctx, "account creation conflict", err)
			s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "account creation failed"))
			return
		}
		s.writeExistingAccount(ctx, w, existing)
		return
	case err != nil:
		s.logError(ctx, "account creation failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "account creation failed"))
		return
	}
	w.Header().Set("Location", s.accountURL(account.ID))
	s.writeJSON(ctx, w, http.StatusCreated, s.accountView(account))
}

// Answers a newAccount request whose key already owns an account.
func (s *Server) writeExistingAccount(ctx context.Context, w http.ResponseWriter, account *Account) {
	if account.Status != AccountValid {
		s.writeProblem(ctx, w, Problemf(ErrorUnauthorized, "the account owning this key is %s", string(account.Status)))
		return
	}
	w.Header().Set("Location", s.accountURL(account.ID))
	s.writeJSON(ctx, w, http.StatusOK, s.accountView(account))
}

// Validates a newAccount payload and returns the account to store.
func (s *Server) buildAccount(ctx context.Context, req *signedRequest, thumbprint string,
	payload *newAccountJSON) (*Account, *Problem) {
	if p := validateContacts(payload.Contact); p != nil {
		return nil, p
	}
	if s.requireTOS && !payload.TermsOfServiceAgreed {
		return nil, NewProblem(ErrorUserActionRequired, "the terms of service must be agreed to")
	}
	var externalID string
	switch {
	case len(payload.ExternalAccountBinding) == 0 && s.meta.ExternalAccountRequired:
		return nil, NewProblem(ErrorExternalAccountRequired, "an external account binding is required")
	case len(payload.ExternalAccountBinding) > 0:
		id, p := s.verifyExternalAccountBinding(ctx, thumbprint, payload.ExternalAccountBinding)
		if p != nil {
			return nil, p
		}
		externalID = id
	}
	id, err := newID()
	if err != nil {
		s.logError(ctx, "identifier generation failed", err)
		return nil, NewProblem(ErrorServerInternal, "account creation failed")
	}
	account := &Account{
		ID:                   id,
		Status:               AccountValid,
		Key:                  req.Key,
		KeyThumbprint:        thumbprint,
		Contact:              payload.Contact,
		TermsOfServiceAgreed: payload.TermsOfServiceAgreed,
		ExternalAccountID:    externalID,
		CreatedAt:            s.clock.Now(),
	}
	if p := s.policyProblem(ctx, s.policy.NewAccount(ctx, account), "account policy"); p != nil {
		return nil, p
	}
	return account, nil
}

// Maps a policy result to a problem, logging unexpected errors.
func (s *Server) policyProblem(ctx context.Context, err error, what string) *Problem {
	if err == nil {
		return nil
	}
	if p, ok := AsProblem(err); ok {
		return p
	}
	s.logError(ctx, what+" failed", err)
	return NewProblem(ErrorServerInternal, what+" failed")
}

// Checks contact URLs. Only mailto with one bare address is supported.
func validateContacts(contacts []string) *Problem {
	if len(contacts) > maxContacts {
		return Problemf(ErrorMalformed, "at most %d contacts are allowed", maxContacts)
	}
	for _, contact := range contacts {
		u, err := url.Parse(contact)
		if err != nil || u.Scheme == "" {
			return Problemf(ErrorInvalidContact, "contact %q is not a URL", contact)
		}
		if !strings.EqualFold(u.Scheme, "mailto") {
			return Problemf(ErrorUnsupportedContact, "contact scheme %q is not supported", u.Scheme)
		}
		if u.Opaque == "" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Opaque, ",") {
			return Problemf(ErrorInvalidContact, "contact %q must be a single mailto address without parameters", contact)
		}
		addr, err := mail.ParseAddress(u.Opaque)
		if err != nil || addr.Name != "" || addr.Address != u.Opaque {
			return Problemf(ErrorInvalidContact, "contact %q is not a valid email address", contact)
		}
	}
	return nil
}

// Returns the account, updates it or deactivates it, see RFC 8555 sections 7.3.2 and 7.3.6.
func (s *Server) serveAccount(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	req, p := s.readOwnedAccount(r, id, accountPathPrefix+id)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	account := req.Account
	if len(req.Payload) == 0 {
		s.writeJSON(ctx, w, http.StatusOK, s.accountView(account))
		return
	}
	var payload accountUpdateJSON
	if p := decodePayload(req.Payload, &payload); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	if payload.Status != nil && *payload.Status != string(AccountDeactivated) {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "status can only be changed to deactivated"))
		return
	}
	if payload.Contact != nil {
		if p := validateContacts(*payload.Contact); p != nil {
			s.writeProblem(ctx, w, p)
			return
		}
		account.Contact = *payload.Contact
	}
	if payload.Status != nil {
		account.Status = AccountDeactivated
	}
	if p := s.updateAccount(ctx, account); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	s.writeJSON(ctx, w, http.StatusOK, s.accountView(account))
}

// Lists the orders of an account, see RFC 8555 section 7.1.2.1.
func (s *Server) serveAccountOrders(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	req, p := s.readOwnedAccount(r, id, accountPathPrefix+id+"/orders")
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	if p := requireEmptyPayload(req); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" && !validID(cursor) {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "unknown cursor"))
		return
	}
	ids, err := s.store.OrderIDs(ctx, id, cursor, ordersPageSize+1)
	if errors.Is(err, ErrNotFound) {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "unknown cursor"))
		return
	}
	if err != nil {
		s.logError(ctx, "order listing failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "order listing failed"))
		return
	}
	more := len(ids) > ordersPageSize
	if more {
		ids = ids[:ordersPageSize]
	}
	now := s.clock.Now()
	urls := make([]string, 0, len(ids))
	for _, orderID := range ids {
		order, err := s.store.Order(ctx, orderID)
		if err != nil {
			s.logError(ctx, "order lookup failed", err)
			s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "order listing failed"))
			return
		}
		if effectiveOrderStatus(order, now) != OrderInvalid {
			urls = append(urls, s.resourceURL(orderPathPrefix+orderID))
		}
	}
	if more {
		next := s.resourceURL(accountPathPrefix+id+"/orders") + "?cursor=" + url.QueryEscape(ids[len(ids)-1])
		w.Header().Add("Link", `<`+next+`>;rel="next"`)
	}
	s.writeJSON(ctx, w, http.StatusOK, map[string][]string{"orders": urls})
}

// Replaces the account key, see RFC 8555 section 7.3.5.
func (s *Server) serveKeyChange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, p := s.readSignedRequest(r, resourceKeyChange, keyModeAccount)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	inner, err := jws.ParseInner(req.Payload)
	if err != nil {
		s.writeProblem(ctx, w, innerProblem(err))
		return
	}
	if inner.Header.URL != s.resourceURL(resourceKeyChange) {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "inner JWS url does not match the outer JWS url"))
		return
	}
	if err := inner.Verify(inner.Header.Key); err != nil {
		s.writeProblem(ctx, w, innerProblem(err))
		return
	}
	var payload keyChangeJSON
	if p := decodePayload(inner.Payload, &payload); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	account := req.Account
	if payload.Account != s.accountURL(account.ID) {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "inner JWS account does not match the signing account"))
		return
	}
	oldKey, err := jws.ParseJWK(payload.OldKey)
	if err != nil {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "inner JWS oldKey: "+err.Error()))
		return
	}
	oldThumbprint, err := jws.Thumbprint(oldKey)
	if err != nil || oldThumbprint != account.KeyThumbprint {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "inner JWS oldKey is not the current account key"))
		return
	}
	newThumbprint, err := jws.Thumbprint(inner.Header.Key)
	if err != nil {
		s.writeProblem(ctx, w, NewProblem(ErrorBadPublicKey, "new key cannot be thumbprinted"))
		return
	}
	if newThumbprint == oldThumbprint {
		s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "new key is the current account key"))
		return
	}
	account.Key, account.KeyThumbprint = inner.Header.Key, newThumbprint
	if p := s.updateAccount(ctx, account); p != nil {
		if p.Type == ErrorMalformed && p.Status == http.StatusConflict {
			if other, err := s.store.AccountByKey(ctx, newThumbprint); err == nil {
				w.Header().Set("Location", s.accountURL(other.ID))
			}
		}
		s.writeProblem(ctx, w, p)
		return
	}
	s.writeJSON(ctx, w, http.StatusOK, s.accountView(account))
}

// Maps an inner JWS failure to malformed as RFC 8555 section 7.3.5 requires.
func innerProblem(err error) *Problem {
	p := problemFromJWS(err)
	if p.Type == ErrorBadSignatureAlgorithm || p.Type == ErrorBadPublicKey {
		return p
	}
	return NewProblem(ErrorMalformed, "inner JWS: "+p.Detail)
}

// Reads a signed request for an account resource and checks that the account owns it.
func (s *Server) readOwnedAccount(r *http.Request, id, rel string) (*signedRequest, *Problem) {
	req, p := s.readSignedRequest(r, rel, keyModeAccount)
	if p != nil {
		return nil, p
	}
	if req.Account.ID != id {
		return nil, NewProblem(ErrorUnauthorized, "the signing account does not own this resource")
	}
	return req, nil
}

// Stores an account update and maps store errors to problems.
func (s *Server) updateAccount(ctx context.Context, account *Account) *Problem {
	err := s.store.UpdateAccount(ctx, account)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrConflict):
		return NewProblem(ErrorMalformed, "another account already uses this key").WithStatus(http.StatusConflict)
	case errors.Is(err, ErrRevisionMismatch):
		return NewProblem(ErrorMalformed, "the account changed concurrently, retry the request").
			WithStatus(http.StatusConflict)
	case errors.Is(err, ErrNotFound):
		return NewProblem(ErrorAccountDoesNotExist, "account does not exist")
	}
	s.logError(ctx, "account update failed", err)
	return NewProblem(ErrorServerInternal, "account update failed")
}
