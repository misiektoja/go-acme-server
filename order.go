package acmeserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"
)

// The newOrder payload of RFC 8555 section 7.4.
type newOrderJSON struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore"`
	NotAfter    string       `json:"notAfter"`
	// The RFC 9773 predecessor, used only when Config.RenewalInfo is set.
	Replaces string `json:"replaces"`
	// The certificate profile of draft-ietf-acme-profiles. Empty selects Config.DefaultProfile.
	Profile string `json:"profile"`
}

// The authorization update payload of RFC 8555 section 7.5.2.
type authorizationUpdateJSON struct {
	Status string `json:"status"`
}

// The challenge response payload. RFC 8555 section 7.5.1 sends an empty object and RFC 9448
// section 4 adds the Authority Token for tkauth-01. ATIS-1000080 clause 6.3.5.2 puts the same
// token in an atc field, which SHAKEN clients send, so both names are read.
type challengeResponseJSON struct {
	TKAuth string `json:"tkauth"`
	ATC    string `json:"atc"`
}

// Returns the Authority Token of a response, from whichever field carries it.
func (p challengeResponseJSON) authorityToken() string {
	if p.TKAuth != "" {
		return p.TKAuth
	}
	return p.ATC
}

// Bounds the Authority Token a client may present.
const maxAuthorityTokenLength = 16 << 10

// Creates an order with its authorizations and challenges, see RFC 8555 section 7.4.
func (s *Server) serveNewOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, p := s.readSignedRequest(r, resourceNewOrder, keyModeAccount)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	var payload newOrderJSON
	if p := decodePayload(req.Payload, &payload); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	now := s.clock.Now()
	order, p := s.buildOrder(ctx, req.Account, &payload, now, clientAddr(r))
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	preApproved, p := s.preApprove(ctx, req.Account, order)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	authzs, challenges, p := s.buildAuthorizations(ctx, order, preApproved)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	if err := s.store.CreateOrder(ctx, order, authzs, challenges); err != nil {
		if p := replacementProblem(err); order.Replaces != "" && p != nil {
			s.writeProblem(ctx, w, p)
			return
		}
		s.logError(ctx, "order creation failed", err)
		s.writeProblem(ctx, w, NewProblem(ErrorServerInternal, "order creation failed"))
		return
	}
	s.writeOrder(ctx, w, http.StatusCreated, order, now)
}

// Validates a newOrder payload and returns the order to store, without authorizations.
func (s *Server) buildOrder(ctx context.Context, account *Account, payload *newOrderJSON, now time.Time, client netip.Addr) (*Order, *Problem) {
	if len(payload.Identifiers) == 0 {
		return nil, NewProblem(ErrorMalformed, "an order needs at least one identifier")
	}
	if len(payload.Identifiers) > s.maxIdentifiers {
		return nil, Problemf(ErrorMalformed, "an order may have at most %d identifiers", s.maxIdentifiers)
	}
	for _, id := range payload.Identifiers {
		if id.Type == IdentifierIP && !s.ipIdentifiers {
			return nil, NewProblem(ErrorUnsupportedIdentifier, "IP identifiers are not supported").WithIdentifier(id)
		}
		if id.Type == IdentifierTNAuthList && !s.tnAuthList {
			return nil, NewProblem(ErrorUnsupportedIdentifier, "TNAuthList identifiers are not supported").
				WithIdentifier(id)
		}
		if id.Type == IdentifierNfInstanceID && !s.nfInstanceIDs {
			return nil, NewProblem(ErrorUnsupportedIdentifier, "NfInstanceId identifiers are not supported").
				WithIdentifier(id)
		}
		if id.Type == IdentifierURI {
			return nil, NewProblem(ErrorUnsupportedIdentifier, "uri names come only from authority tokens").
				WithIdentifier(id)
		}
	}
	identifiers, err := NormalizeIdentifiers(payload.Identifiers)
	if err != nil {
		p, _ := AsProblem(err)
		return nil, p
	}
	// A certificate carries one id-pe-TNAuthList extension, so a second list could never be
	// matched by a certificate request.
	if countIdentifiers(identifiers, IdentifierTNAuthList) > 1 {
		return nil, NewProblem(ErrorMalformed, "an order may have at most one TNAuthList identifier")
	}
	// A network function certificate names one instance (3GPP TS 33.310 clause 6.1.3c.3), and an
	// authority list certificate is a STIR credential, so neither combines with the other.
	nfInstances := countIdentifiers(identifiers, IdentifierNfInstanceID)
	if nfInstances > 1 {
		return nil, NewProblem(ErrorMalformed, "an order may have at most one NfInstanceId identifier")
	}
	if nfInstances > 0 && countIdentifiers(identifiers, IdentifierTNAuthList) > 0 {
		return nil, NewProblem(ErrorMalformed, "an order may not combine NfInstanceId and TNAuthList identifiers")
	}
	for _, id := range identifiers {
		if len(s.challengeTypesFor(id)) == 0 {
			return nil, NewProblem(ErrorRejectedIdentifier, "no supported validation method for this identifier").
				WithIdentifier(id)
		}
	}
	notBefore, p := parseTime(payload.NotBefore, "notBefore")
	if p != nil {
		return nil, p
	}
	notAfter, p := parseTime(payload.NotAfter, "notAfter")
	if p != nil {
		return nil, p
	}
	if !notBefore.IsZero() && !notAfter.IsZero() && !notAfter.After(notBefore) {
		return nil, NewProblem(ErrorMalformed, "notAfter must be later than notBefore")
	}
	profile, p := s.selectProfile(ctx, account, payload.Profile)
	if p != nil {
		return nil, p
	}
	replaces, p := s.checkReplaces(ctx, account, identifiers, payload.Replaces)
	if p != nil {
		return nil, p
	}
	id, err := newID()
	if err != nil {
		s.logError(ctx, "identifier generation failed", err)
		return nil, NewProblem(ErrorServerInternal, "order creation failed")
	}
	order := &Order{
		ID:          id,
		AccountID:   account.ID,
		Status:      OrderPending,
		Expires:     now.Add(s.orderLifetime),
		Identifiers: identifiers,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		Replaces:    replaces,
		Profile:     profile,
		CreatedAt:   now,
	}
	limit := LimitRequest{
		Kind:        LimitNewOrder,
		Client:      client,
		Account:     account,
		Identifiers: identifiers,
		Replaces:    replaces,
	}
	if p := s.checkLimit(ctx, limit); p != nil {
		return nil, p
	}
	if p := s.reviewOrder(ctx, account, order); p != nil {
		return nil, p
	}
	return order, nil
}

// Returns the profile a new order is issued under: the requested one when the server offers it.
// When the client names none, a ProfileChooser policy picks one or the default applies. An
// unadvertised name is refused rather than replaced, so a client never receives a certificate
// it did not ask for.
func (s *Server) selectProfile(ctx context.Context, account *Account, requested string) (string, *Problem) {
	if requested != "" {
		if _, ok := s.profiles[requested]; !ok {
			return "", NewProblem(ErrorInvalidProfile, "the server does not offer the requested profile")
		}
		return requested, nil
	}
	chooser, ok := s.policy.(ProfileChooser)
	if !ok {
		return s.defaultProfile, nil
	}
	const what = "profile choice"
	chosen, err := chooser.DefaultProfile(ctx, account)
	if p := s.hostProblem(ctx, err, what); p != nil {
		return "", p
	}
	if chosen == "" {
		return s.defaultProfile, nil
	}
	if _, ok := s.profiles[chosen]; !ok {
		return "", s.hostProblem(ctx, errors.New("the policy chose a profile the server does not offer"), what)
	}
	return chosen, nil
}

// Asks the policy about a new order and keeps only its changes to NotBefore and NotAfter. Any
// other change, or a validity period the server would refuse from a client, fails the request.
func (s *Server) reviewOrder(ctx context.Context, account *Account, order *Order) *Problem {
	reviewed := *order
	reviewed.Identifiers = slices.Clone(order.Identifiers)
	if p := s.hostProblem(ctx, s.policy.NewOrder(ctx, account, &reviewed), "order policy"); p != nil {
		return p
	}
	notBefore, notAfter := reviewed.NotBefore, reviewed.NotAfter
	reviewed.NotBefore, reviewed.NotAfter = order.NotBefore, order.NotAfter
	var err error
	switch {
	case !reflect.DeepEqual(&reviewed, order):
		err = errors.New("the policy changed order fields other than NotBefore and NotAfter")
	case !notBefore.IsZero() && !notAfter.IsZero() && !notAfter.After(notBefore):
		err = errors.New("the policy set NotAfter no later than NotBefore")
	}
	if err != nil {
		return s.hostProblem(ctx, err, "order policy")
	}
	order.NotBefore, order.NotAfter = notBefore, notAfter
	return nil
}

// Asks a PreApprover policy which identifiers of a new order need no challenge.
func (s *Server) preApprove(ctx context.Context, account *Account, order *Order) (map[Identifier]bool, *Problem) {
	authorizer, ok := s.policy.(PreApprover)
	if !ok {
		return nil, nil
	}
	reviewed := *order
	reviewed.Identifiers = slices.Clone(order.Identifiers)
	const what = "pre-approval policy"
	ids, err := authorizer.PreApprove(ctx, account, &reviewed)
	if p := s.hostProblem(ctx, err, what); p != nil {
		return nil, p
	}
	if !reflect.DeepEqual(&reviewed, order) {
		return nil, s.hostProblem(ctx, errors.New("the policy changed the order"), what)
	}
	granted := make(map[Identifier]bool, len(ids))
	for _, id := range ids {
		normalized, err := id.Normalize()
		if err != nil || !slices.Contains(order.Identifiers, normalized) {
			return nil, s.hostProblem(ctx, errors.New("the policy returned an identifier the order does not contain"), what)
		}
		granted[normalized] = true
	}
	return granted, nil
}

// Creates one authorization per identifier. A pre-approved identifier gets a valid
// authorization without challenges and every other one a pending authorization with a challenge
// per supported type. An order whose authorizations are all valid starts ready.
func (s *Server) buildAuthorizations(ctx context.Context, order *Order, preApproved map[Identifier]bool) ([]*Authorization, []*Challenge, *Problem) {
	authzs := make([]*Authorization, 0, len(order.Identifiers))
	var challenges []*Challenge
	order.AuthorizationIDs = make([]string, 0, len(order.Identifiers))
	for _, id := range order.Identifiers {
		authzID, err := newID()
		if err != nil {
			s.logError(ctx, "identifier generation failed", err)
			return nil, nil, NewProblem(ErrorServerInternal, "order creation failed")
		}
		authz := &Authorization{
			ID:         authzID,
			AccountID:  order.AccountID,
			OrderID:    order.ID,
			Identifier: id,
			Status:     AuthorizationPending,
			Expires:    order.Expires,
			Wildcard:   id.IsWildcard(),
			CreatedAt:  order.CreatedAt,
		}
		if authz.Wildcard {
			authz.Identifier.Value = strings.TrimPrefix(id.Value, "*.")
		}
		if preApproved[id] {
			authz.Status = AuthorizationValid
			authz.PreApproved = true
			authzs = append(authzs, authz)
			order.AuthorizationIDs = append(order.AuthorizationIDs, authz.ID)
			continue
		}
		for _, typ := range s.challengeTypesFor(id) {
			challengeID, err := newID()
			if err != nil {
				s.logError(ctx, "identifier generation failed", err)
				return nil, nil, NewProblem(ErrorServerInternal, "order creation failed")
			}
			token, err := newToken()
			if err != nil {
				s.logError(ctx, "token generation failed", err)
				return nil, nil, NewProblem(ErrorServerInternal, "order creation failed")
			}
			challenges = append(challenges, &Challenge{
				ID:              challengeID,
				AuthorizationID: authz.ID,
				AccountID:       order.AccountID,
				Type:            typ,
				Status:          ChallengePending,
				Token:           token,
			})
			authz.ChallengeIDs = append(authz.ChallengeIDs, challengeID)
		}
		authzs = append(authzs, authz)
		order.AuthorizationIDs = append(order.AuthorizationIDs, authz.ID)
	}
	if len(preApproved) == len(order.Identifiers) {
		order.Status = OrderReady
	}
	return authzs, challenges, nil
}

// Counts the identifiers of one type.
func countIdentifiers(ids []Identifier, typ IdentifierType) int {
	n := 0
	for _, id := range ids {
		if id.Type == typ {
			n++
		}
	}
	return n
}

// Returns the configured challenge types that may validate the identifier. Wildcard names need
// dns-01, IP addresses exclude it and only TNAuthList and NfInstanceId identifiers use tkauth-01,
// see RFC 8555 section 7.1.3, RFC 8738 section 5, RFC 9447 section 3 and 3GPP TS 33.310 clause
// J.3.3.2.
func (s *Server) challengeTypesFor(id Identifier) []ChallengeType {
	var types []ChallengeType
	token := id.Type == IdentifierTNAuthList || id.Type == IdentifierNfInstanceID
	for _, typ := range []ChallengeType{ChallengeHTTP01, ChallengeDNS01, ChallengeTLSALPN01, ChallengeTKAuth01} {
		if _, ok := s.validators[typ]; !ok {
			continue
		}
		if (typ == ChallengeTKAuth01) != token {
			continue
		}
		if id.IsWildcard() && typ != ChallengeDNS01 {
			continue
		}
		if id.Type == IdentifierIP && typ == ChallengeDNS01 {
			continue
		}
		types = append(types, typ)
	}
	return types
}

// Checks a challenge response payload against what the challenge type expects.
func checkChallengeResponse(typ ChallengeType, payload challengeResponseJSON) *Problem {
	if typ != ChallengeTKAuth01 {
		if payload.authorityToken() != "" {
			return Problemf(ErrorMalformed, "a %s response does not carry an authority token", string(typ))
		}
		return nil
	}
	switch {
	case payload.authorityToken() == "":
		return NewProblem(ErrorMalformed, "a tkauth-01 response needs the authority token in tkauth or atc")
	case payload.TKAuth != "" && payload.ATC != "" && payload.TKAuth != payload.ATC:
		return NewProblem(ErrorMalformed, "the tkauth and atc fields carry different authority tokens")
	case len(payload.authorityToken()) > maxAuthorityTokenLength:
		return Problemf(ErrorMalformed, "the authority token exceeds %d characters", maxAuthorityTokenLength)
	}
	return nil
}

// Returns a random challenge token with 256 bits of entropy.
func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Parses an optional RFC 3339 timestamp from an order payload.
func parseTime(value, field string) (time.Time, *Problem) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, Problemf(ErrorMalformed, "%s is not an RFC 3339 timestamp", field)
	}
	return t, nil
}

// Returns an order, see RFC 8555 section 7.4.
func (s *Server) serveOrder(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	req, order, p := s.readOwnedOrder(r, id, orderPathPrefix+id)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	if p := requireEmptyPayload(req); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	s.writeOrder(ctx, w, http.StatusOK, order, s.clock.Now())
}

// Reads a signed request for an order resource and loads the order the account owns.
func (s *Server) readOwnedOrder(r *http.Request, id, rel string) (*signedRequest, *Order, *Problem) {
	req, p := s.readSignedRequest(r, rel, keyModeAccount)
	if p != nil {
		return nil, nil, p
	}
	order, err := s.store.Order(r.Context(), id)
	if err != nil {
		return nil, nil, s.storeProblem(r.Context(), err, "order")
	}
	if order.AccountID != req.Account.ID {
		return nil, nil, NewProblem(ErrorUnauthorized, "the signing account does not own this order")
	}
	if order.Status == OrderPending || order.Status == OrderReady {
		status, err := s.deriveOrderStatus(r.Context(), order, nil)
		if err != nil {
			return nil, nil, s.storeProblem(r.Context(), err, "authorization")
		}
		order.Status = status
	}
	return req, order, nil
}

// Returns or deactivates an authorization, see RFC 8555 sections 7.5 and 7.5.2.
func (s *Server) serveAuthorization(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	req, p := s.readSignedRequest(r, authzPathPrefix+id, keyModeAccount)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	authz, err := s.store.Authorization(ctx, id)
	if err != nil {
		s.writeProblem(ctx, w, s.storeProblem(ctx, err, "authorization"))
		return
	}
	if authz.AccountID != req.Account.ID {
		s.writeProblem(ctx, w, NewProblem(ErrorUnauthorized, "the signing account does not own this authorization"))
		return
	}
	now := s.clock.Now()
	if len(req.Payload) != 0 {
		var payload authorizationUpdateJSON
		if p := decodePayload(req.Payload, &payload); p != nil {
			s.writeProblem(ctx, w, p)
			return
		}
		if payload.Status != string(AuthorizationDeactivated) {
			s.writeProblem(ctx, w, NewProblem(ErrorMalformed, "status can only be changed to deactivated"))
			return
		}
		if p := s.deactivateAuthorization(ctx, authz, now); p != nil {
			s.writeProblem(ctx, w, p)
			return
		}
	}
	challenges, p := s.loadChallenges(ctx, authz)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	s.writeJSON(ctx, w, http.StatusOK, s.authorizationView(authz, challenges, now))
}

// Moves a pending or valid authorization to deactivated.
func (s *Server) deactivateAuthorization(ctx context.Context, authz *Authorization, now time.Time) *Problem {
	status := effectiveAuthzStatus(authz, now)
	if status == AuthorizationDeactivated {
		return nil
	}
	if !status.CanTransition(AuthorizationDeactivated) {
		return Problemf(ErrorMalformed, "authorization is %s and cannot be deactivated", string(status))
	}
	authz.Status = AuthorizationDeactivated
	err := s.store.UpdateAuthorization(ctx, authz)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrRevisionMismatch):
		return NewProblem(ErrorMalformed, "the authorization changed concurrently, retry the request").
			WithStatus(http.StatusConflict)
	}
	s.logError(ctx, "authorization update failed", err)
	return NewProblem(ErrorServerInternal, "authorization update failed")
}

// Loads the challenges of an authorization in their stored order.
func (s *Server) loadChallenges(ctx context.Context, authz *Authorization) ([]*Challenge, *Problem) {
	challenges := make([]*Challenge, 0, len(authz.ChallengeIDs))
	for _, id := range authz.ChallengeIDs {
		ch, err := s.store.Challenge(ctx, id)
		if err != nil {
			s.logError(ctx, "challenge lookup failed", err)
			return nil, NewProblem(ErrorServerInternal, "challenge lookup failed")
		}
		challenges = append(challenges, ch)
	}
	return challenges, nil
}

// Returns a challenge or accepts the client's response to it, see RFC 8555 section 7.5.1.
func (s *Server) serveChallenge(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	req, p := s.readSignedRequest(r, challengePathPrefix+id, keyModeAccount)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	ch, err := s.store.Challenge(ctx, id)
	if err != nil {
		s.writeProblem(ctx, w, s.storeProblem(ctx, err, "challenge"))
		return
	}
	if ch.AccountID != req.Account.ID {
		s.writeProblem(ctx, w, NewProblem(ErrorUnauthorized, "the signing account does not own this challenge"))
		return
	}
	w.Header().Add("Link", `<`+s.resourceURL(authzPathPrefix+ch.AuthorizationID)+`>;rel="up"`)
	if len(req.Payload) != 0 {
		var payload challengeResponseJSON
		if p := decodePayload(req.Payload, &payload); p != nil {
			s.writeProblem(ctx, w, p)
			return
		}
		ch, p = s.acceptChallenge(ctx, ch, req.Account, payload)
		if p != nil {
			s.writeProblem(ctx, w, p)
			return
		}
	}
	s.writeChallenge(ctx, w, ch)
}

// Moves a pending challenge to processing and enqueues its validation. A challenge that is no
// longer pending is returned unchanged without reading the payload, so repeated responses are
// harmless whatever they carry.
func (s *Server) acceptChallenge(ctx context.Context, ch *Challenge, account *Account,
	payload challengeResponseJSON) (*Challenge, *Problem) {
	if ch.Status != ChallengePending {
		return ch, nil
	}
	if p := checkChallengeResponse(ch.Type, payload); p != nil {
		return nil, p
	}
	authz, err := s.store.Authorization(ctx, ch.AuthorizationID)
	if err != nil {
		s.logError(ctx, "authorization lookup failed", err)
		return nil, NewProblem(ErrorServerInternal, "authorization lookup failed")
	}
	now := s.clock.Now()
	if status := effectiveAuthzStatus(authz, now); status != AuthorizationPending {
		return nil, Problemf(ErrorMalformed, "authorization is %s", string(status))
	}
	taskID, err := newID()
	if err != nil {
		s.logError(ctx, "identifier generation failed", err)
		return nil, NewProblem(ErrorServerInternal, "challenge update failed")
	}
	ch.Status = ChallengeProcessing
	ch.KeyThumbprint = account.KeyThumbprint
	ch.AuthorityToken = payload.authorityToken()
	task := &Task{ID: taskID, Kind: TaskValidate, TargetID: ch.ID, AccountID: account.ID, RunAt: now, CreatedAt: now}
	err = s.store.AcceptChallenge(ctx, ch, task)
	switch {
	case err == nil:
		s.workAccepted(ctx)
		return ch, nil
	case errors.Is(err, ErrRevisionMismatch):
		// Only a concurrent response moves the challenge on. One that is still pending was not
		// stored, so answering with it would leave the client waiting for a validation that never runs.
		current, lookupErr := s.store.Challenge(ctx, ch.ID)
		switch {
		case lookupErr != nil:
			err = lookupErr
		case current.Status != ChallengePending:
			return current, nil
		}
	}
	s.logError(ctx, "challenge update failed", err)
	return nil, NewProblem(ErrorServerInternal, "challenge update failed")
}
