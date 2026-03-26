package acmeserver

// The status of an account resource, see RFC 8555 section 7.1.2.
type AccountStatus string

// Account statuses.
const (
	AccountValid       AccountStatus = "valid"
	AccountDeactivated AccountStatus = "deactivated"
	AccountRevoked     AccountStatus = "revoked"
)

// Reports whether the status is one the protocol defines.
func (s AccountStatus) Known() bool {
	switch s {
	case AccountValid, AccountDeactivated, AccountRevoked:
		return true
	}
	return false
}

// Reports whether RFC 8555 section 7.1.6 allows the status to move to next.
func (s AccountStatus) CanTransition(next AccountStatus) bool {
	return s == AccountValid && (next == AccountDeactivated || next == AccountRevoked)
}

// The status of an order resource, see RFC 8555 section 7.1.3.
type OrderStatus string

// Order statuses.
const (
	OrderPending    OrderStatus = "pending"
	OrderReady      OrderStatus = "ready"
	OrderProcessing OrderStatus = "processing"
	OrderValid      OrderStatus = "valid"
	OrderInvalid    OrderStatus = "invalid"
)

// Reports whether the status is one the protocol defines.
func (s OrderStatus) Known() bool {
	switch s {
	case OrderPending, OrderReady, OrderProcessing, OrderValid, OrderInvalid:
		return true
	}
	return false
}

// Reports whether no further transition is possible.
func (s OrderStatus) Terminal() bool { return s == OrderValid || s == OrderInvalid }

// Reports whether RFC 8555 section 7.1.6 allows the status to move to next.
func (s OrderStatus) CanTransition(next OrderStatus) bool {
	switch s {
	case OrderPending:
		return next == OrderReady || next == OrderInvalid
	case OrderReady:
		return next == OrderProcessing || next == OrderInvalid
	case OrderProcessing:
		return next == OrderValid || next == OrderInvalid
	case OrderValid, OrderInvalid:
		return false
	}
	return false
}

// The status of an authorization resource, see RFC 8555 section 7.1.4.
type AuthorizationStatus string

// Authorization statuses.
const (
	AuthorizationPending     AuthorizationStatus = "pending"
	AuthorizationValid       AuthorizationStatus = "valid"
	AuthorizationInvalid     AuthorizationStatus = "invalid"
	AuthorizationDeactivated AuthorizationStatus = "deactivated"
	AuthorizationExpired     AuthorizationStatus = "expired"
	AuthorizationRevoked     AuthorizationStatus = "revoked"
)

// Reports whether the status is one the protocol defines.
func (s AuthorizationStatus) Known() bool {
	switch s {
	case AuthorizationPending, AuthorizationValid, AuthorizationInvalid,
		AuthorizationDeactivated, AuthorizationExpired, AuthorizationRevoked:
		return true
	}
	return false
}

// Reports whether no further transition is possible.
func (s AuthorizationStatus) Terminal() bool {
	return s.Known() && s != AuthorizationPending && s != AuthorizationValid
}

// Reports whether RFC 8555 section 7.1.6 allows the status to move to next.
func (s AuthorizationStatus) CanTransition(next AuthorizationStatus) bool {
	switch s {
	case AuthorizationPending:
		return next == AuthorizationValid || next == AuthorizationInvalid ||
			next == AuthorizationDeactivated || next == AuthorizationExpired
	case AuthorizationValid:
		return next == AuthorizationDeactivated || next == AuthorizationExpired || next == AuthorizationRevoked
	case AuthorizationInvalid, AuthorizationDeactivated, AuthorizationExpired, AuthorizationRevoked:
		return false
	}
	return false
}

// The status of a challenge resource, see RFC 8555 section 7.1.5.
type ChallengeStatus string

// Challenge statuses.
const (
	ChallengePending    ChallengeStatus = "pending"
	ChallengeProcessing ChallengeStatus = "processing"
	ChallengeValid      ChallengeStatus = "valid"
	ChallengeInvalid    ChallengeStatus = "invalid"
)

// Reports whether the status is one the protocol defines.
func (s ChallengeStatus) Known() bool {
	switch s {
	case ChallengePending, ChallengeProcessing, ChallengeValid, ChallengeInvalid:
		return true
	}
	return false
}

// Reports whether no further transition is possible.
func (s ChallengeStatus) Terminal() bool { return s == ChallengeValid || s == ChallengeInvalid }

// Reports whether the status may move to next, including pending to invalid per erratum 5732.
func (s ChallengeStatus) CanTransition(next ChallengeStatus) bool {
	switch s {
	case ChallengePending:
		return next == ChallengeProcessing || next == ChallengeValid || next == ChallengeInvalid
	case ChallengeProcessing:
		return next == ChallengeValid || next == ChallengeInvalid
	case ChallengeValid, ChallengeInvalid:
		return false
	}
	return false
}
