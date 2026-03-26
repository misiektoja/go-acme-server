package acmeserver

import "testing"

func TestAccountStatus(t *testing.T) {
	for _, s := range []AccountStatus{AccountValid, AccountDeactivated, AccountRevoked} {
		if !s.Known() {
			t.Errorf("%s not known", s)
		}
	}
	if AccountStatus("pending").Known() {
		t.Error("pending account status reported as known")
	}
	allowed := map[[2]AccountStatus]bool{
		{AccountValid, AccountDeactivated}: true,
		{AccountValid, AccountRevoked}:     true,
	}
	all := []AccountStatus{AccountValid, AccountDeactivated, AccountRevoked}
	for _, from := range all {
		for _, to := range all {
			if got := from.CanTransition(to); got != allowed[[2]AccountStatus{from, to}] {
				t.Errorf("%s -> %s = %v", from, to, got)
			}
		}
	}
}

func TestOrderStatus(t *testing.T) {
	all := []OrderStatus{OrderPending, OrderReady, OrderProcessing, OrderValid, OrderInvalid}
	for _, s := range all {
		if !s.Known() {
			t.Errorf("%s not known", s)
		}
	}
	if OrderStatus("done").Known() {
		t.Error("done order status reported as known")
	}
	allowed := map[[2]OrderStatus]bool{
		{OrderPending, OrderReady}:      true,
		{OrderPending, OrderInvalid}:    true,
		{OrderReady, OrderProcessing}:   true,
		{OrderReady, OrderInvalid}:      true,
		{OrderProcessing, OrderValid}:   true,
		{OrderProcessing, OrderInvalid}: true,
	}
	for _, from := range all {
		for _, to := range all {
			if got := from.CanTransition(to); got != allowed[[2]OrderStatus{from, to}] {
				t.Errorf("%s -> %s = %v", from, to, got)
			}
		}
		if from.Terminal() != (from == OrderValid || from == OrderInvalid) {
			t.Errorf("%s Terminal() = %v", from, from.Terminal())
		}
	}
}

func TestAuthorizationStatus(t *testing.T) {
	all := []AuthorizationStatus{AuthorizationPending, AuthorizationValid, AuthorizationInvalid,
		AuthorizationDeactivated, AuthorizationExpired, AuthorizationRevoked}
	for _, s := range all {
		if !s.Known() {
			t.Errorf("%s not known", s)
		}
	}
	if AuthorizationStatus("").Known() || AuthorizationStatus("").Terminal() {
		t.Error("empty authorization status reported as known or terminal")
	}
	allowed := map[[2]AuthorizationStatus]bool{
		{AuthorizationPending, AuthorizationValid}:       true,
		{AuthorizationPending, AuthorizationInvalid}:     true,
		{AuthorizationPending, AuthorizationDeactivated}: true,
		{AuthorizationPending, AuthorizationExpired}:     true,
		{AuthorizationValid, AuthorizationDeactivated}:   true,
		{AuthorizationValid, AuthorizationExpired}:       true,
		{AuthorizationValid, AuthorizationRevoked}:       true,
	}
	for _, from := range all {
		for _, to := range all {
			if got := from.CanTransition(to); got != allowed[[2]AuthorizationStatus{from, to}] {
				t.Errorf("%s -> %s = %v", from, to, got)
			}
		}
		wantTerminal := from != AuthorizationPending && from != AuthorizationValid
		if from.Terminal() != wantTerminal {
			t.Errorf("%s Terminal() = %v", from, from.Terminal())
		}
	}
}

func TestChallengeStatus(t *testing.T) {
	all := []ChallengeStatus{ChallengePending, ChallengeProcessing, ChallengeValid, ChallengeInvalid}
	for _, s := range all {
		if !s.Known() {
			t.Errorf("%s not known", s)
		}
	}
	allowed := map[[2]ChallengeStatus]bool{
		{ChallengePending, ChallengeProcessing}: true,
		{ChallengePending, ChallengeValid}:      true,
		{ChallengePending, ChallengeInvalid}:    true,
		{ChallengeProcessing, ChallengeValid}:   true,
		{ChallengeProcessing, ChallengeInvalid}: true,
	}
	for _, from := range all {
		for _, to := range all {
			if got := from.CanTransition(to); got != allowed[[2]ChallengeStatus{from, to}] {
				t.Errorf("%s -> %s = %v", from, to, got)
			}
		}
		if from.Terminal() != (from == ChallengeValid || from == ChallengeInvalid) {
			t.Errorf("%s Terminal() = %v", from, from.Terminal())
		}
	}
}
