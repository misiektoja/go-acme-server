# Accounts and policy

This page covers what a host controls about who may register, what an account may order and what
the directory tells clients. All of it is configuration on `Config` plus two optional interfaces.

## Directory metadata

```go
Meta: acmeserver.DirectoryMeta{
	TermsOfService:          "https://ca.example.com/terms",
	Website:                 "https://ca.example.com",
	CAAIdentities:           []string{"ca.example.com"},
	ExternalAccountRequired: true,
},
```

The `meta` object is included in the directory when any field is set. `TermsOfService` also adds a
`Link` header with `rel="terms-of-service"` to `newAccount` responses. `CAAIdentities` is
informational. The library does not check CAA records, so a CA that must honor CAA does so in the
issuance policy, see [Issuance policy](issuance.md#issuance-policy).

## Terms of service

`RequireTermsOfServiceAgreed` refuses a `newAccount` whose payload does not set
`termsOfServiceAgreed` with a `userActionRequired` problem. It needs `Meta.TermsOfService`, so
the client can show the URL. Agreement is stored on the account.

## External account binding

External account binding ties an ACME account to an identity the CA already knows, such as a
customer or a device. The client presents a MAC over its account key, signed with a key the CA
issued out of band under a key identifier.

```go
type ExternalAccountKeys interface {
	MACKey(ctx context.Context, keyID string) ([]byte, error)
}
```

Implement it over your key registry and set `Config.ExternalAccounts`. Return `ErrNotFound` for an
unknown identifier, which becomes an `unauthorized` problem. Return any other error for a lookup
failure. HS256, HS384 and HS512 are accepted. RFC 7518 section 3.2 requires a key at least as long
as the hash, so a 256-bit key works with HS256 only and a 512-bit key with all three. A binding
whose algorithm needs a longer key is refused with `badSignatureAlgorithm` listing the algorithms
the key allows. A key shorter than 256 bits is refused with `unauthorized` and logged. Issue keys of
at least 512 bits if clients may choose HS512. A verified binding stores the key identifier as
`Account.ExternalAccountID`, which is available to `Policy.NewAccount` and to your own audit
queries.

`Meta.ExternalAccountRequired` advertises the requirement and refuses accounts without a binding
with `externalAccountRequired`. Without it a binding is verified when present and optional
otherwise.

`SingleUseExternalAccounts` binds each key identifier to at most one account. The claim is stored
with the account, so the store's uniqueness check enforces it under concurrency. A client that
retries `newAccount` with the same account key gets its existing account back. A different account
key with the same identifier is refused with `unauthorized`.

## Account policy

```go
type Policy interface {
	NewAccount(ctx context.Context, account *Account) error
	NewOrder(ctx context.Context, account *Account, order *Order) error
}
```

`Config.Policy` defaults to `AllowAll`. Embed it and override the methods you need:

```go
type customerPolicy struct {
	acmeserver.AllowAll
	customers Registry
}

func (p customerPolicy) NewOrder(ctx context.Context, account *acmeserver.Account, order *acmeserver.Order) error {
	for _, id := range order.Identifiers {
		if !p.customers.Owns(ctx, account.ExternalAccountID, id.Value) {
			return acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier, "not authorized for this name").
				WithIdentifier(id)
		}
	}
	return nil
}
```

`NewAccount` sees the key, the contacts, the terms of service flag and the external account
identity before the account is stored. `NewOrder` sees the account and the order after identifier
normalization and before any authorization is created. It may change `NotBefore` and `NotAfter`,
for example to cap the requested validity. Any other change, or a `NotAfter` that is not later than
`NotBefore`, is logged and answered with `serverInternal`.

A returned `*Problem` is sent to the client. Any other error is logged and answered with
`serverInternal`.

## Rate limits

`Config.Limits` takes a `Limiter`, which decides how often clients may get nonces, create accounts
and place orders. Without one nothing is limited.

```go
type Limiter interface {
	Allow(ctx context.Context, req LimitRequest) error
}
```

`Allow` is asked once for each of these requests:

| `LimitRequest.Kind` | Asked | Fields set |
| --- | --- | --- |
| `LimitNewNonce` | Before a nonce is issued | `Client` |
| `LimitNewAccount` | After the contacts, terms of service and external account binding were checked, before `Policy.NewAccount`. A request that finds an existing account is not asked about | `Client`, `Account` (not yet stored) |
| `LimitNewOrder` | After the identifiers, profile and `replaces` were checked, before `Policy.NewOrder` | `Client`, `Account`, `Identifiers` (normalized), `Replaces` |

Count the request when you return nil. To refuse, return a `rateLimited` problem with
`WithRetryAfter`. The client gets status 429 and a `Retry-After` header in whole seconds, rounded
up. A refused `newNonce` answer carries no `Replay-Nonce`. Refused `newAccount` and `newOrder`
answers carry one, like every other error. Any other error is logged and answered with
`serverInternal`. Return nil on errors instead if clients should keep working while your limit
store is unavailable. New kinds may be added in later versions, so allow kinds you do not know.

```go
func (l limits) Allow(ctx context.Context, req acmeserver.LimitRequest) error {
	if req.Kind != acmeserver.LimitNewOrder || req.Replaces != "" {
		return nil // renewals that name their predecessor are never held back
	}
	wait, err := l.buckets.Take(ctx, "orders:"+req.Account.ID, 300, time.Hour)
	if err != nil || wait == 0 {
		return err
	}
	return acmeserver.NewProblem(acmeserver.ErrorRateLimited, "too many new orders for this account").
		WithRetryAfter(wait)
}
```

`Client` is the address of the connection from `http.Request.RemoteAddr`, with IPv4-mapped IPv6
addresses unmapped. It is the zero `netip.Addr` when `RemoteAddr` holds no IP address. Forwarded
headers such as `X-Forwarded-For` are never read, because any client can set them. Behind a reverse
proxy every client has the proxy's address. If you trust the proxy, rewrite `RemoteAddr` from its
header in a middleware before the handler. IPv6 clients usually control a whole /64, so key
per-address limits on the prefix rather than the full address.

`Replaces` is set only after the server has checked that the replaced certificate belongs to the
account and shares an identifier with the order, so a client cannot claim to renew someone else's
certificate to escape a limit.

## Pre-approved identifiers

Some CAs let an administrator approve names in advance for an external account binding, because
the CA cannot reach internal hosts and the team cannot publish DNS records. A policy that also
implements `PreApprover` names the identifiers of a new order that need no challenge:

```go
func (p customerPolicy) PreApprove(ctx context.Context, account *acmeserver.Account, order *acmeserver.Order) ([]acmeserver.Identifier, error) {
	var approved []acmeserver.Identifier
	for _, id := range order.Identifiers {
		if p.customers.Approved(ctx, account.ExternalAccountID, id) {
			approved = append(approved, id)
		}
	}
	return approved, nil
}
```

`PreApprove` runs after `NewOrder` has accepted the order and must not change it. Each returned
identifier must be one of `order.Identifiers`, wildcard names included. Its authorization starts
`valid` with no challenges and expires with the order. An order whose identifiers are all
pre-approved starts `ready`, so the client can finalize at once. The issuer sees `PreApproved` set
on those entries of `IssueRequest.Validations`.

A pre-approved authorization never lets the account revoke a certificate another account
ordered, because it proves nothing about control of the name. A returned `*Problem` refuses the
order. Any other error, or an identifier the order does not contain, is answered with
`serverInternal`.

## Accounts over their lifetime

* **Registration** returns the existing account when the key is already known, so a client that lost its account URL recovers it with `onlyReturnExisting`.
* **Contacts** must be `mailto` URLs with one bare address each, at most ten. Other schemes are refused with `unsupportedContact`.
* **Key rollover** replaces the key through the inner JWS of RFC 8555 section 7.3.5. An in-flight validation keeps the thumbprint captured when the client responded.
* **Deactivation** is permanent. Pending work of the account stops: a challenge accepted but not yet validated becomes invalid without a proof being fetched. New orders are refused. Recovery of an issuance the CA may already have completed continues, because the certificate may exist.
* **Order list** is served at the account's `orders` URL in pages of 100 with a `rel="next"` link.

Account IDs are random and appear only in the account URL. The store indexes accounts by ID and
by key thumbprint.

## Limits worth setting

| Field | Default | Reason to change |
| --- | --- | --- |
| `MaxIdentifiers` | 100 | Cap the size of one order for your CA |
| `OrderLifetime` | 7 days | How long a client has to complete validation and finalization |
| `AuthorizationLifetime` | 30 days | How long a validated authorization stays valid, which matters for revocation by another account |
| `MaxRequestBody` | 64 KiB | Raise only if a policy accepts unusually large CSRs |
