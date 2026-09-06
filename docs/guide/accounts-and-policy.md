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
[issuance policy](issuance.md#issuance-policy).

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
failure. HS256, HS384 and HS512 are accepted. A verified binding stores the key identifier as
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
for example to cap the requested validity, but must not change the identifiers.

A returned `*Problem` is sent to the client. Any other error is logged and answered with
`serverInternal`. Rate limiting belongs here too. Return a `rateLimited` problem built with
`WithRetryAfter` and the client backs off.

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
