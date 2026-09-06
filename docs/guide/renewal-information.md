# Renewal information

RFC 9773 lets a server tell each client when to renew a certificate and lets a client name the
certificate a new order replaces. Setting `Config.RenewalInfo` enables both.

```go
RenewalInfo: acmeserver.LifetimeRenewal{},
```

With it set, the directory advertises `renewalInfo`, clients fetch a suggested window with an
unauthenticated GET and new orders may carry `replaces`. Without it, the resource is absent and a
`replaces` member is ignored.

## The renewal window

```go
type RenewalAdvisor interface {
	RenewalInfo(ctx context.Context, cert *Certificate) (RenewalInfo, error)
}
```

`LifetimeRenewal` is the built-in advisor. It opens the window at two thirds of the certificate
lifetime and closes it at five sixths. For a 90-day certificate that is days 60 to 75. A revoked
certificate gets a window that opened at its revocation time, so clients renew at once. The
fractions, an explanation URL and the `Retry-After` are fields on the struct:

```go
RenewalInfo: acmeserver.LifetimeRenewal{
	Start:          0.5,
	End:            0.75,
	ExplanationURL: "https://ca.example.com/renewal",
	RetryAfter:     12 * time.Hour,
},
```

Implement `RenewalAdvisor` for other schedules, for example to move every window forward when a
CA incident requires mass renewal. The `End` must be later than the `Start`. `RetryAfter` defaults
to six hours and tells clients how long to wait before asking again.

## The certificate identifier

Clients address renewal information by the certificate identifier of RFC 9773 section 4.1: the
base64url authority key identifier and the base64url serial number joined by a dot. The server
computes it as `Certificate.RenewalID` when the certificate is stored. It is empty when the leaf
has no authority key identifier. Such a certificate has no renewal information and cannot be
replaced. Make sure your CA sets the extension.

Stores keep non-empty `RenewalID` values unique and look certificates up by them through
`CertificateByRenewalID`.

## Replacing a certificate

A new order may name the certificate it replaces. The server checks that:

* the identifier is well formed and names a stored certificate, otherwise `malformed`
* the certificate belongs to the requesting account, otherwise `unauthorized`
* the new order shares at least one identifier with the certificate's validated identifiers, otherwise `malformed`

The store then marks the certificate as replaced by the order in the same transaction that creates
the order. A second order naming the same certificate is refused with `alreadyReplaced` while the
first one is not invalid. Once the first order expires or fails, the claim is free again. Clients
such as acmez and lego drop the `replaces` member after an `alreadyReplaced` answer and order
without it.

`Order.Replaces` and `Certificate.ReplacedByOrderID` record the relation for the host. A CA that
wants to revoke the old certificate once the new one is issued has both ends of the link.
