# Certificate profiles

A certificate profile is a named kind of certificate the CA issues, such as a TLS server
certificate or a short-lived one. The draft [draft-ietf-acme-profiles](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/)
lets a server list its profiles in the directory and lets a client name one on a new order.
Setting `Config.Profiles` enables it. The draft is not an RFC yet, so its wire format may still
change.

```go
Profiles: []acmeserver.Profile{
	{Name: "tls-server", Description: "TLS server certificate, valid for 90 days"},
	{Name: "short-lived", Description: "TLS server certificate, valid for 7 days"},
	{Name: "legacy", URL: "https://ca.example.com/profiles/legacy"},
},
DefaultProfile: "tls-server",
```

The library carries the profile name from the order to your `Issuer`. What a profile means, such
as its key usages, extended key usages or validity, is decided by your CA.

## The directory

The directory `meta` member gains `profiles`, an object that maps each name to the URL of a
human-readable description:

```json
"profiles": {
  "tls-server": "https://ca.example.com/acme/profiles/tls-server",
  "short-lived": "https://ca.example.com/acme/profiles/short-lived",
  "legacy": "https://ca.example.com/profiles/legacy"
}
```

A profile with a `Description` is described by the server itself at `<BaseURL>profiles/<name>`,
served as `text/plain` to GET and HEAD. A profile with a `URL` points at a page you publish
elsewhere. Each profile needs exactly one of the two.

A name has 1 to 64 ASCII letters, digits, dots, underscores or hyphens and starts with a letter or
digit. This keeps names safe in URLs and in clients that parse the directory loosely.

## Choosing a profile on an order

A new order may carry a `profile` member:

* A name the server offers selects that profile.
* No `profile` member selects `Config.DefaultProfile`, so clients without profile support keep
  getting the default certificate.
* Any other name is refused with `invalidProfile`. The server never falls back to the default for
  a name it does not offer, because the client asked for something specific.

The order object shows the selected profile in its `profile` member. `Order.Profile` stores it.
`Policy.NewOrder` cannot change it. `IssueRequest.Profile` tells the issuer which profile to apply.

Clients send the member in different ways. Certbot sends `--required-profile` always and
`--preferred-profile` only when the directory lists that name. lego has `--profile`, acme.sh has
`--cert-profile` and cert-manager has `spec.acme.profile` on the issuer.

## Changing the profile list

Profiles are read from `Config` when the server is created. When you remove a profile, orders
created under it are refused with `invalidProfile` at finalization. Orders already finalized
continue. The draft recommends keeping a profile until the orders that use it have expired, which
`Config.OrderLifetime` bounds.

Orders created while `Config.Profiles` was empty have no profile. They finalize normally after you
add profiles. `IssueRequest.Profile` is empty for them.

Without `Config.Profiles`, the directory has no `profiles` member and a new order that names a
profile is refused with `invalidProfile`.

## Renewal

The draft does not tie a profile to renewal. A client that renews sends the profile it is
configured with, which can differ from the profile of the certificate it replaces. Certbot and
acme.sh store the profile in their renewal configuration. A renewal without a profile gets the
default.
