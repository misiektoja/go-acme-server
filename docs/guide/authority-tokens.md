# Authority Token challenges

The `tkauth-01` challenge of RFC 9447 proves authority over a set of telephone numbers instead of
control of a network resource. It is how STIR certificates are issued to service providers under
RFC 9448. The client presents an Authority Token issued by a Token Authority the CA trusts. The
token names the TNAuthList the certificate may carry.

## Enable it

```go
tkauth, err := challenge.NewTKAuth01(challenge.TKAuthOptions{
	Authorities: challenge.StaticTokenAuthorities{
		ByURL: map[string]*x509.Certificate{
			"https://authority.example.com/cert": authorityCert,
		},
	},
})

cfg := acmeserver.Config{
	TNAuthListIdentifiers: true,
	TokenAuthority:        "https://authority.example.com/token",
	Validators: map[acmeserver.ChallengeType]acmeserver.Validator{
		acmeserver.ChallengeHTTP01:  http01,
		acmeserver.ChallengeTKAuth01: tkauth,
	},
}
```

`Config.TNAuthListIdentifiers` accepts orders with an identifier of type `TNAuthList` and requires a
`ChallengeTKAuth01` validator. `Config.TokenAuthority` is the optional `token-authority` URL
advertised on each challenge, which tells clients where to obtain a token. Clients fall back to
their own configuration when it is empty.

## What an order looks like

An order carries at most one `TNAuthList` identifier. Its value is the unpadded base64url encoding of
a DER `TNAuthorizationList` from RFC 8226. That identifier receives a single `tkauth-01` challenge
with `tkauth-type` set to `atc`. Any DNS or IP identifiers in the same order keep their network
challenges.

The client answers the challenge with a payload of the form `{"tkauth": "<token>"}`. The server
stores the token on the challenge and hands it to the validator.

## What the validator checks

The validator performs steps 1 to 8 of RFC 9448 section 6:

1. The token is a compact JWS and its payload carries `exp`, `jti` and an `atc` claim with `tktype`, `tkvalue` and `fingerprint`.
2. The header names a Token Authority either by an `https` `x5u` URL or by an `x5c` chain.
3. `TokenAuthorities.AuthorityCertificate` returns the certificate that must have signed the token. The certificate must be within its validity period.
4. The token signature verifies under that certificate's key.
5. `tktype` equals `TNAuthList`, compared without regard to case because RFC 9447 and RFC 9448 spell it differently.
6. `tkvalue` decodes to the same authority list as the challenge identifier. Padded and unpadded base64 are both accepted.
7. `exp` and `nbf` hold, with `ClockSkew` tolerance, one minute by default.
8. `fingerprint` identifies the responding account key, either as the RFC 7638 thumbprint or as `SHA256` followed by the colon-separated hex form of the same digest.

The validator never fetches the `x5u` URL. Trusting a Token Authority is a deployment decision, so
the reference goes to your `TokenAuthorities` implementation. `StaticTokenAuthorities` covers a
fixed trust list indexed by exact URL and by `x5c` leaf certificate. A host whose ecosystem
publishes a trust list implements the interface itself. Returning a `*Problem` fails the challenge
and any other error is retried, which suits a lookup that could not be completed.

A successful validation records two grants on the authorization: whether the token's `atc.ca`
claim authorizes a CA certificate and the token expiry as the latest acceptable certificate expiry.

## Finalization and issuance

The certificate request must carry the same authority list in its `id-pe-TNAuthList` extension
request. The subject common name normally counts as a requested identifier and must match one of
the order's identifiers. It is exempt when the authority list is the only identifier, so the request
may name the service provider there. An order that also covers DNS or IP identifiers keeps the
normal rule.

Every authorization of the order must have granted exactly what the request asks for. A request
for a CA certificate without the `ca` grant is refused as `badCSR`. So is a request without the
CA basic constraint after the grant. Network challenges grant nothing, so a mixed order can never
finalize a CA certificate.

The issuer receives the token expiry as `IssueRequest.NotAfter` unless the order asked for an
earlier time. A leaf valid past the token expiry fails the publication check and is retained as an
[unpublished result](issuance.md#unpublished-results). The issuer recognizes a STIR order by the
`TNAuthList` identifier in `req.Identifiers` and copies the list from the CSR extension into the
certificate.

## Testing

No independent ACME client speaks `tkauth-01`. The interoperability module drives the flow with a
raw go-jose client and a local Token Authority, including a token issued to another account key that
must leave the order invalid without issuance. See [Tested clients](../interoperability/tested-clients.md).
