# Authority Token challenges

The `tkauth-01` challenge of RFC 9447 proves authority through a token instead of control of a
network resource. The client presents an Authority Token issued by a Token Authority the CA trusts.
The server supports two uses:

* STIR certificates for telephone service providers under RFC 9448. The token names the
  TNAuthList the certificate may carry.
* 5G network function certificates under 3GPP TS 33.310 Annex J. The operator's management system
  (OAM) issues a token for one network function instance, and the token may add the instance's NF
  type and further names. See [Network function certificates](#network-function-certificates).

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
`ChallengeTKAuth01` validator. `Config.NfInstanceIDIdentifiers` does the same for `NfInstanceId`
identifiers. The two can be enabled together. `Config.TokenAuthority` is the optional `token-authority` URL
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
5. `tktype` equals the identifier type, compared without regard to case because RFC 9447 and RFC 9448 spell `TNAuthList` differently.
6. `tkvalue` decodes to the same authority list as the challenge identifier. Padded and unpadded base64 are both accepted. For an `NfInstanceId`, `tkvalue` names the same UUID in any case.
7. `exp` and `nbf` hold, with `ClockSkew` tolerance, one minute by default.
8. `fingerprint` identifies the responding account key, either as the RFC 7638 thumbprint or as `SHA256` followed by the colon-separated hex form of the same digest.

The server does not track `jti` values. The same account can answer further `tkauth-01` challenges
with one token until its `exp`. RFC 9447 anticipates one token answering several challenges within
its lifetime, so keep `exp` short when that window matters.

The validator never fetches the `x5u` URL. Trusting a Token Authority is a deployment decision, so
the reference goes to your `TokenAuthorities` implementation. `StaticTokenAuthorities` covers a
fixed trust list indexed by exact URL and by `x5c` leaf certificate. A host whose ecosystem
publishes a trust list implements the interface itself. Returning a `*Problem` fails the challenge
and any other error is retried, which suits a lookup that could not be completed.

A successful validation records grants on the authorization: whether the token's `atc.ca` claim
authorizes a CA certificate and the token expiry as the latest acceptable certificate expiry. An NF
token also grants its NF type and extra names, see below.

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
earlier time. The expiry also bounds `IssueRequest.Deadline`. If the token expires before the worker
dispatches the order, the order becomes invalid with `authority token expired before issuance
dispatch` and the CA is not called. A leaf valid past the token expiry fails the publication check and is retained as an
unpublished result, see [Unpublished results](issuance.md#unpublished-results). The issuer recognizes a STIR order by the
`TNAuthList` identifier in `req.Identifiers` and copies the list from the CSR extension into the
certificate.

## Network function certificates

3GPP TS 33.310 Annex J lets a 5G network function (NF) enroll its own certificate. The NF is the
ACME client and orders one identifier of the form
`{"type": "NfInstanceId", "value": "4ace9d34-2c69-4f99-92d5-a73a3fe8e23b"}`. The value is the NF
instance UUID. It is lowercased and the nil UUID is refused. An order names at most one instance and
never combines it with a `TNAuthList`. DNS and IP identifiers in the same order keep their network
challenges.

The token is an NF Certificate Authority Token. Its `atc` claim has `tktype` `NfInstanceId`, the
UUID as `tkvalue` and the account `fingerprint`. Two optional members are checked as well:

* `nftype` must be an RFC 9310 NF type: 1 to 32 printable ASCII characters without spaces, such as `AMF`. It is not compared with a list, because 3GPP keeps adding types.
* `sans` lists further names for the certificate, at most 100. An entry starting with `urn:uuid:` must name the token's own instance. An entry containing `://` must be an `https` URI, such as an API root. An IP address is an `ip` name. Anything else must be a valid DNS name. Wildcard names are accepted and left to your policy.

These grants reach the issuer as `IssueRequest.Validations[].NFType` and `Names`. URIs appear as
identifiers of type `uri`, which only a token can grant. An order that names a `uri` identifier is
refused. A custom `GrantingValidator` may grant only `dns`, `ip` and `uri` names. Any other grant fails
the challenge with `serverInternal`.

The certificate request must include the instance as the URI name `urn:uuid:<value>`. It may add
any granted name and nothing else. The common name is not treated as an identifier, because the CA
sets the subject of an NF certificate. The leaf the issuer returns is checked the same way.

The issuer recognizes an NF order by the `NfInstanceId` identifier in `req.Identifiers`. It decides
the profile of TS 33.310 clause 6.1.3c.3 itself: the subject, the `nfTypes` extension from the
granted NF type, which granted names to include, key usages and validity. The token expiry bounds
`NotAfter` as for STIR orders, so a short token lifetime also limits the certificate lifetime.

The server does not track `jti` values here either, so one token answers further challenges for the
same instance and account until it expires. Clause J.4 limits revocation of an NF certificate to the
enrolling account and the holder of the certificate key. Another account is refused even when it
holds a valid authorization for the instance.

## Testing

No independent ACME client speaks `tkauth-01`. The interoperability module drives the flow with a
raw go-jose client and a local Token Authority, including a token issued to another account key that
must leave the order invalid without issuance and an `NfInstanceId` order with granted names. See
[Tested clients](../interoperability/tested-clients.md).
