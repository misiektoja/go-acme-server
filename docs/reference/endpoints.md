# Endpoints

Every resource lives below `Config.BaseURL`. The table uses `https://ca.example.com/acme/` as the
base URL. Resource IDs are opaque random strings.

| Path | Methods | Resource |
| --- | --- | --- |
| `directory` | GET, HEAD | The directory object with the `meta` member when configured |
| `new-nonce` | GET, HEAD | A fresh `Replay-Nonce`. HEAD answers 200, GET answers 204 |
| `new-account` | POST | Account creation and lookup, signed with an embedded JWK |
| `new-order` | POST | Order creation |
| `revoke-cert` | POST | Revocation, signed with an account `kid` or the certificate key as an embedded JWK |
| `key-change` | POST | Account key rollover |
| `acct/<id>` | POST | Account update, deactivation and POST-as-GET |
| `acct/<id>/orders` | POST | The account's order list in pages of 100 with a `rel="next"` link |
| `order/<id>` | POST | Order status and POST-as-GET |
| `order/<id>/finalize` | POST | Finalization with a CSR |
| `authz/<id>` | POST | Authorization status, deactivation and POST-as-GET |
| `chall/<id>` | POST | Challenge status and the client's response |
| `cert/<id>` | POST | The certificate chain as `application/pem-certificate-chain` |
| `renewal-info/<id>` | GET, HEAD | RFC 9773 renewal information, only with `Config.RenewalInfo` |

Any other path below the base URL and any path outside it is answered with a `404` `malformed`
problem. A method the resource does not support is answered with `405` and an `Allow` header.

## Headers

Every response except the directory carries `Cache-Control: no-store` and a `Link` header with
`rel="index"` pointing at the directory. Every POST response and every problem document carries
a fresh `Replay-Nonce`. `newAccount` responses carry a `Link` with `rel="terms-of-service"` when
`Meta.TermsOfService` is set. Processing orders and challenges carry `Retry-After`, and so do
problems built with `WithRetryAfter`. Renewal information responses carry the advisor's
`Retry-After`.

Request bodies must be `application/jose+json` and at most `Config.MaxRequestBody` bytes.
Responses are `application/json`, `application/problem+json` or
`application/pem-certificate-chain`.

## What the handler expects from the host

* The request path reaches the handler with the base URL path intact, so `r.URL.Path` starts with `/acme/` in the example.
* The scheme, host and port clients used equal those in `Config.BaseURL`, because the signed `url` in every request is compared with the URL the server builds from the base URL. A query string, if any, is compared too.
* TLS is terminated by the host. The handler never inspects the connection.

[Deployment](../operations/deployment.md) shows reverse proxy configurations that satisfy these rules.
