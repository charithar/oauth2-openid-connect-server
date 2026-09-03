# charithar/oauth2-openid-connect-server

Framework-agnostic OpenID Connect Core 1.0 layer for [league/oauth2-server](https://oauth2.thephpleague.com/). PHP 8.1+, PSR-7/PSR-15, `lcobucci/jwt` v5. MIT licensed, intended for public release. See `README.md` for the user-facing API and wiring example.

## Origin and design stance

This library exists because a production app (a separate, private codebase) was running `steverhoades/oauth2-openid-connect-server` on top of league/oauth2-server, hit several real bugs/gaps in it, and needed a general-purpose replacement. This is a **clean-room implementation**, not a fork or wrapper: no code is shared, interfaces are named independently, and the app's specific fixes were generalized into first-class features here rather than ported as overrides. See the README's Acknowledgments section for the credit line.

Non-negotiable design constraints, decided deliberately:
- **PHP 8.1+, no lower.** (Originally scoped for 7.4+, raised to 8.1 mid-design.)
- **Interfaces only for persistence.** No Doctrine/PDO/concrete repository implementations ship in this package - consumers implement league's own repository interfaces plus this library's `Repositories\UserRepositoryInterface` and `Keys\SigningKeyRepositoryInterface`.
- **Building blocks + PSR-15 handlers**, not just building blocks. The library ships mountable handlers for discovery, JWKS, UserInfo, RP-Initiated Logout, revocation, and introspection - not just grants/response-types - specifically to reduce integration boilerplate while staying framework-agnostic (PSR-15 is a standard, not a framework).
- **No hybrid/implicit flow, no id_token encryption (JWE), no pairwise subject identifiers, no consent screen, no dynamic client registration, no front/back-channel logout.** Deliberately out of scope for v1. Authorization Code (+PKCE via league's own support) and Refresh Token are the only grants.

## Architecture map

| Area | Class(es) | Why it exists |
|---|---|---|
| Grant | `Grants\OidcAuthCodeGrant` | Extends league's `AuthCodeGrant`. Adds nonce/auth_time, `response_mode`, and a redirect_uri error-taxonomy fix (see below). |
| Authorize request | `RequestTypes\OidcAuthorizationRequest` | Extends league's `AuthorizationRequest` with `nonce`, `authTime`, `responseMode` fields league has no room for. |
| Response mode | `ResponseModes\ResponseMode`, `ResponseModes\ModeAwareRedirectResponse` | Replaces league's hardcoded query-string-only `RedirectResponse` for the authorize-success path. |
| id_token | `ResponseTypes\IdTokenResponse` | Extends league's `BearerTokenResponse`, overriding the `getExtraParams()` hook league itself documents for this purpose. Builds/signs the JWT directly (not layered on the access token's own claims) so a registered-claim name can never reach `withClaim()` and throw. |
| Claims | `ClaimExtractor`, `ClaimSets\StandardClaimSets`, `Entities\ClaimSetInterface`/`ClaimSetEntity` | Scope -> claims resolution. `ClaimExtractor::extract()` *always* strips RFC 7519 registered claim names (iss/sub/aud/exp/nbf/iat/jti) regardless of scope - this is the fix for the classic "openid scope leaks a `sub` claim that then collides with the JWT builder's own `sub`" bug, done by design rather than as a special-cased workaround. |
| Cross-request bridging | `Context\OidcRequestContext` | See "The nonce/auth_time bridge" below. |
| Keys | `Keys\SigningKeyInterface`, `Keys\SigningKeyRepositoryInterface` | Consumer-implemented; supports multiple simultaneously-active keys for `kid` rotation. |
| JWKS | `Jwks\JwksFactory`, `Jwks\JwksRequestHandler` | Builds an RFC 7517 JWK Set from all active keys via `openssl_pkey_get_details()` (RSA only - no EC/OKP support yet). |
| Discovery | `Discovery\DiscoveryDocument`, `Discovery\DiscoveryRequestHandler` | Plain value object + PSR-15 handler. Every endpoint URL is passed in explicitly by the consumer - the library assumes no routing convention. |
| Client auth | `ClientAuthentication\ClientCredentialsMiddleware` | Fixes league's `getBasicAuthCredentials()`, which base64-decodes an `Authorization: Basic` header and splits on `:` but never percent-decodes the parts, contrary to RFC 6749 §2.3.1. Injects corrected values into the parsed body (where league already looks first), so client_secret_post values already present are never overwritten. |
| UserInfo | `UserInfo\UserInfoRequestHandler` | The **spec-correct**, Bearer-token-validated endpoint (via league's `ResourceServer`). A session-cookie-authenticated variant for a browser/SPA is an app-specific concern and does not belong in this library. |
| Logout | `Logout\LogoutRequestHandler`, `Logout\LogoutSessionHandlerInterface` | OIDC RP-Initiated Logout. Validates `id_token_hint` (signature/issuer/expiry), resolves the client via `aud`, and only redirects to a `post_logout_redirect_uri` the client has registered (`Entities\ClaimsAwareClientEntityInterface::getPostLogoutRedirectUris()`) - anything else still logs the user out but responds 200 instead of becoming an open redirect. Session teardown itself is delegated to `LogoutSessionHandlerInterface` since it's framework-specific. |
| Revocation / Introspection | `Revocation\TokenRevocationRequestHandler` (RFC 7009), `Introspection\TokenIntrospectionRequestHandler` (RFC 7662) | league ships neither. No extra repository interfaces were needed: access tokens are self-contained signed JWTs (client/`aud` and id/`jti` are read directly off the parsed token), and refresh tokens are opaque payloads encrypted with the *same* key league's own grants already use for them - both handlers `use League\OAuth2\Server\CryptTrait;` directly to decrypt them the same way, without going through a Grant. |

## The nonce/auth_time bridge (the trickiest part)

league/oauth2-server has no concept of OIDC `nonce` or `auth_time`. They need to survive two boundaries:

1. **Authorize request -> redeemed auth code (a real HTTP redirect apart, possibly minutes later).** Solved by putting `nonce` and `auth_time` *inside the same encrypted JSON payload* league's own `AuthCodeGrant` already builds for `client_id`/`redirect_uri`/`scopes`/etc. No extra storage, no repository lookup - `OidcAuthCodeGrant::completeAuthorizationRequest()` adds the two fields to that payload, and `respondToAccessTokenRequest()` decrypts the redeemed code (via the inherited `CryptTrait::decrypt()`) purely to read them back out.
2. **Grant -> response type, within the same token-endpoint request.** `OidcAuthCodeGrant` and `IdTokenResponse` are two different objects instantiated together by the consumer's bootstrap/factory (same as league's own `AuthorizationServerFactory` pattern). They share one `Context\OidcRequestContext` instance, injected into both at construction. This is a plain, non-static, per-request object - not a global - specifically so it doesn't become the kind of hidden static state the app this library replaces relied on (`NonceHolder`/`AuthTimeHolder` there). **Constraint this implies:** one `OidcRequestContext` (and the `AuthorizationServer`/grant/response-type built around it) must be constructed fresh per HTTP request. Fine under traditional PHP-FPM/CLI-server lifecycles; a long-running worker runtime (Swoole, RoadRunner) must not reuse one across requests.

`auth_time` itself has no `/authorize` query parameter - the consuming app calls `$authorizationRequest->setAuthTime(...)` itself once it knows when the user actually authenticated, the same way it already calls `setUser()`.

## The redirect_uri fix

league/oauth2-server 9.3's `AbstractGrant::validateRedirectUri()` throws `invalid_client` on a `redirect_uri` mismatch. RFC 6749 §5.2 reserves `invalid_client` for failed *client* authentication (bad client_id/secret) - a redirect_uri mismatch is a different failure and should be `invalid_request`, which is what `AuthCodeGrant::validateAuthorizationCode()` already correctly uses for the equivalent check at token-exchange time. `OidcAuthCodeGrant::validateRedirectUri()` overrides the one (protected) method both the `/authorize` and `/token` paths delegate to, fixing both call sites at once. Covered by `tests/Unit/OidcAuthCodeGrantTest.php::testRedirectUriMismatchRaisesInvalidRequestNotInvalidClient`.

## Testing

No mocking framework is used - `tests/Fixtures/` holds small in-memory implementations of every league + this-library repository/entity interface (`InMemory*Repository`, `Fixture*`). `tests/Fixtures/keys/rsa{1,2}.key` are static, checked-in 2048-bit RSA test keys (generated once via the `openssl` CLI) - signing-key fixtures deliberately do **not** call `openssl_pkey_new()` at test time, because that call depends on an openssl.cnf being discoverable and is not reliable on every machine (this bit Windows PHP installs during development).

```bash
composer install
composer test       # PHPUnit
composer stan        # PHPStan level 8 (phpstan/phpstan ^2.2)
composer cs-check    # PHP-CS-Fixer, dry-run
composer cs-fix      # PHP-CS-Fixer, apply
```

CI (`.github/workflows/ci.yml`) runs all three across a PHP 8.1-8.4 matrix on every push/PR to `main`/`dev`, via `composer update` (no committed lockfile - this is a library, consumers resolve their own versions). Because of that, **anything used directly in this library's own source must be a direct `require`**, not relied on transitively - `lcobucci/clock` was added as a direct dependency for exactly this reason (it's used directly for `SystemClock::fromUTC()` in the Logout/Introspection handlers, but is only pulled in transitively via `league/oauth2-server`, not `lcobucci/jwt`, so a from-scratch CI resolution isn't guaranteed to keep bringing it in).

## Repo state

- GitHub: `charithar/oauth2-openid-connect-server`, MIT license.
- `main` and `dev` are kept in sync as a single linear history (no long-lived divergence) - both branches were deliberately reset to the same clean history at the point this file was added, after an earlier accidental merge briefly reintroduced now-superseded commit content.
