# Changelog

All notable changes to this project are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [1.0.0]

Initial public release.

### Added

- `Grants\OidcAuthCodeGrant` - authorization_code grant with OIDC `nonce`/`auth_time` support, `response_mode` (`query`/`fragment`/`form_post`), and a fix for league/oauth2-server raising `invalid_client` instead of `invalid_request` on a `redirect_uri` mismatch (RFC 6749 §5.2).
- `ResponseTypes\IdTokenResponse` - signs and attaches `id_token` via `lcobucci/jwt` v5, with `kid`-based multi-key rotation support (RS256 only - see README Limitations).
- `ClaimExtractor` + `ClaimSets\StandardClaimSets` - scope-to-claims resolution for the standard `openid`/`profile`/`email`/`address`/`phone` scopes (OIDC Core §5.4), always excluding JWT-registered claim names.
- PSR-15 request handlers: `Discovery\DiscoveryRequestHandler`, `Jwks\JwksRequestHandler`, `UserInfo\UserInfoRequestHandler` (Bearer-token, spec-correct), `Logout\LogoutRequestHandler` (RP-Initiated Logout), `Revocation\TokenRevocationRequestHandler` (RFC 7009), `Introspection\TokenIntrospectionRequestHandler` (RFC 7662).
- `ClientAuthentication\ClientCredentialsMiddleware` - RFC 6749 §2.3.1-compliant percent-decoding of `client_secret_basic` credentials.
- Interfaces for persistence: `Repositories\UserRepositoryInterface`, `Keys\SigningKeyRepositoryInterface`, `Entities\ClaimsAwareUserEntityInterface`, `Entities\ClaimsAwareClientEntityInterface`, `Logout\LogoutSessionHandlerInterface`.

### Known limitations

- RS256 signing keys only (see README Limitations).
- No hybrid/implicit flow, id_token encryption (JWE), pairwise subject identifiers, consent screen, dynamic client registration, or front/back-channel logout (see README "Not in scope (v1)").
