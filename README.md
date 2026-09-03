# charithar/oauth2-openid-connect-server

[![CI](https://github.com/charithar/oauth2-openid-connect-server/actions/workflows/ci.yml/badge.svg)](https://github.com/charithar/oauth2-openid-connect-server/actions/workflows/ci.yml)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-777bb4.svg)](composer.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A framework-agnostic OpenID Connect Core 1.0 layer for [league/oauth2-server](https://oauth2.thephpleague.com/), built on PHP 8.1+, PSR-7/PSR-15, and [lcobucci/jwt](https://github.com/lcobucci/jwt) v5.

This is a clean-room implementation built directly on league's own extension points, adding the OAuth2/OIDC surface (revocation, introspection, RP-Initiated Logout, response_mode, key rotation) needed for general-purpose use.

## Install

```bash
composer require charithar/oauth2-openid-connect-server
```

## What this library owns

- **`OidcAuthCodeGrant`** - a drop-in replacement for league's own `AuthCodeGrant` that adds:
  - `nonce` and `auth_time` support (carried inside the authorization code's own encrypted payload, so no extra storage is needed)
  - `response_mode` (`query` / `fragment` / `form_post`) on the authorize-success response
  - a fix for league throwing `invalid_client` on a `redirect_uri` mismatch, which RFC 6749 §5.2 reserves for failed *client* authentication - this now correctly raises `invalid_request`
- **`IdTokenResponse`** - signs and attaches `id_token` via league's own `getExtraParams()` extension point, using `lcobucci/jwt` v5, with support for multiple active signing keys (`kid` rotation)
- **`ClaimExtractor`** + **`StandardClaimSets`** - scope-to-claims resolution for `openid`/`profile`/`email`/`address`/`phone` (OIDC Core §5.4), which never leaks a JWT-registered claim name (avoiding the `sub`-claim collision bug found in the vendor library this replaces)
- **PSR-15 request handlers** for the endpoints league doesn't provide: discovery document, JWKS, a spec-correct Bearer-token UserInfo endpoint, RP-Initiated Logout, RFC 7009 token revocation, and RFC 7662 token introspection
- **`ClientCredentialsMiddleware`** - correctly percent-decodes `client_secret_basic` credentials per RFC 6749 §2.3.1 (league's own Basic-auth reader does not do this)

Everything is interface-based for persistence - there are no bundled repository implementations. You supply league's own repository interfaces plus this library's `UserRepositoryInterface` and `SigningKeyRepositoryInterface`.

## Wiring example

```php
use Charithar\OpenIDConnectServer\ClaimExtractor;
use Charithar\OpenIDConnectServer\ClaimSets\StandardClaimSets;
use Charithar\OpenIDConnectServer\Context\OidcRequestContext;
use Charithar\OpenIDConnectServer\Grants\OidcAuthCodeGrant;
use Charithar\OpenIDConnectServer\ResponseTypes\IdTokenResponse;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\RefreshTokenGrant;

$context = new OidcRequestContext();

$claimExtractor = new ClaimExtractor(StandardClaimSets::all());

$idTokenResponse = new IdTokenResponse(
    $userRepository,        // implements Charithar\OpenIDConnectServer\Repositories\UserRepositoryInterface
    $claimExtractor,
    $signingKeyRepository,  // implements Charithar\OpenIDConnectServer\Keys\SigningKeyRepositoryInterface
    $context,
    'https://issuer.example.com'
);

$authServer = new AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey,
    $idTokenResponse
);

$authCodeGrant = new OidcAuthCodeGrant(
    $context,
    $authCodeRepository,
    $refreshTokenRepository,
    new DateInterval('PT10M')
);

$authServer->enableGrantType($authCodeGrant, new DateInterval('PT1H'));
$authServer->enableGrantType(new RefreshTokenGrant($refreshTokenRepository), new DateInterval('PT1H'));
```

Mount the standard endpoints wherever your router/framework of choice puts them:

```php
use Charithar\OpenIDConnectServer\Discovery\DiscoveryDocument;
use Charithar\OpenIDConnectServer\Discovery\DiscoveryRequestHandler;
use Charithar\OpenIDConnectServer\Jwks\JwksFactory;
use Charithar\OpenIDConnectServer\Jwks\JwksRequestHandler;
use Charithar\OpenIDConnectServer\UserInfo\UserInfoRequestHandler;
use Charithar\OpenIDConnectServer\Logout\LogoutRequestHandler;
use Charithar\OpenIDConnectServer\Revocation\TokenRevocationRequestHandler;
use Charithar\OpenIDConnectServer\Introspection\TokenIntrospectionRequestHandler;
use League\OAuth2\Server\ResourceServer;

// GET /.well-known/openid-configuration
$discoveryHandler = new DiscoveryRequestHandler($discoveryDocument, $responseFactory);

// GET /.well-known/jwks.json
$jwksHandler = new JwksRequestHandler(new JwksFactory($signingKeyRepository), $responseFactory);

// UserInfoRequestHandler validates the Bearer token itself, via league's own
// ResourceServer - construct one with the same access token repository and
// public key your resource server / access-token validation already uses.
$resourceServer = new ResourceServer($accessTokenRepository, $publicKey);

// GET/POST /oauth2/userinfo (Bearer token)
$userInfoHandler = new UserInfoRequestHandler($resourceServer, $userRepository, $claimExtractor, $responseFactory);

// GET /logout (RP-Initiated Logout)
$logoutHandler = new LogoutRequestHandler($clientRepository, $signingKeyRepository, 'https://issuer.example.com', $responseFactory, $sessionHandler);

// POST /oauth2/revoke - mount behind ClientCredentialsMiddleware
$revocationHandler = new TokenRevocationRequestHandler($clientRepository, $accessTokenRepository, $refreshTokenRepository, $encryptionKey, $responseFactory);

// POST /oauth2/introspect - mount behind ClientCredentialsMiddleware
$introspectionHandler = new TokenIntrospectionRequestHandler($clientRepository, $accessTokenRepository, $refreshTokenRepository, $encryptionKey, $responseFactory);
```

> **`ClientRepositoryInterface::validateClient()` note:** revocation and introspection aren't tied to any grant, so both handlers call `validateClient($clientId, $clientSecret, null)` - a `null` grant type. If your implementation switches on the third argument (e.g. to restrict a secret to specific grants), make sure it treats `null` as "just verify the secret," not as an unrecognized/rejected case.

## Interfaces you implement

| Interface | Purpose |
|---|---|
| `Repositories\UserRepositoryInterface` | Look up a claims-bearing user by identifier |
| `Keys\SigningKeyRepositoryInterface` | Supply one or more RSA signing keys for id_token signing and JWKS, enabling `kid` rotation (RS256 only in this version - see Limitations) |
| `Entities\ClaimsAwareUserEntityInterface` | Your user entity: extends league's `UserEntityInterface`, adds `getClaims(): array` |
| `Entities\ClaimsAwareClientEntityInterface` | Your client entity: extends league's `ClientEntityInterface`, adds `getPostLogoutRedirectUris(): array` |
| `Logout\LogoutSessionHandlerInterface` | *(optional)* Hook for your own session teardown on RP-Initiated Logout |

Plus league/oauth2-server's own repository interfaces (`ClientRepositoryInterface`, `AccessTokenRepositoryInterface`, `RefreshTokenRepositoryInterface`, `AuthCodeRepositoryInterface`, `ScopeRepositoryInterface`).

## Not in scope (v1)

Hybrid/implicit flow, id_token encryption (JWE), pairwise subject identifiers, a consent screen, dynamic client registration, and front/back-channel logout are deliberately not implemented. Authorization Code (with PKCE, via league's own support) and Refresh Token are the supported grants.

## Limitations

- **RS256 only.** id_tokens are always signed with RS256, and `JwksFactory` only knows how to publish RSA keys - `SigningKeyInterface::getAlgorithm()` must return `"RS256"`, and both `IdTokenResponse` and `JwksFactory` throw a clear exception otherwise rather than producing a token or JWKS entry that doesn't match what was actually used. EC (ES256/384/512) and OKP (EdDSA) keys aren't supported yet.

## Development

```bash
composer install
composer test      # PHPUnit
composer stan       # PHPStan level 8
composer cs-check   # PHP-CS-Fixer (dry-run)
composer cs-fix      # PHP-CS-Fixer (apply)
```

## License

MIT.

## Acknowledgments

Inspired by [steverhoades/oauth2-openid-connect-server](https://github.com/steverhoades/oauth2-openid-connect-server), an OIDC add-on for league/oauth2-server. This library is an independent, clean-room implementation - no code is shared - built to add the OAuth2/OIDC surface and fixes needed for general-purpose use.
