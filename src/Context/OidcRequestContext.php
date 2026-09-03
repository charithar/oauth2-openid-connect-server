<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Context;

/**
 * Carries the OIDC `nonce` and `auth_time` values from OidcAuthCodeGrant
 * (which decrypts the redeemed authorization code during the token request
 * and finds them in its payload) to IdTokenResponse (which needs them when
 * it signs the id_token moments later, in the same request/response cycle).
 *
 * This is a plain, non-static object precisely so it is not global state:
 * construct exactly one instance per incoming HTTP request and inject the
 * same instance into both OidcAuthCodeGrant and IdTokenResponse when you
 * build them. That is safe under the traditional PHP-FPM/CLI-server
 * per-request lifecycle. Under a long-running worker runtime (Swoole,
 * RoadRunner, etc.), make sure a fresh instance - and fresh
 * AuthorizationServer/grant/response-type instances - are built for every
 * request; do not reuse one across requests.
 */
final class OidcRequestContext
{
    private ?string $nonce = null;

    private ?int $authTime = null;

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }

    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setAuthTime(?int $authTime): void
    {
        $this->authTime = $authTime;
    }

    public function getAuthTime(): ?int
    {
        return $this->authTime;
    }
}
