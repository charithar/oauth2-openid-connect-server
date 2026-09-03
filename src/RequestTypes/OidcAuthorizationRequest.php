<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\RequestTypes;

use Charithar\OpenIDConnectServer\ResponseModes\ResponseMode;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

/**
 * Adds the OIDC-specific fields league/oauth2-server's own AuthorizationRequest
 * has no room for. `nonce` and `response_mode` are populated by
 * OidcAuthCodeGrant::validateAuthorizationRequest() from the /authorize query
 * string. `auth_time` has no equivalent request parameter - the consuming
 * app calls setAuthTime() itself (the same way it already calls setUser())
 * once it knows when the end-user actually authenticated, before invoking
 * completeAuthorizationRequest().
 */
class OidcAuthorizationRequest extends AuthorizationRequest
{
    private ?string $nonce = null;

    private ?int $authTime = null;

    private ?ResponseMode $responseMode = null;

    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }

    public function getAuthTime(): ?int
    {
        return $this->authTime;
    }

    public function setAuthTime(?int $authTime): void
    {
        $this->authTime = $authTime;
    }

    public function getResponseMode(): ?ResponseMode
    {
        return $this->responseMode;
    }

    public function setResponseMode(?ResponseMode $responseMode): void
    {
        $this->responseMode = $responseMode;
    }
}
