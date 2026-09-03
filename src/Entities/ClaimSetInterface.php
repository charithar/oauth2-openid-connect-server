<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Entities;

/**
 * A named group of claims that becomes available when its scope is granted,
 * per OIDC Core 1.0 §5.4 (Requesting Claims using Scope Values).
 */
interface ClaimSetInterface
{
    /**
     * The OAuth2 scope identifier that unlocks this claim set (e.g. "profile").
     *
     * @return non-empty-string
     */
    public function getScope(): string;

    /**
     * @return non-empty-string[] Claim names carried by this scope.
     */
    public function getClaims(): array;
}
