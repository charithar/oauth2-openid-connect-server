<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Entities;

use League\OAuth2\Server\Entities\UserEntityInterface;

interface ClaimsAwareUserEntityInterface extends UserEntityInterface
{
    /**
     * All claims this user can supply, keyed by claim name, regardless of
     * scope - ClaimExtractor filters this down to what the granted scopes
     * actually expose.
     *
     * @return array<string, mixed>
     */
    public function getClaims(): array;
}
