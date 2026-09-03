<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

final class InMemoryScopeRepository implements ScopeRepositoryInterface
{
    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return new FixtureScope($identifier);
    }

    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, string|null $userIdentifier = null, ?string $authCodeId = null): array
    {
        return $scopes;
    }
}
