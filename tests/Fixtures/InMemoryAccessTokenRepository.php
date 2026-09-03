<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final class InMemoryAccessTokenRepository implements AccessTokenRepositoryInterface
{
    /** @var array<string, bool> */
    private array $revoked = [];

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, string|null $userIdentifier = null): AccessTokenEntityInterface
    {
        $token = new FixtureAccessToken();
        $token->setClient($clientEntity);

        if ($userIdentifier !== null) {
            $token->setUserIdentifier($userIdentifier);
        }

        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->revoked[$tokenId] = true;
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return $this->revoked[$tokenId] ?? false;
    }
}
