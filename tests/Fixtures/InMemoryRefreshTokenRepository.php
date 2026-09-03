<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

final class InMemoryRefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    /** @var array<string, bool> */
    private array $revoked = [];

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new class () implements RefreshTokenEntityInterface {
            use RefreshTokenTrait;

            private string $identifier;

            public function getIdentifier(): string
            {
                return $this->identifier;
            }

            public function setIdentifier(string $identifier): void
            {
                $this->identifier = $identifier;
            }
        };
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $this->revoked[$tokenId] = true;
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return $this->revoked[$tokenId] ?? false;
    }
}
