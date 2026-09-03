<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

final class InMemoryAuthCodeRepository implements AuthCodeRepositoryInterface
{
    /** @var array<string, bool> */
    private array $revoked = [];

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new FixtureAuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
    }

    public function revokeAuthCode(string $codeId): void
    {
        $this->revoked[$codeId] = true;
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        return $this->revoked[$codeId] ?? false;
    }
}
