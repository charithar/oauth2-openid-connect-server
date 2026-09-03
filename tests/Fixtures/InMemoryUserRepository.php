<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use Charithar\OpenIDConnectServer\Entities\ClaimsAwareUserEntityInterface;
use Charithar\OpenIDConnectServer\Repositories\UserRepositoryInterface;

final class InMemoryUserRepository implements UserRepositoryInterface
{
    /** @var array<string, ClaimsAwareUserEntityInterface> */
    private array $users = [];

    public function add(ClaimsAwareUserEntityInterface $user): void
    {
        $this->users[$user->getIdentifier()] = $user;
    }

    public function getUserEntityByIdentifier(string $identifier): ?ClaimsAwareUserEntityInterface
    {
        return $this->users[$identifier] ?? null;
    }
}
