<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use Charithar\OpenIDConnectServer\Entities\ClaimsAwareUserEntityInterface;

final class FixtureUser implements ClaimsAwareUserEntityInterface
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private readonly string $identifier,
        private readonly array $claims = []
    ) {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }
}
