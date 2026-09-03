<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use League\OAuth2\Server\Entities\ScopeEntityInterface;

final class FixtureScope implements ScopeEntityInterface
{
    public function __construct(private readonly string $identifier)
    {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function jsonSerialize(): string
    {
        return $this->identifier;
    }
}
