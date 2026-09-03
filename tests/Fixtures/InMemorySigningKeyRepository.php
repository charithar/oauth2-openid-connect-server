<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use Charithar\OpenIDConnectServer\Keys\SigningKeyInterface;
use Charithar\OpenIDConnectServer\Keys\SigningKeyRepositoryInterface;
use RuntimeException;

final class InMemorySigningKeyRepository implements SigningKeyRepositoryInterface
{
    /** @var SigningKeyInterface[] */
    private array $keys;

    public function __construct(SigningKeyInterface ...$keys)
    {
        $this->keys = $keys;
    }

    public function getActiveKeys(): array
    {
        return $this->keys;
    }

    public function getCurrentSigningKey(): SigningKeyInterface
    {
        return $this->keys[0] ?? throw new RuntimeException('No signing keys configured');
    }
}
