<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Entities;

final class ClaimSetEntity implements ClaimSetInterface
{
    /**
     * @param non-empty-string $scope
     * @param non-empty-string[] $claims
     */
    public function __construct(
        private readonly string $scope,
        private readonly array $claims
    ) {
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }
}
