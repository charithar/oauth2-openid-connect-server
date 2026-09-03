<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use Charithar\OpenIDConnectServer\Entities\ClaimsAwareClientEntityInterface;

final class FixtureClient implements ClaimsAwareClientEntityInterface
{
    /**
     * @param string|string[] $redirectUri
     * @param string[] $postLogoutRedirectUris
     */
    public function __construct(
        private readonly string $identifier,
        private readonly string|array $redirectUri,
        private readonly bool $confidential = true,
        private readonly array $postLogoutRedirectUris = []
    ) {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getName(): string
    {
        return $this->identifier;
    }

    public function getRedirectUri(): string|array
    {
        return $this->redirectUri;
    }

    public function isConfidential(): bool
    {
        return $this->confidential;
    }

    public function getPostLogoutRedirectUris(): array
    {
        return $this->postLogoutRedirectUris;
    }
}
