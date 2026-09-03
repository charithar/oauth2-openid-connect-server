<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

final class InMemoryClientRepository implements ClientRepositoryInterface
{
    /** @var array<string, ClientEntityInterface> */
    private array $clients = [];

    /** @var array<string, string> */
    private array $secrets = [];

    public function add(ClientEntityInterface $client, ?string $secret = null): void
    {
        $this->clients[$client->getIdentifier()] = $client;

        if ($secret !== null) {
            $this->secrets[$client->getIdentifier()] = $secret;
        }
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        return $this->clients[$clientIdentifier] ?? null;
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        return ($this->secrets[$clientIdentifier] ?? null) === $clientSecret;
    }
}
