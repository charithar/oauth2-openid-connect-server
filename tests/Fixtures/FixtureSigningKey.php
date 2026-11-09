<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use Charithar\OpenIDConnectServer\Keys\SigningKeyInterface;

/**
 * Loads one of the static, pre-generated test key pairs (2048-bit RSA
 * rsa1/rsa2, EC P-256 ec1, P-384 ec384, P-521 ec521) rather than generating
 * one at runtime with openssl_pkey_new(): that call depends on a working
 * openssl.cnf being discoverable, which is not a given on every machine
 * (notably some Windows PHP installs), and would make these tests flaky for
 * reasons unrelated to the library itself.
 *
 * The key pair defaults to the one matching $algorithm; $keyName overrides
 * it to build a key whose material deliberately doesn't match its algorithm.
 */
final class FixtureSigningKey implements SigningKeyInterface
{
    public function __construct(
        private readonly string $identifier,
        private readonly int $slot = 1,
        private readonly string $algorithm = 'RS256',
        private readonly ?string $keyName = null
    ) {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function getPrivateKeyContents(): string
    {
        return (string) file_get_contents(__DIR__ . "/keys/{$this->keyName()}.key");
    }

    public function getPublicKeyContents(): string
    {
        return (string) file_get_contents(__DIR__ . "/keys/{$this->keyName()}.pub.key");
    }

    public function getPassphrase(): ?string
    {
        return null;
    }

    private function keyName(): string
    {
        return $this->keyName ?? match ($this->algorithm) {
            'ES256' => 'ec1',
            'ES384' => 'ec384',
            'ES512' => 'ec521',
            default => "rsa{$this->slot}",
        };
    }
}
