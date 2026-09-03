<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use Charithar\OpenIDConnectServer\Keys\SigningKeyInterface;

/**
 * Loads one of two static, pre-generated 2048-bit RSA test key pairs rather
 * than generating one at runtime with openssl_pkey_new(): that call depends
 * on a working openssl.cnf being discoverable, which is not a given on
 * every machine (notably some Windows PHP installs), and would make these
 * tests flaky for reasons unrelated to the library itself.
 */
final class FixtureSigningKey implements SigningKeyInterface
{
    public function __construct(
        private readonly string $identifier,
        private readonly int $slot = 1
    ) {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getAlgorithm(): string
    {
        return 'RS256';
    }

    public function getPrivateKeyContents(): string
    {
        return (string) file_get_contents(__DIR__ . "/keys/rsa{$this->slot}.key");
    }

    public function getPublicKeyContents(): string
    {
        return (string) file_get_contents(__DIR__ . "/keys/rsa{$this->slot}.pub.key");
    }

    public function getPassphrase(): ?string
    {
        return null;
    }
}
