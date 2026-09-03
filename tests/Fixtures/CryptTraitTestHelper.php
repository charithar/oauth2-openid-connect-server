<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use League\OAuth2\Server\CryptTrait;

/**
 * CryptTrait::encrypt()/decrypt() are protected - this exposes them so
 * tests can build the same encrypted refresh-token payloads the handlers
 * under test are expected to decrypt, using the exact mechanism
 * (Defuse\Crypto\Crypto, via a shared string key) league's own grants use.
 */
final class CryptTraitTestHelper
{
    use CryptTrait;

    public function __construct(string $encryptionKey)
    {
        $this->setEncryptionKey($encryptionKey);
    }

    public function encryptPublic(string $data): string
    {
        return $this->encrypt($data);
    }
}
