<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Jwks;

use function base64_encode;

use Charithar\OpenIDConnectServer\Keys\SigningKeyRepositoryInterface;

use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function rtrim;

use RuntimeException;

use function sprintf;
use function str_replace;

/**
 * Builds an RFC 7517 JWK Set from every active signing key, so id_tokens
 * signed under an older `kid` still verify while it's rotated out.
 */
final class JwksFactory
{
    public function __construct(private readonly SigningKeyRepositoryInterface $signingKeyRepository)
    {
    }

    /**
     * @return array{keys: array<int, array<string, string>>}
     */
    public function build(): array
    {
        $keys = [];

        foreach ($this->signingKeyRepository->getActiveKeys() as $key) {
            $resource = openssl_pkey_get_public($key->getPublicKeyContents());

            if ($resource === false) {
                throw new RuntimeException(sprintf('Unable to parse public key for kid "%s"', $key->getIdentifier()));
            }

            $details = openssl_pkey_get_details($resource);

            if ($details === false || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
                throw new RuntimeException(sprintf('Only RSA signing keys are supported for JWKS (kid "%s")', $key->getIdentifier()));
            }

            $keys[] = [
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => $key->getAlgorithm(),
                'kid' => $key->getIdentifier(),
                'n'   => self::base64UrlEncode($details['rsa']['n']),
                'e'   => self::base64UrlEncode($details['rsa']['e']),
            ];
        }

        return ['keys' => $keys];
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($data)), '=');
    }
}
