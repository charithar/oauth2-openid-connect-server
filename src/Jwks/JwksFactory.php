<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Jwks;

use function base64_encode;

use Charithar\OpenIDConnectServer\Keys\SigningAlgorithm;
use Charithar\OpenIDConnectServer\Keys\SigningKeyInterface;
use Charithar\OpenIDConnectServer\Keys\SigningKeyRepositoryInterface;

use function is_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function rtrim;

use RuntimeException;

use function sprintf;
use function str_pad;

use const STR_PAD_LEFT;

use function str_replace;
use function strlen;

/**
 * Builds an RFC 7517 JWK Set from every active signing key, so id_tokens
 * signed under an older `kid` still verify while it's rotated out. RSA keys
 * are published as `kty: RSA`, EC keys as `kty: EC` (RFC 7518 §6.2); the
 * key's actual type and curve must match the algorithm it advertises, so
 * the published `alg` can never diverge from what IdTokenResponse signs.
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
            $algorithm = SigningAlgorithm::fromKey($key);
            $resource = openssl_pkey_get_public($key->getPublicKeyContents());

            if ($resource === false) {
                throw new RuntimeException(sprintf('Unable to parse public key for kid "%s"', $key->getIdentifier()));
            }

            $details = openssl_pkey_get_details($resource);

            if ($details === false) {
                // @codeCoverageIgnoreStart
                throw new RuntimeException(sprintf('Unable to read public key details for kid "%s"', $key->getIdentifier()));
                // @codeCoverageIgnoreEnd
            }

            $keys[] = [
                'kty' => $algorithm->isEcdsa() ? 'EC' : 'RSA',
                'use' => 'sig',
                'alg' => $algorithm->value,
                'kid' => $key->getIdentifier(),
            ] + ($algorithm->isEcdsa()
                ? self::ecParameters($key, $algorithm, $details)
                : self::rsaParameters($key, $algorithm, $details));
        }

        return ['keys' => $keys];
    }

    /**
     * @param array<array-key, mixed> $details
     *
     * @return array{n: string, e: string}
     */
    private static function rsaParameters(SigningKeyInterface $key, SigningAlgorithm $algorithm, array $details): array
    {
        $n = $details['rsa']['n'] ?? null;
        $e = $details['rsa']['e'] ?? null;

        if (! is_string($n) || ! is_string($e)) {
            throw self::keyTypeMismatch($key, $algorithm);
        }

        return [
            'n' => self::base64UrlEncode($n),
            'e' => self::base64UrlEncode($e),
        ];
    }

    /**
     * @param array<array-key, mixed> $details
     *
     * @return array{crv: string, x: string, y: string}
     */
    private static function ecParameters(SigningKeyInterface $key, SigningAlgorithm $algorithm, array $details): array
    {
        $curveName = $details['ec']['curve_name'] ?? null;
        $x = $details['ec']['x'] ?? null;
        $y = $details['ec']['y'] ?? null;

        if ($curveName !== $algorithm->opensslCurveName() || ! is_string($x) || ! is_string($y)) {
            throw self::keyTypeMismatch($key, $algorithm);
        }

        $length = $algorithm->ecCoordinateLength();

        return [
            'crv' => (string) $algorithm->ecCurve(),
            'x'   => self::base64UrlEncode(self::padCoordinate($x, $length)),
            'y'   => self::base64UrlEncode(self::padCoordinate($y, $length)),
        ];
    }

    /**
     * OpenSSL returns coordinates as big-endian integers with leading zero
     * bytes stripped; a JWK needs the full fixed-length octet string.
     */
    private static function padCoordinate(string $coordinate, int $length): string
    {
        return strlen($coordinate) >= $length ? $coordinate : str_pad($coordinate, $length, "\0", STR_PAD_LEFT);
    }

    private static function keyTypeMismatch(SigningKeyInterface $key, SigningAlgorithm $algorithm): RuntimeException
    {
        return new RuntimeException(sprintf(
            'Public key for kid "%s" does not match its advertised algorithm "%s"',
            $key->getIdentifier(),
            $algorithm->value
        ));
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($data)), '=');
    }
}
