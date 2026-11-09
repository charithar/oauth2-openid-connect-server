<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Jwks\JwksFactory;
use Charithar\OpenIDConnectServer\Keys\SigningKeyInterface;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemorySigningKeyRepository;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class JwksFactoryTest extends TestCase
{
    public function testBuildsOneJwkPerActiveKeyWithMatchingKid(): void
    {
        $repository = new InMemorySigningKeyRepository(
            new FixtureSigningKey('current', 1),
            new FixtureSigningKey('previous', 2)
        );

        $jwks = (new JwksFactory($repository))->build();

        self::assertCount(2, $jwks['keys']);
        self::assertSame('current', $jwks['keys'][0]['kid']);
        self::assertSame('previous', $jwks['keys'][1]['kid']);

        foreach ($jwks['keys'] as $key) {
            self::assertSame('RSA', $key['kty']);
            self::assertSame('sig', $key['use']);
            self::assertSame('RS256', $key['alg']);
            self::assertNotSame('', $key['n']);
            self::assertNotSame('', $key['e']);
            // JWK base64url encoding must not contain standard base64 chars.
            self::assertStringNotContainsString('+', $key['n']);
            self::assertStringNotContainsString('/', $key['n']);
            self::assertStringNotContainsString('=', $key['n']);
        }
    }

    public function testThrowsWhenPublicKeyContentsAreNotAValidKey(): void
    {
        $key = new class () implements SigningKeyInterface {
            public function getIdentifier(): string
            {
                return 'kid-1';
            }

            public function getAlgorithm(): string
            {
                return 'RS256';
            }

            public function getPrivateKeyContents(): string
            {
                return 'unused';
            }

            public function getPublicKeyContents(): string
            {
                return 'this is not a PEM-encoded key';
            }

            public function getPassphrase(): ?string
            {
                return null;
            }
        };

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to parse public key');

        (new JwksFactory(new InMemorySigningKeyRepository($key)))->build();
    }

    /**
     * @return iterable<string, array{string, string, int}>
     */
    public static function ecAlgorithms(): iterable
    {
        yield 'ES256' => ['ES256', 'P-256', 32];
        yield 'ES384' => ['ES384', 'P-384', 48];
        yield 'ES512' => ['ES512', 'P-521', 66];
    }

    #[DataProvider('ecAlgorithms')]
    public function testPublishesEcKeyWithCurveAndFixedLengthCoordinates(string $algorithm, string $crv, int $length): void
    {
        $signingKey = new FixtureSigningKey('kid-ec', 1, $algorithm);

        $jwk = (new JwksFactory(new InMemorySigningKeyRepository($signingKey)))->build()['keys'][0];

        self::assertSame(['kty', 'use', 'alg', 'kid', 'crv', 'x', 'y'], array_keys($jwk));
        self::assertSame(['EC', 'sig', $algorithm, 'kid-ec', $crv], [$jwk['kty'], $jwk['use'], $jwk['alg'], $jwk['kid'], $jwk['crv']]);

        $x = self::base64UrlDecode($jwk['x']);
        $y = self::base64UrlDecode($jwk['y']);
        self::assertSame($length, strlen($x));
        self::assertSame($length, strlen($y));

        // Independent check: an SPKI EC public key ends with the uncompressed
        // point 0x04 || X || Y, each coordinate full length.
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s/', '', $signingKey->getPublicKeyContents()) ?? '', true);
        self::assertIsString($der);
        self::assertSame("\x04" . $x . $y, substr($der, -(2 * $length + 1)));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function mismatchedKeys(): iterable
    {
        yield 'RSA key advertised as ES256' => ['ES256', 'rsa1'];
        yield 'EC key advertised as RS256' => ['RS256', 'ec1'];
        yield 'P-256 key advertised as ES384' => ['ES384', 'ec1'];
    }

    #[DataProvider('mismatchedKeys')]
    public function testThrowsWhenKeyMaterialDoesNotMatchItsAlgorithm(string $algorithm, string $keyName): void
    {
        $key = new FixtureSigningKey('kid-1', 1, $algorithm, $keyName);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('does not match its advertised algorithm');

        (new JwksFactory(new InMemorySigningKeyRepository($key)))->build();
    }

    public function testThrowsForUnsupportedAlgorithm(): void
    {
        $key = new FixtureSigningKey('kid-1', 1, 'HS256');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unsupported signing algorithm "HS256"');

        (new JwksFactory(new InMemorySigningKeyRepository($key)))->build();
    }

    private static function base64UrlDecode(string $data): string
    {
        return (string) base64_decode(strtr($data, '-_', '+/'), true);
    }
}
