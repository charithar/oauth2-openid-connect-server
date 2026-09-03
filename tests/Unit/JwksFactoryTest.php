<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Jwks\JwksFactory;
use Charithar\OpenIDConnectServer\Keys\SigningKeyInterface;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemorySigningKeyRepository;
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

    public function testThrowsForANonRsaSigningKey(): void
    {
        $ecPublicKeyContents = (string) file_get_contents(__DIR__ . '/../Fixtures/keys/ec1.pub.key');

        $key = new class ($ecPublicKeyContents) implements SigningKeyInterface {
            public function __construct(private readonly string $publicKeyContents)
            {
            }

            public function getIdentifier(): string
            {
                return 'kid-1';
            }

            public function getAlgorithm(): string
            {
                return 'ES256';
            }

            public function getPrivateKeyContents(): string
            {
                return 'unused';
            }

            public function getPublicKeyContents(): string
            {
                return $this->publicKeyContents;
            }

            public function getPassphrase(): ?string
            {
                return null;
            }
        };

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Only RSA signing keys are supported');

        (new JwksFactory(new InMemorySigningKeyRepository($key)))->build();
    }
}
