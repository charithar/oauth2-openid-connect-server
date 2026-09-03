<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Jwks\JwksFactory;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemorySigningKeyRepository;
use PHPUnit\Framework\TestCase;

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
}
