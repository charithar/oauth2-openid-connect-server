<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\ClaimExtractor;
use Charithar\OpenIDConnectServer\ClaimSets\StandardClaimSets;
use Charithar\OpenIDConnectServer\Context\OidcRequestContext;
use Charithar\OpenIDConnectServer\Keys\SigningKeyInterface;
use Charithar\OpenIDConnectServer\ResponseTypes\IdTokenResponse;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureAccessToken;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureClient;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureScope;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureUser;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemorySigningKeyRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryUserRepository;
use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\Response;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class IdTokenResponseTest extends TestCase
{
    public function testIdTokenCarriesClaimsNonceAuthTimeAndKidWithoutThrowing(): void
    {
        $userRepository = new InMemoryUserRepository();
        $user = new FixtureUser('user-1', ['name' => 'Ada Lovelace', 'sub' => 'should-never-surface']);
        $userRepository->add($user);

        $signingKey = new FixtureSigningKey('kid-1');
        $context = new OidcRequestContext();
        $context->setNonce('nonce-abc');
        $context->setAuthTime(1700000000);

        $idTokenResponse = new IdTokenResponse(
            $userRepository,
            new ClaimExtractor(StandardClaimSets::all()),
            new InMemorySigningKeyRepository($signingKey),
            $context,
            'https://issuer.example.com'
        );

        $accessToken = new FixtureAccessToken();
        $accessToken->setIdentifier('access-token-1');
        $accessToken->setClient(new FixtureClient('client-1', 'https://client.example.com/callback'));
        $accessToken->setUserIdentifier('user-1');
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $accessToken->addScope(new FixtureScope('openid'));
        $accessToken->addScope(new FixtureScope('profile'));
        $accessToken->setPrivateKey(new CryptKey($signingKey->getPrivateKeyContents(), null, false));

        $idTokenResponse->setAccessToken($accessToken);

        // getExtraParams() is `protected` (the extension point
        // BearerTokenResponse itself documents); exercising it through
        // generateHttpResponse(), same as AuthorizationServer would, avoids
        // reaching into internals via reflection.
        $httpResponse = $idTokenResponse->generateHttpResponse(new Response());
        $body = json_decode((string) $httpResponse->getBody(), true);

        self::assertArrayHasKey('id_token', $body);

        $token = (new Parser(new JoseEncoder()))->parse($body['id_token']);

        self::assertSame('kid-1', $token->headers()->get('kid'));
        self::assertSame('https://issuer.example.com', $token->claims()->get('iss'));
        self::assertSame('user-1', $token->claims()->get('sub'));
        self::assertSame('Ada Lovelace', $token->claims()->get('name'));
        self::assertSame('nonce-abc', $token->claims()->get('nonce'));
        self::assertSame(1700000000, $token->claims()->get('auth_time'));
    }

    public function testReturnsNoIdTokenWhenOpenidScopeWasNotGranted(): void
    {
        $userRepository = new InMemoryUserRepository();
        $userRepository->add(new FixtureUser('user-1'));

        $signingKey = new FixtureSigningKey('kid-1');

        $idTokenResponse = new IdTokenResponse(
            $userRepository,
            new ClaimExtractor(StandardClaimSets::all()),
            new InMemorySigningKeyRepository($signingKey),
            new OidcRequestContext(),
            'https://issuer.example.com'
        );

        $accessToken = new FixtureAccessToken();
        $accessToken->setIdentifier('access-token-1');
        $accessToken->setClient(new FixtureClient('client-1', 'https://client.example.com/callback'));
        $accessToken->setUserIdentifier('user-1');
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $accessToken->addScope(new FixtureScope('profile'));
        $accessToken->setPrivateKey(new CryptKey($signingKey->getPrivateKeyContents(), null, false));

        $idTokenResponse->setAccessToken($accessToken);

        $httpResponse = $idTokenResponse->generateHttpResponse(new Response());
        $body = json_decode((string) $httpResponse->getBody(), true);

        self::assertArrayNotHasKey('id_token', $body);
    }

    public function testThrowsWhenSigningKeyAdvertisesANonRs256Algorithm(): void
    {
        $userRepository = new InMemoryUserRepository();
        $userRepository->add(new FixtureUser('user-1'));

        $nonRs256Key = new class () implements SigningKeyInterface {
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
                return 'unused';
            }

            public function getPassphrase(): ?string
            {
                return null;
            }
        };

        $idTokenResponse = new IdTokenResponse(
            $userRepository,
            new ClaimExtractor(StandardClaimSets::all()),
            new InMemorySigningKeyRepository($nonRs256Key),
            new OidcRequestContext(),
            'https://issuer.example.com'
        );

        $accessToken = new FixtureAccessToken();
        $accessToken->setIdentifier('access-token-1');
        $accessToken->setClient(new FixtureClient('client-1', 'https://client.example.com/callback'));
        $accessToken->setUserIdentifier('user-1');
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $accessToken->addScope(new FixtureScope('openid'));
        $accessToken->setPrivateKey(new CryptKey((new FixtureSigningKey('access-token-key'))->getPrivateKeyContents(), null, false));

        $idTokenResponse->setAccessToken($accessToken);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('only supports RS256');

        $idTokenResponse->generateHttpResponse(new Response());
    }
}
