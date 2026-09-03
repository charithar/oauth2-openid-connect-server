<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\ClaimExtractor;
use Charithar\OpenIDConnectServer\ClaimSets\StandardClaimSets;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureAccessToken;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureClient;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureScope;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureUser;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryAccessTokenRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryUserRepository;
use Charithar\OpenIDConnectServer\UserInfo\UserInfoRequestHandler;
use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;
use PHPUnit\Framework\TestCase;

final class UserInfoRequestHandlerTest extends TestCase
{
    private function issueBearerToken(FixtureSigningKey $signingKey, InMemoryAccessTokenRepository $accessTokenRepository, string $userId, array $scopeIdentifiers): string
    {
        $accessToken = new FixtureAccessToken();
        $accessToken->setIdentifier('access-token-1');
        $accessToken->setClient(new FixtureClient('client-1', 'https://client.example.com/callback'));
        $accessToken->setUserIdentifier($userId);
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        foreach ($scopeIdentifiers as $scopeIdentifier) {
            $accessToken->addScope(new FixtureScope($scopeIdentifier));
        }

        $accessToken->setPrivateKey(new CryptKey($signingKey->getPrivateKeyContents(), null, false));

        return $accessToken->toString();
    }

    public function testReturnsSubjectAndScopeFilteredClaimsForAValidBearerToken(): void
    {
        $signingKey = new FixtureSigningKey('kid-1');
        $accessTokenRepository = new InMemoryAccessTokenRepository();

        $userRepository = new InMemoryUserRepository();
        $userRepository->add(new FixtureUser('user-1', ['name' => 'Ada Lovelace', 'email' => 'ada@example.com']));

        $jwt = $this->issueBearerToken($signingKey, $accessTokenRepository, 'user-1', ['openid', 'profile']);

        $resourceServer = new ResourceServer($accessTokenRepository, new CryptKey($signingKey->getPublicKeyContents(), null, false));

        $handler = new UserInfoRequestHandler(
            $resourceServer,
            $userRepository,
            new ClaimExtractor(StandardClaimSets::all()),
            new ResponseFactory()
        );

        $request = (new ServerRequest())->withHeader('Authorization', 'Bearer ' . $jwt);

        $response = $handler->handle($request);
        $body = json_decode((string) $response->getBody(), true);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('no-store, no-cache, must-revalidate', $response->getHeaderLine('Cache-Control'));
        self::assertSame('user-1', $body['sub']);
        self::assertSame('Ada Lovelace', $body['name']);
        self::assertArrayNotHasKey('email', $body, 'email scope was not granted');
    }

    public function testMissingAuthorizationHeaderIsRejected(): void
    {
        $signingKey = new FixtureSigningKey('kid-1');
        $accessTokenRepository = new InMemoryAccessTokenRepository();
        $resourceServer = new ResourceServer($accessTokenRepository, new CryptKey($signingKey->getPublicKeyContents(), null, false));

        $handler = new UserInfoRequestHandler(
            $resourceServer,
            new InMemoryUserRepository(),
            new ClaimExtractor(StandardClaimSets::all()),
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest());

        self::assertSame(401, $response->getStatusCode());
    }

    public function testValidTokenForAnUnknownUserIsRejectedAsInvalidToken(): void
    {
        $signingKey = new FixtureSigningKey('kid-1');
        $accessTokenRepository = new InMemoryAccessTokenRepository();

        // No user added to the repository for 'user-1'.
        $jwt = $this->issueBearerToken($signingKey, $accessTokenRepository, 'user-1', ['openid']);

        $resourceServer = new ResourceServer($accessTokenRepository, new CryptKey($signingKey->getPublicKeyContents(), null, false));

        $handler = new UserInfoRequestHandler(
            $resourceServer,
            new InMemoryUserRepository(),
            new ClaimExtractor(StandardClaimSets::all()),
            new ResponseFactory()
        );

        $request = (new ServerRequest())->withHeader('Authorization', 'Bearer ' . $jwt);

        $response = $handler->handle($request);
        $body = json_decode((string) $response->getBody(), true);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer error="invalid_token"', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame('invalid_token', $body['error']);
    }
}
