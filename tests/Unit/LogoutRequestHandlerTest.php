<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\ClaimExtractor;
use Charithar\OpenIDConnectServer\ClaimSets\StandardClaimSets;
use Charithar\OpenIDConnectServer\Context\OidcRequestContext;
use Charithar\OpenIDConnectServer\Logout\LogoutRequestHandler;
use Charithar\OpenIDConnectServer\ResponseTypes\IdTokenResponse;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureAccessToken;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureClient;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureScope;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureUser;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryClientRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemorySigningKeyRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryUserRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\SpyLogoutSessionHandler;
use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;

final class LogoutRequestHandlerTest extends TestCase
{
    private const ISSUER = 'https://issuer.example.com';

    private function issueIdToken(FixtureSigningKey $signingKey, string $clientId, ?DateInterval $ttl = null): string
    {
        $userRepository = new InMemoryUserRepository();
        $userRepository->add(new FixtureUser('user-1'));

        $idTokenResponse = new IdTokenResponse(
            $userRepository,
            new ClaimExtractor(StandardClaimSets::all()),
            new InMemorySigningKeyRepository($signingKey),
            new OidcRequestContext(),
            self::ISSUER
        );

        $accessToken = new FixtureAccessToken();
        $accessToken->setIdentifier('access-token-1');
        $accessToken->setClient(new FixtureClient($clientId, 'https://client.example.com/callback'));
        $accessToken->setUserIdentifier('user-1');
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add($ttl ?? new DateInterval('PT1H')));
        $accessToken->addScope(new FixtureScope('openid'));
        $accessToken->setPrivateKey(new \League\OAuth2\Server\CryptKey($signingKey->getPrivateKeyContents(), null, false));

        $idTokenResponse->setAccessToken($accessToken);

        $body = json_decode((string) $idTokenResponse->generateHttpResponse(new Response())->getBody(), true);

        return $body['id_token'];
    }

    public function testMissingIdTokenHintIsRejected(): void
    {
        $handler = new LogoutRequestHandler(
            new InMemoryClientRepository(),
            new InMemorySigningKeyRepository(new FixtureSigningKey('kid-1')),
            self::ISSUER,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest());

        self::assertSame(400, $response->getStatusCode());
    }

    public function testMalformedIdTokenHintIsRejected(): void
    {
        $handler = new LogoutRequestHandler(
            new InMemoryClientRepository(),
            new InMemorySigningKeyRepository(new FixtureSigningKey('kid-1')),
            self::ISSUER,
            new ResponseFactory()
        );

        $request = new ServerRequest(queryParams: ['id_token_hint' => 'not-a-jwt']);

        $response = $handler->handle($request);

        self::assertSame(403, $response->getStatusCode());
    }

    public function testUnknownKidIsRejected(): void
    {
        $signingKeyUsedToSign = new FixtureSigningKey('kid-signed-with', 1);
        $idToken = $this->issueIdToken($signingKeyUsedToSign, 'client-1');

        // The handler's own key repository doesn't know this kid at all.
        $handler = new LogoutRequestHandler(
            new InMemoryClientRepository(),
            new InMemorySigningKeyRepository(new FixtureSigningKey('some-other-kid', 2)),
            self::ISSUER,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest(queryParams: ['id_token_hint' => $idToken]));

        self::assertSame(403, $response->getStatusCode());
    }

    public function testWrongIssuerIsRejected(): void
    {
        $signingKey = new FixtureSigningKey('kid-1');

        $userRepository = new InMemoryUserRepository();
        $userRepository->add(new FixtureUser('user-1'));

        $idTokenResponse = new IdTokenResponse(
            $userRepository,
            new ClaimExtractor(StandardClaimSets::all()),
            new InMemorySigningKeyRepository($signingKey),
            new OidcRequestContext(),
            'https://a-different-issuer.example.com'
        );

        $accessToken = new FixtureAccessToken();
        $accessToken->setIdentifier('access-token-1');
        $accessToken->setClient(new FixtureClient('client-1', 'https://client.example.com/callback'));
        $accessToken->setUserIdentifier('user-1');
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $accessToken->addScope(new FixtureScope('openid'));
        $accessToken->setPrivateKey(new \League\OAuth2\Server\CryptKey($signingKey->getPrivateKeyContents(), null, false));
        $idTokenResponse->setAccessToken($accessToken);

        $idToken = json_decode((string) $idTokenResponse->generateHttpResponse(new Response())->getBody(), true)['id_token'];

        $handler = new LogoutRequestHandler(
            new InMemoryClientRepository(),
            new InMemorySigningKeyRepository($signingKey),
            self::ISSUER,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest(queryParams: ['id_token_hint' => $idToken]));

        self::assertSame(403, $response->getStatusCode());
    }

    public function testExpiredIdTokenIsRejected(): void
    {
        $signingKey = new FixtureSigningKey('kid-1');
        $idToken = $this->issueIdToken($signingKey, 'client-1', new DateInterval('PT0S'));

        // Ensure it's unambiguously in the past by the time it's validated.
        sleep(1);

        $handler = new LogoutRequestHandler(
            new InMemoryClientRepository(),
            new InMemorySigningKeyRepository($signingKey),
            self::ISSUER,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest(queryParams: ['id_token_hint' => $idToken]));

        self::assertSame(403, $response->getStatusCode());
    }

    public function testUnknownClientIsRejected(): void
    {
        $signingKey = new FixtureSigningKey('kid-1');
        $idToken = $this->issueIdToken($signingKey, 'client-not-registered');

        $handler = new LogoutRequestHandler(
            new InMemoryClientRepository(),
            new InMemorySigningKeyRepository($signingKey),
            self::ISSUER,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest(queryParams: ['id_token_hint' => $idToken]));

        self::assertSame(400, $response->getStatusCode());
    }

    public function testUnregisteredPostLogoutRedirectUriStillTerminatesSessionButRespondsOk(): void
    {
        $signingKey = new FixtureSigningKey('kid-1');
        $idToken = $this->issueIdToken($signingKey, 'client-1');

        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback', true, ['https://client.example.com/logged-out']));

        $sessionHandler = new SpyLogoutSessionHandler();

        $handler = new LogoutRequestHandler(
            $clients,
            new InMemorySigningKeyRepository($signingKey),
            self::ISSUER,
            new ResponseFactory(),
            $sessionHandler
        );

        $response = $handler->handle(new ServerRequest(queryParams: [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://attacker.example.com/',
        ]));

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($sessionHandler->wasTerminated());
    }

    public function testRegisteredPostLogoutRedirectUriRedirectsWithState(): void
    {
        $signingKey = new FixtureSigningKey('kid-1');
        $idToken = $this->issueIdToken($signingKey, 'client-1');

        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback', true, ['https://client.example.com/logged-out']));

        $sessionHandler = new SpyLogoutSessionHandler();

        $handler = new LogoutRequestHandler(
            $clients,
            new InMemorySigningKeyRepository($signingKey),
            self::ISSUER,
            new ResponseFactory(),
            $sessionHandler
        );

        $response = $handler->handle(new ServerRequest(queryParams: [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://client.example.com/logged-out',
            'state' => 'xyz',
        ]));

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('https://client.example.com/logged-out?state=xyz', $response->getHeaderLine('Location'));
        self::assertTrue($sessionHandler->wasTerminated());
    }
}
