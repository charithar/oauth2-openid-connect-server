<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Introspection\TokenIntrospectionRequestHandler;
use Charithar\OpenIDConnectServer\Tests\Fixtures\CryptTraitTestHelper;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureAccessToken;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureClient;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureScope;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryAccessTokenRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryClientRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryRefreshTokenRepository;
use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\TestCase;

final class TokenIntrospectionRequestHandlerTest extends TestCase
{
    private const ENCRYPTION_KEY = 'a-test-encryption-key-that-is-long-enough';

    private function issueAccessTokenJwt(string $clientId, string $jti = 'access-token-1'): string
    {
        $signingKey = new FixtureSigningKey('kid-1');
        $accessToken = new FixtureAccessToken();
        $accessToken->setIdentifier($jti);
        $accessToken->setClient(new FixtureClient($clientId, 'https://client.example.com/callback'));
        $accessToken->setUserIdentifier('user-1');
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $accessToken->addScope(new FixtureScope('openid'));
        $accessToken->setPrivateKey(new CryptKey($signingKey->getPrivateKeyContents(), null, false));

        return $accessToken->toString();
    }

    private function encryptRefreshTokenPayload(string $clientId, string $refreshTokenId, ?int $expireTime = null): string
    {
        $helper = new CryptTraitTestHelper(self::ENCRYPTION_KEY);

        return $helper->encryptPublic((string) json_encode([
            'client_id'        => $clientId,
            'refresh_token_id' => $refreshTokenId,
            'access_token_id'  => 'access-token-1',
            'scopes'           => ['openid'],
            'user_id'          => 'user-1',
            'expire_time'      => $expireTime ?? (new DateTimeImmutable())->add(new DateInterval('P1M'))->getTimestamp(),
        ]));
    }

    public function testMissingTokenIsRejected(): void
    {
        $handler = new TokenIntrospectionRequestHandler(
            new InMemoryClientRepository(),
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest(parsedBody: ['client_id' => 'client-1']));

        self::assertSame(400, $response->getStatusCode());
    }

    public function testUnknownClientIsRejected(): void
    {
        $handler = new TokenIntrospectionRequestHandler(
            new InMemoryClientRepository(),
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest(parsedBody: ['token' => 'whatever', 'client_id' => 'no-such-client']));

        self::assertSame(401, $response->getStatusCode());
    }

    public function testConfidentialClientWithWrongSecretIsRejected(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'correct-secret');

        $handler = new TokenIntrospectionRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => 'whatever',
            'client_id' => 'client-1',
            'client_secret' => 'wrong-secret',
        ]));

        self::assertSame(401, $response->getStatusCode());
    }

    public function testActiveAccessTokenIntrospection(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');

        $handler = new TokenIntrospectionRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $jwt = $this->issueAccessTokenJwt('client-1', 'access-token-1');

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => $jwt,
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));
        $body = json_decode((string) $response->getBody(), true);

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($body['active']);
        self::assertSame('Bearer', $body['token_type']);
        self::assertSame('client-1', $body['client_id']);
        self::assertSame('user-1', $body['sub']);
        self::assertSame('openid', $body['scope']);
        self::assertSame('access-token-1', $body['jti']);
    }

    public function testRevokedAccessTokenIsInactive(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');
        $accessTokenRepository = new InMemoryAccessTokenRepository();
        $accessTokenRepository->revokeAccessToken('access-token-1');

        $handler = new TokenIntrospectionRequestHandler(
            $clients,
            $accessTokenRepository,
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $jwt = $this->issueAccessTokenJwt('client-1', 'access-token-1');

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => $jwt,
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));
        $body = json_decode((string) $response->getBody(), true);

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($body['active']);
    }

    public function testAccessTokenOwnedByDifferentClientIsReportedInactive(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');

        $handler = new TokenIntrospectionRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $jwt = $this->issueAccessTokenJwt('client-2', 'access-token-1');

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => $jwt,
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));
        $body = json_decode((string) $response->getBody(), true);

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($body['active']);
    }

    public function testActiveRefreshTokenIntrospection(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');

        $handler = new TokenIntrospectionRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $encrypted = $this->encryptRefreshTokenPayload('client-1', 'refresh-1');

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => $encrypted,
            'token_type_hint' => 'refresh_token',
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));
        $body = json_decode((string) $response->getBody(), true);

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($body['active']);
        self::assertSame('refresh_token', $body['token_type']);
        self::assertSame('client-1', $body['client_id']);
        self::assertSame('user-1', $body['sub']);
    }

    public function testRevokedRefreshTokenIsInactive(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');
        $refreshTokenRepository = new InMemoryRefreshTokenRepository();
        $refreshTokenRepository->revokeRefreshToken('refresh-1');

        $handler = new TokenIntrospectionRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            $refreshTokenRepository,
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $encrypted = $this->encryptRefreshTokenPayload('client-1', 'refresh-1');

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => $encrypted,
            'token_type_hint' => 'refresh_token',
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));
        $body = json_decode((string) $response->getBody(), true);

        self::assertFalse($body['active']);
    }

    public function testExpiredRefreshTokenIsInactive(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');

        $handler = new TokenIntrospectionRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $encrypted = $this->encryptRefreshTokenPayload('client-1', 'refresh-1', (new DateTimeImmutable('-1 hour'))->getTimestamp());

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => $encrypted,
            'token_type_hint' => 'refresh_token',
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));
        $body = json_decode((string) $response->getBody(), true);

        self::assertFalse($body['active']);
    }

    public function testNoHintFallsBackFromAccessTokenToRefreshToken(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');

        $handler = new TokenIntrospectionRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        // No token_type_hint given, and this isn't a JWT - introspectAccessToken()
        // fails to parse it and returns null, so the refresh-token path is tried next.
        $encrypted = $this->encryptRefreshTokenPayload('client-1', 'refresh-1');

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => $encrypted,
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));
        $body = json_decode((string) $response->getBody(), true);

        self::assertTrue($body['active']);
        self::assertSame('refresh_token', $body['token_type']);
    }
}
