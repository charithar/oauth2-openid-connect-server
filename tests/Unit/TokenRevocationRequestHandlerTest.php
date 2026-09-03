<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Revocation\TokenRevocationRequestHandler;
use Charithar\OpenIDConnectServer\Tests\Fixtures\CryptTraitTestHelper;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureAccessToken;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureClient;
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

final class TokenRevocationRequestHandlerTest extends TestCase
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
        $accessToken->setPrivateKey(new CryptKey($signingKey->getPrivateKeyContents(), null, false));

        return $accessToken->toString();
    }

    private function encryptRefreshTokenPayload(string $clientId, string $refreshTokenId): string
    {
        $helper = new CryptTraitTestHelper(self::ENCRYPTION_KEY);

        return $helper->encryptPublic((string) json_encode([
            'client_id'        => $clientId,
            'refresh_token_id' => $refreshTokenId,
            'access_token_id'  => 'access-token-1',
            'scopes'           => ['openid'],
            'user_id'          => 'user-1',
            'expire_time'      => (new DateTimeImmutable())->add(new DateInterval('P1M'))->getTimestamp(),
        ]));
    }

    public function testMissingTokenIsRejected(): void
    {
        $handler = new TokenRevocationRequestHandler(
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
        $handler = new TokenRevocationRequestHandler(
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

        $handler = new TokenRevocationRequestHandler(
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

    public function testRevokesAnAccessTokenOwnedByTheRequestingClient(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');
        $accessTokenRepository = new InMemoryAccessTokenRepository();

        $handler = new TokenRevocationRequestHandler(
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

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($accessTokenRepository->isAccessTokenRevoked('access-token-1'));
    }

    public function testDoesNotRevokeAnAccessTokenOwnedByADifferentClient(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');
        $accessTokenRepository = new InMemoryAccessTokenRepository();

        $handler = new TokenRevocationRequestHandler(
            $clients,
            $accessTokenRepository,
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

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($accessTokenRepository->isAccessTokenRevoked('access-token-1'));
    }

    public function testRevokesARefreshTokenOwnedByTheRequestingClient(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');
        $refreshTokenRepository = new InMemoryRefreshTokenRepository();

        $handler = new TokenRevocationRequestHandler(
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

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($refreshTokenRepository->isRefreshTokenRevoked('refresh-1'));
    }

    public function testDoesNotRevokeARefreshTokenOwnedByADifferentClient(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');
        $refreshTokenRepository = new InMemoryRefreshTokenRepository();

        $handler = new TokenRevocationRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            $refreshTokenRepository,
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $encrypted = $this->encryptRefreshTokenPayload('client-2', 'refresh-1');

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => $encrypted,
            'token_type_hint' => 'refresh_token',
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($refreshTokenRepository->isRefreshTokenRevoked('refresh-1'));
    }

    public function testPublicClientDoesNotNeedASecret(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback', false));
        $accessTokenRepository = new InMemoryAccessTokenRepository();

        $handler = new TokenRevocationRequestHandler(
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
        ]));

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($accessTokenRepository->isAccessTokenRevoked('access-token-1'));
    }

    public function testMalformedTokenStillRespondsOkWithoutRevokingAnything(): void
    {
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'secret');

        $handler = new TokenRevocationRequestHandler(
            $clients,
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            self::ENCRYPTION_KEY,
            new ResponseFactory()
        );

        $response = $handler->handle(new ServerRequest(parsedBody: [
            'token' => 'this-is-not-a-valid-token',
            'client_id' => 'client-1',
            'client_secret' => 'secret',
        ]));

        self::assertSame(200, $response->getStatusCode());
    }
}
