<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Context\OidcRequestContext;
use Charithar\OpenIDConnectServer\Grants\OidcAuthCodeGrant;
use Charithar\OpenIDConnectServer\RequestTypes\OidcAuthorizationRequest;
use Charithar\OpenIDConnectServer\ResponseModes\ModeAwareRedirectResponse;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureClient;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureUser;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryAccessTokenRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryAuthCodeRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryClientRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryRefreshTokenRepository;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemoryScopeRepository;
use DateInterval;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LogicException;
use PHPUnit\Framework\TestCase;

final class OidcAuthCodeGrantTest extends TestCase
{
    private const ENCRYPTION_KEY = 'a-test-encryption-key-that-is-long-enough';

    public function testRedirectUriMismatchRaisesInvalidRequestNotInvalidClient(): void
    {
        $grant = $this->makeGrant();
        $client = new FixtureClient('client-1', 'https://client.example.com/callback');
        $clients = new InMemoryClientRepository();
        $clients->add($client);
        $grant->setClientRepository($clients);
        $grant->setScopeRepository(new InMemoryScopeRepository());

        $request = new ServerRequest(queryParams: [
            'response_type' => 'code',
            'client_id'     => 'client-1',
            'redirect_uri'  => 'https://attacker.example.com/callback',
        ]);

        try {
            $grant->validateAuthorizationRequest($request);
            self::fail('Expected an OAuthServerException for the redirect_uri mismatch.');
        } catch (OAuthServerException $exception) {
            // This is the exact fix over league/oauth2-server 9.3's own
            // AbstractGrant::validateRedirectUri(), which throws
            // invalid_client here - RFC 6749 §5.2 reserves that for failed
            // *client* authentication, not a redirect_uri mismatch.
            self::assertSame('invalid_request', $exception->getErrorType());
        }
    }

    public function testNonceAndResponseModeSurviveTheFullAuthorizeToTokenRoundTrip(): void
    {
        $context = new OidcRequestContext();
        $grant = $this->makeGrant($context);
        $client = new FixtureClient('client-1', 'https://client.example.com/callback');
        $clients = new InMemoryClientRepository();
        $clients->add($client, 'test-secret');
        $grant->setClientRepository($clients);
        $grant->setScopeRepository(new InMemoryScopeRepository());

        $authorizeRequest = new ServerRequest(queryParams: [
            'response_type'  => 'code',
            'client_id'      => 'client-1',
            'redirect_uri'   => 'https://client.example.com/callback',
            'scope'          => 'openid',
            'nonce'          => 'nonce-value-123',
            'response_mode'  => 'fragment',
        ]);

        $authorizationRequest = $grant->validateAuthorizationRequest($authorizeRequest);
        self::assertInstanceOf(OidcAuthorizationRequest::class, $authorizationRequest);
        self::assertSame('nonce-value-123', $authorizationRequest->getNonce());

        $authorizationRequest->setUser(new FixtureUser('user-1'));
        $authorizationRequest->setAuthorizationApproved(true);
        $authorizationRequest->setAuthTime(1700000000);

        $completionResponse = $grant->completeAuthorizationRequest($authorizationRequest);
        self::assertInstanceOf(ModeAwareRedirectResponse::class, $completionResponse);

        $redirectResponse = $completionResponse->generateHttpResponse(new Response());
        $location = $redirectResponse->getHeaderLine('Location');

        // response_mode=fragment must produce a "#", not a "?".
        self::assertStringContainsString('#code=', $location);

        parse_str((string) parse_url($location, PHP_URL_FRAGMENT), $fragmentParams);
        $code = $fragmentParams['code'];

        $tokenRequest = new ServerRequest(parsedBody: [
            'grant_type'    => 'authorization_code',
            'client_id'     => 'client-1',
            'client_secret' => 'test-secret',
            'redirect_uri'  => 'https://client.example.com/callback',
            'code'          => $code,
        ]);

        $grant->respondToAccessTokenRequest($tokenRequest, new BearerTokenResponse(), new DateInterval('PT1H'));

        // The grant must have copied nonce + auth_time out of the redeemed
        // code's payload and into the shared context, ready for
        // IdTokenResponse::getExtraParams() to pick up in the same request.
        self::assertSame('nonce-value-123', $context->getNonce());
        self::assertSame(1700000000, $context->getAuthTime());
    }

    public function testCompleteAuthorizationRequestThrowsWithoutAUser(): void
    {
        $grant = $this->makeGrant();
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'test-secret');
        $grant->setClientRepository($clients);
        $grant->setScopeRepository(new InMemoryScopeRepository());

        $authorizationRequest = $grant->validateAuthorizationRequest(new ServerRequest(queryParams: [
            'response_type' => 'code',
            'client_id'     => 'client-1',
            'redirect_uri'  => 'https://client.example.com/callback',
        ]));
        $authorizationRequest->setAuthorizationApproved(true);
        // setUser() deliberately not called.

        $this->expectException(LogicException::class);

        $grant->completeAuthorizationRequest($authorizationRequest);
    }

    public function testCompleteAuthorizationRequestFallsBackToTheClientsRegisteredRedirectUri(): void
    {
        $grant = $this->makeGrant();
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'test-secret');
        $grant->setClientRepository($clients);
        $grant->setScopeRepository(new InMemoryScopeRepository());

        // No redirect_uri given - allowed since the client has exactly one registered.
        $authorizationRequest = $grant->validateAuthorizationRequest(new ServerRequest(queryParams: [
            'response_type' => 'code',
            'client_id'     => 'client-1',
        ]));
        $authorizationRequest->setUser(new FixtureUser('user-1'));
        $authorizationRequest->setAuthorizationApproved(true);

        $response = $grant->completeAuthorizationRequest($authorizationRequest);
        $location = $response->generateHttpResponse(new Response())->getHeaderLine('Location');

        self::assertStringStartsWith('https://client.example.com/callback', $location);
    }

    public function testCompleteAuthorizationRequestThrowsAccessDeniedWhenNotApproved(): void
    {
        $grant = $this->makeGrant();
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'test-secret');
        $grant->setClientRepository($clients);
        $grant->setScopeRepository(new InMemoryScopeRepository());

        $authorizationRequest = $grant->validateAuthorizationRequest(new ServerRequest(queryParams: [
            'response_type' => 'code',
            'client_id'     => 'client-1',
            'redirect_uri'  => 'https://client.example.com/callback',
        ]));
        $authorizationRequest->setUser(new FixtureUser('user-1'));
        // isAuthorizationApproved() defaults to false.

        try {
            $grant->completeAuthorizationRequest($authorizationRequest);
            self::fail('Expected an OAuthServerException for the denied authorization.');
        } catch (OAuthServerException $exception) {
            self::assertSame('access_denied', $exception->getErrorType());
            self::assertTrue($exception->hasRedirect());
        }
    }

    public function testCompleteAuthorizationRequestThrowsOnJsonEncodingFailure(): void
    {
        $grant = $this->makeGrant();
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'test-secret');
        $grant->setClientRepository($clients);
        $grant->setScopeRepository(new InMemoryScopeRepository());

        // An invalid-UTF-8 scope identifier makes json_encode() of the auth
        // code payload fail once it reaches the 'scopes' array.
        $authorizationRequest = $grant->validateAuthorizationRequest(new ServerRequest(queryParams: [
            'response_type' => 'code',
            'client_id'     => 'client-1',
            'redirect_uri'  => 'https://client.example.com/callback',
            'scope'         => "openid \xB1\x31",
        ]));
        $authorizationRequest->setUser(new FixtureUser('user-1'));
        $authorizationRequest->setAuthorizationApproved(true);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('JSON encoding');

        $grant->completeAuthorizationRequest($authorizationRequest);
    }

    public function testRespondToAccessTokenRequestSwallowsDecryptionFailureAndDelegatesToParent(): void
    {
        $context = new OidcRequestContext();
        $grant = $this->makeGrant($context);
        $clients = new InMemoryClientRepository();
        $clients->add(new FixtureClient('client-1', 'https://client.example.com/callback'), 'test-secret');
        $grant->setClientRepository($clients);
        $grant->setScopeRepository(new InMemoryScopeRepository());

        $tokenRequest = new ServerRequest(parsedBody: [
            'grant_type'    => 'authorization_code',
            'client_id'     => 'client-1',
            'client_secret' => 'test-secret',
            'redirect_uri'  => 'https://client.example.com/callback',
            'code'          => 'this-is-not-a-validly-encrypted-code',
        ]);

        try {
            $grant->respondToAccessTokenRequest($tokenRequest, new BearerTokenResponse(), new DateInterval('PT1H'));
            self::fail('Expected an OAuthServerException for the undecryptable code.');
        } catch (OAuthServerException) {
            // Expected: parent::respondToAccessTokenRequest() performs the
            // real validation and raises this once decryption fails there too.
        }

        self::assertNull($context->getNonce());
        self::assertNull($context->getAuthTime());
    }

    private function makeGrant(?OidcRequestContext $context = null): OidcAuthCodeGrant
    {
        $grant = new OidcAuthCodeGrant(
            $context ?? new OidcRequestContext(),
            new InMemoryAuthCodeRepository(),
            new InMemoryRefreshTokenRepository(),
            new DateInterval('PT10M')
        );

        $signingKey = new FixtureSigningKey('test');
        $grant->setPrivateKey(new CryptKey($signingKey->getPrivateKeyContents(), null, false));
        $grant->setEncryptionKey(self::ENCRYPTION_KEY);
        $grant->setAccessTokenRepository(new InMemoryAccessTokenRepository());
        $grant->setDefaultScope('');

        return $grant;
    }
}
