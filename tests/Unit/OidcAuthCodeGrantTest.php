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
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
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

        $redirectResponse = $completionResponse->generateHttpResponse(new \Laminas\Diactoros\Response());
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
