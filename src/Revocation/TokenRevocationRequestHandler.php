<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Revocation;

use Defuse\Crypto\Key;

use function is_string;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;

/**
 * RFC 7009 Token Revocation - not part of league/oauth2-server itself.
 * Access tokens are self-contained signed JWTs, so the client that owns one
 * (`aud`) and its identifier (`jti`) are read directly off the token, no
 * lookup needed. Refresh tokens are opaque payloads encrypted with the same
 * key league's own grants use for them (via CryptTrait, used here directly
 * rather than through a Grant), so they're decrypted the same way.
 *
 * Mount this behind ClientCredentialsMiddleware so client_secret_basic
 * credentials land in the parsed body the same way they do for the token
 * endpoint.
 */
final class TokenRevocationRequestHandler implements RequestHandlerInterface
{
    use CryptTrait;

    public function __construct(
        private readonly ClientRepositoryInterface $clientRepository,
        private readonly AccessTokenRepositoryInterface $accessTokenRepository,
        private readonly RefreshTokenRepositoryInterface $refreshTokenRepository,
        Key|string $encryptionKey,
        private readonly ResponseFactoryInterface $responseFactory
    ) {
        $this->setEncryptionKey($encryptionKey);
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = (array) $request->getParsedBody();
        $token = is_string($body['token'] ?? null) ? $body['token'] : null;
        $clientId = is_string($body['client_id'] ?? null) ? $body['client_id'] : null;
        $clientSecret = is_string($body['client_secret'] ?? null) ? $body['client_secret'] : null;

        if ($token === null || $token === '' || $clientId === null) {
            return $this->errorResponse(400, 'invalid_request');
        }

        $client = $this->clientRepository->getClientEntity($clientId);

        if ($client === null) {
            return $this->errorResponse(401, 'invalid_client');
        }

        if ($client->isConfidential() && $this->clientRepository->validateClient($clientId, $clientSecret, null) === false) {
            return $this->errorResponse(401, 'invalid_client');
        }

        $hint = is_string($body['token_type_hint'] ?? null) ? $body['token_type_hint'] : null;

        $revoked = false;

        if ($hint !== 'refresh_token') {
            $revoked = $this->revokeIfOwnedAccessToken($token, $clientId);
        }

        if (! $revoked) {
            $this->revokeIfOwnedRefreshToken($token, $clientId);
        }

        // RFC 7009 §2.2: respond 200 whether or not the token existed/was
        // valid, so an unauthorized caller learns nothing from the response.
        return $this->responseFactory->createResponse(200);
    }

    private function revokeIfOwnedAccessToken(string $token, string $clientId): bool
    {
        if ($token === '') {
            return false;
        }

        try {
            $parsed = (new Parser(new JoseEncoder()))->parse($token);
        } catch (Throwable) {
            return false;
        }

        if (! $parsed instanceof UnencryptedToken) {
            return false;
        }

        $audience = $parsed->claims()->get('aud', []);

        if (($audience[0] ?? null) !== $clientId) {
            return false;
        }

        $this->accessTokenRepository->revokeAccessToken($parsed->claims()->get('jti'));

        return true;
    }

    private function revokeIfOwnedRefreshToken(string $token, string $clientId): void
    {
        try {
            $payload = json_decode($this->decrypt($token), false, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return;
        }

        if (! isset($payload->client_id, $payload->refresh_token_id) || $payload->client_id !== $clientId) {
            return;
        }

        $this->refreshTokenRepository->revokeRefreshToken($payload->refresh_token_id);
    }

    private function errorResponse(int $status, string $error): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status)
            ->withHeader('Content-Type', 'application/json; charset=UTF-8');
        $response->getBody()->write((string) json_encode(['error' => $error]));

        return $response;
    }
}
