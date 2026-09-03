<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Introspection;

use Defuse\Crypto\Key;

use function implode;
use function is_string;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;

use function time;

/**
 * RFC 7662 Token Introspection - not part of league/oauth2-server itself.
 * See TokenRevocationRequestHandler for why no extra repository interfaces
 * beyond league's own are needed: access tokens are self-contained JWTs,
 * refresh tokens decrypt with the same key league's grants already use.
 */
final class TokenIntrospectionRequestHandler implements RequestHandlerInterface
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
            return $this->jsonResponse(400, ['error' => 'invalid_request']);
        }

        $client = $this->clientRepository->getClientEntity($clientId);

        // $grantType is null: this isn't tied to any grant. Implementations
        // that switch on the third argument must treat null as "just check
        // the secret," not as an unrecognized/rejected grant.
        if ($client === null || ($client->isConfidential() && $this->clientRepository->validateClient($clientId, $clientSecret, null) === false)) {
            return $this->jsonResponse(401, ['error' => 'invalid_client']);
        }

        $hint = is_string($body['token_type_hint'] ?? null) ? $body['token_type_hint'] : null;

        $introspection = $hint === 'refresh_token'
            ? ($this->introspectRefreshToken($token, $clientId) ?? $this->introspectAccessToken($token, $clientId))
            : ($this->introspectAccessToken($token, $clientId) ?? $this->introspectRefreshToken($token, $clientId));

        return $this->jsonResponse(200, $introspection ?? ['active' => false]);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function introspectAccessToken(string $token, string $requestingClientId): ?array
    {
        // Defensive and structurally unreachable via the one caller in
        // handle(), which already rejects an empty token before this is
        // called. Kept for robustness if this method is ever called from
        // elsewhere.
        // @codeCoverageIgnoreStart
        if ($token === '') {
            return null;
        }
        // @codeCoverageIgnoreEnd

        try {
            $parsed = (new Parser(new JoseEncoder()))->parse($token);
        } catch (Throwable) {
            return null;
        }

        // Defensive and structurally unreachable: Lcobucci\JWT\Token\Parser
        // never returns anything but an UnencryptedToken - a JWE is
        // rejected earlier, inside parse() itself.
        // @codeCoverageIgnoreStart
        if (! $parsed instanceof UnencryptedToken) {
            return null;
        }
        // @codeCoverageIgnoreEnd

        $audience = $parsed->claims()->get('aud', []);
        $tokenClientId = $audience[0] ?? null;

        if ($tokenClientId !== $requestingClientId) {
            return null;
        }

        $jti = $parsed->claims()->get('jti');

        if ($this->accessTokenRepository->isAccessTokenRevoked($jti)) {
            return ['active' => false];
        }

        $validator = new Validator();

        if (! $validator->validate($parsed, new LooseValidAt(SystemClock::fromUTC()))) {
            return ['active' => false];
        }

        return [
            'active'     => true,
            'token_type' => 'Bearer',
            'client_id'  => $tokenClientId,
            'sub'        => $parsed->claims()->get('sub'),
            'scope'      => implode(' ', (array) $parsed->claims()->get('scopes', [])),
            'exp'        => $parsed->claims()->get('exp')?->getTimestamp(),
            'iat'        => $parsed->claims()->get('iat')?->getTimestamp(),
            'jti'        => $jti,
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function introspectRefreshToken(string $token, string $requestingClientId): ?array
    {
        try {
            $payload = json_decode($this->decrypt($token), false, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        if (! isset($payload->client_id, $payload->refresh_token_id) || $payload->client_id !== $requestingClientId) {
            return null;
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($payload->refresh_token_id)) {
            return ['active' => false];
        }

        if (isset($payload->expire_time) && $payload->expire_time < time()) {
            return ['active' => false];
        }

        return [
            'active'     => true,
            'token_type' => 'refresh_token',
            'client_id'  => $payload->client_id,
            'sub'        => $payload->user_id ?? null,
            'scope'      => implode(' ', (array) ($payload->scopes ?? [])),
            'exp'        => $payload->expire_time ?? null,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function jsonResponse(int $status, array $data): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status)
            ->withHeader('Content-Type', 'application/json; charset=UTF-8');
        $response->getBody()->write((string) json_encode($data));

        return $response;
    }
}
