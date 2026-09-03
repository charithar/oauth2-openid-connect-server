<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\UserInfo;

use Charithar\OpenIDConnectServer\ClaimExtractor;
use Charithar\OpenIDConnectServer\Entities\ClaimsAwareUserEntityInterface;
use Charithar\OpenIDConnectServer\Repositories\UserRepositoryInterface;

use function is_array;
use function json_encode;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The spec-correct OIDC UserInfo endpoint: a Bearer access token in,
 * scope-filtered claims out (validated via league's own ResourceServer,
 * exactly like any other protected resource). An app that authenticates its
 * own SPA/browser UserInfo calls via session cookie instead of a Bearer
 * token needs its own handler for that - this one implements the standard.
 */
final class UserInfoRequestHandler implements RequestHandlerInterface
{
    public function __construct(
        private readonly ResourceServer $resourceServer,
        private readonly UserRepositoryInterface $userRepository,
        private readonly ClaimExtractor $claimExtractor,
        private readonly ResponseFactoryInterface $responseFactory
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $validated = $this->resourceServer->validateAuthenticatedRequest($request);
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse($this->responseFactory->createResponse());
        }

        $scopes = $validated->getAttribute('oauth_scopes', []);
        $scopeIdentifiers = is_array($scopes) ? $scopes : [];

        $userId = $validated->getAttribute('oauth_user_id');
        $userEntity = $userId !== null ? $this->userRepository->getUserEntityByIdentifier((string) $userId) : null;

        if (! $userEntity instanceof ClaimsAwareUserEntityInterface) {
            $response = $this->responseFactory->createResponse(401)
                ->withHeader('WWW-Authenticate', 'Bearer error="invalid_token"')
                ->withHeader('Content-Type', 'application/json; charset=UTF-8');
            $response->getBody()->write((string) json_encode(['error' => 'invalid_token']));

            return $response;
        }

        $claims = ['sub' => $userEntity->getIdentifier()]
            + $this->claimExtractor->extract($scopeIdentifiers, $userEntity->getClaims());

        $response = $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json; charset=UTF-8')
            ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
            ->withHeader('Pragma', 'no-cache');

        $response->getBody()->write((string) json_encode($claims));

        return $response;
    }
}
