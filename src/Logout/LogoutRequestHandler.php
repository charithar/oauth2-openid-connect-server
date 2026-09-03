<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Logout;

use Charithar\OpenIDConnectServer\Entities\ClaimsAwareClientEntityInterface;
use Charithar\OpenIDConnectServer\Keys\SigningKeyRepositoryInterface;

use function in_array;
use function is_string;

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function rawurlencode;
use function str_contains;

/**
 * OIDC RP-Initiated Logout 1.0. Validates id_token_hint (signature, issuer,
 * expiry), resolves the client from its `aud` claim, and only redirects to
 * a post_logout_redirect_uri that client has explicitly registered - an
 * unregistered or missing redirect target still logs the user out (via
 * LogoutSessionHandlerInterface) but responds 200 instead of redirecting,
 * rather than becoming an open redirect.
 */
final class LogoutRequestHandler implements RequestHandlerInterface
{
    /**
     * @param non-empty-string $issuer
     */
    public function __construct(
        private readonly ClientRepositoryInterface $clientRepository,
        private readonly SigningKeyRepositoryInterface $signingKeyRepository,
        private readonly string $issuer,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly ?LogoutSessionHandlerInterface $sessionHandler = null
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();
        $idTokenHint = $queryParams['id_token_hint'] ?? null;
        $postLogoutRedirectUri = $queryParams['post_logout_redirect_uri'] ?? null;
        $state = $queryParams['state'] ?? null;

        if (! is_string($idTokenHint) || $idTokenHint === '') {
            return $this->responseFactory->createResponse(400);
        }

        try {
            $token = (new Parser(new JoseEncoder()))->parse($idTokenHint);
        } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound) {
            return $this->responseFactory->createResponse(403);
        }

        if (! $token instanceof UnencryptedToken) {
            return $this->responseFactory->createResponse(403);
        }

        $kid = $token->headers()->get('kid', null);
        $signingKey = null;

        foreach ($this->signingKeyRepository->getActiveKeys() as $key) {
            if ($kid === null || $key->getIdentifier() === $kid) {
                $signingKey = $key;
                break;
            }
        }

        if ($signingKey === null) {
            return $this->responseFactory->createResponse(403);
        }

        $validator = new Validator();

        try {
            $validator->assert($token, new SignedWith(new Sha256(), InMemory::plainText($signingKey->getPublicKeyContents())));
            $validator->assert($token, new IssuedBy($this->issuer));
            $validator->assert($token, new StrictValidAt(SystemClock::fromUTC()));
        } catch (RequiredConstraintsViolated) {
            return $this->responseFactory->createResponse(403);
        }

        $audience = $token->claims()->get('aud', []);
        $clientId = $audience[0] ?? null;

        $client = $clientId !== null ? $this->clientRepository->getClientEntity((string) $clientId) : null;

        if (! $client instanceof ClaimsAwareClientEntityInterface) {
            return $this->responseFactory->createResponse(400);
        }

        if ($this->sessionHandler !== null) {
            $this->sessionHandler->terminate($request);
        }

        if (! is_string($postLogoutRedirectUri) || ! in_array($postLogoutRedirectUri, $client->getPostLogoutRedirectUris(), true)) {
            return $this->responseFactory->createResponse(200);
        }

        $location = $postLogoutRedirectUri;

        if (is_string($state) && $state !== '') {
            $location .= (str_contains($location, '?') ? '&' : '?') . 'state=' . rawurlencode($state);
        }

        return $this->responseFactory->createResponse(302)->withHeader('Location', $location);
    }
}
