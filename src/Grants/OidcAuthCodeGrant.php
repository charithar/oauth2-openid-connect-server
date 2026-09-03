<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Grants;

use Charithar\OpenIDConnectServer\Context\OidcRequestContext;
use Charithar\OpenIDConnectServer\RequestTypes\OidcAuthorizationRequest;
use Charithar\OpenIDConnectServer\ResponseModes\ModeAwareRedirectResponse;
use Charithar\OpenIDConnectServer\ResponseModes\ResponseMode;
use DateInterval;
use DateTimeImmutable;

use function is_int;
use function is_string;
use function json_decode;
use function json_encode;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\RedirectUriValidators\RedirectUriValidator;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;
use Throwable;

/**
 * OIDC-aware authorization_code grant. league/oauth2-server has no concept
 * of `nonce`, `auth_time`, or `response_mode`, and (as of 9.3) throws
 * `invalid_client` for a redirect_uri mismatch, which RFC 6749 §5.2 reserves
 * for failed *client* authentication - a wrong redirect_uri is a different
 * failure and should be `invalid_request`. This grant adds all four:
 *
 *  - nonce/response_mode are read from the /authorize query string in
 *    validateAuthorizationRequest() (relying on createAuthorizationRequest()
 *    below to hand back an OidcAuthorizationRequest instance to set them on).
 *  - nonce and auth_time are carried inside the encrypted authorization
 *    code's own JSON payload (the same mechanism league already uses for
 *    client_id/redirect_uri/scopes/etc.) so they survive the redirect round
 *    trip to the token endpoint intact, without any external storage.
 *  - at token-exchange time, respondToAccessTokenRequest() peeks at that
 *    payload (decrypting it itself) purely to copy nonce/auth_time into the
 *    shared OidcRequestContext for IdTokenResponse to pick up, then
 *    delegates to the parent for the actual (and only) validation pass -
 *    any problem with the code is left for that real validation to raise as
 *    the correct OAuthServerException.
 *  - $authCodeTTL is captured locally because league's own copy is a
 *    private property on AuthCodeGrant, unreachable from a subclass, and
 *    completeAuthorizationRequest() needs it to compute expire_time.
 */
class OidcAuthCodeGrant extends AuthCodeGrant
{
    private DateInterval $localAuthCodeTTL;

    public function __construct(
        private readonly OidcRequestContext $context,
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);
        $this->localAuthCodeTTL = $authCodeTTL;
    }

    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new OidcAuthorizationRequest();
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $authorizationRequest = parent::validateAuthorizationRequest($request);

        if ($authorizationRequest instanceof OidcAuthorizationRequest) {
            $queryParams = $request->getQueryParams();

            $nonce = $queryParams['nonce'] ?? null;
            $authorizationRequest->setNonce(is_string($nonce) ? $nonce : null);

            $responseMode = $queryParams['response_mode'] ?? null;
            $authorizationRequest->setResponseMode(
                ResponseMode::fromRequestValue(is_string($responseMode) ? $responseMode : null)
            );
        }

        return $authorizationRequest;
    }

    protected function validateRedirectUri(
        string $redirectUri,
        ClientEntityInterface $client,
        ServerRequestInterface $request
    ): void {
        $validator = new RedirectUriValidator($client->getRedirectUri());

        if (! $validator->validateRedirectUri($redirectUri)) {
            throw OAuthServerException::invalidRequest('redirect_uri', 'Invalid redirect URI');
        }
    }

    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        if (! $authorizationRequest->getUser() instanceof UserEntityInterface) {
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $finalRedirectUri = $authorizationRequest->getRedirectUri()
            ?? $this->getClientRedirectUri($authorizationRequest->getClient());

        if ($authorizationRequest->isAuthorizationApproved() === true) {
            $authCode = $this->issueAuthCode(
                $this->localAuthCodeTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $authorizationRequest->getRedirectUri(),
                $authorizationRequest->getScopes()
            );

            $payload = [
                'client_id'             => $authCode->getClient()->getIdentifier(),
                'redirect_uri'          => $authCode->getRedirectUri(),
                'auth_code_id'          => $authCode->getIdentifier(),
                'scopes'                => $authCode->getScopes(),
                'user_id'               => $authCode->getUserIdentifier(),
                'expire_time'           => (new DateTimeImmutable())->add($this->localAuthCodeTTL)->getTimestamp(),
                'code_challenge'        => $authorizationRequest->getCodeChallenge(),
                'code_challenge_method' => $authorizationRequest->getCodeChallengeMethod(),
            ];

            $responseMode = ResponseMode::Query;

            if ($authorizationRequest instanceof OidcAuthorizationRequest) {
                $payload['nonce'] = $authorizationRequest->getNonce();
                $payload['auth_time'] = $authorizationRequest->getAuthTime();
                $responseMode = $authorizationRequest->getResponseMode() ?? ResponseMode::Query;
            }

            $jsonPayload = json_encode($payload);

            if ($jsonPayload === false) {
                throw new LogicException('An error was encountered when JSON encoding the authorization request response');
            }

            return new ModeAwareRedirectResponse(
                (string) $finalRedirectUri,
                [
                    'code'  => $this->encrypt($jsonPayload),
                    'state' => $authorizationRequest->getState(),
                ],
                $responseMode
            );
        }

        throw OAuthServerException::accessDenied(
            'The user denied the request',
            $this->makeRedirectUri((string) $finalRedirectUri, ['state' => $authorizationRequest->getState()])
        );
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        $this->context->setNonce(null);
        $this->context->setAuthTime(null);

        $encryptedAuthCode = $this->getRequestParameter('code', $request);

        if (is_string($encryptedAuthCode)) {
            try {
                $payload = json_decode($this->decrypt($encryptedAuthCode));

                if ($payload instanceof stdClass) {
                    $nonce = $payload->nonce ?? null;
                    $this->context->setNonce(is_string($nonce) ? $nonce : null);

                    $authTime = $payload->auth_time ?? null;
                    $this->context->setAuthTime(is_int($authTime) ? $authTime : null);
                }
            } catch (Throwable) {
                // Ignore: parent::respondToAccessTokenRequest() performs the
                // real validation and raises the correct OAuthServerException
                // for a bad/expired/tampered code.
            }
        }

        return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
    }
}
