<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\ResponseTypes;

use function array_map;

use Charithar\OpenIDConnectServer\ClaimExtractor;
use Charithar\OpenIDConnectServer\Context\OidcRequestContext;
use Charithar\OpenIDConnectServer\Entities\ClaimsAwareUserEntityInterface;
use Charithar\OpenIDConnectServer\Keys\SigningKeyRepositoryInterface;
use Charithar\OpenIDConnectServer\Repositories\UserRepositoryInterface;
use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use RuntimeException;

use function sprintf;

/**
 * Signs and attaches the OIDC id_token to the token response, using
 * BearerTokenResponse::getExtraParams() - the extension point
 * league/oauth2-server itself documents for exactly this purpose. Claims
 * are built directly on a fresh JWT builder rather than layered on top of
 * the access token's own claims, so a claim that collides with a
 * JWT-registered name (sub, iss, ...) can never reach withClaim() and
 * throw: ClaimExtractor already excludes those, and the registered ones are
 * set here directly via the builder's own dedicated methods.
 */
class IdTokenResponse extends BearerTokenResponse
{
    /**
     * @param non-empty-string $issuer
     */
    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
        private readonly ClaimExtractor $claimExtractor,
        private readonly SigningKeyRepositoryInterface $signingKeyRepository,
        private readonly OidcRequestContext $context,
        private readonly string $issuer
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        if (! $this->isOpenIdRequest($accessToken)) {
            return [];
        }

        $userIdentifier = $accessToken->getUserIdentifier();

        if ($userIdentifier === null) {
            return [];
        }

        $userEntity = $this->userRepository->getUserEntityByIdentifier($userIdentifier);

        if (! $userEntity instanceof ClaimsAwareUserEntityInterface) {
            throw new RuntimeException(sprintf('Unable to find a claims-aware user for identifier "%s"', $userIdentifier));
        }

        $signingKey = $this->signingKeyRepository->getCurrentSigningKey();

        $builder = (new Builder(new JoseEncoder(), ChainedFormatter::default()))
            ->issuedBy($this->issuer)
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->identifiedBy($accessToken->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo($userEntity->getIdentifier())
            ->withHeader('kid', $signingKey->getIdentifier());

        $scopeIdentifiers = array_map(
            static fn ($scope): string => $scope->getIdentifier(),
            $accessToken->getScopes()
        );

        foreach ($this->claimExtractor->extract($scopeIdentifiers, $userEntity->getClaims()) as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        $nonce = $this->context->getNonce();
        if ($nonce !== null) {
            $builder = $builder->withClaim('nonce', $nonce);
        }

        $authTime = $this->context->getAuthTime();
        if ($authTime !== null) {
            $builder = $builder->withClaim('auth_time', $authTime);
        }

        $token = $builder->getToken(
            new Sha256(),
            InMemory::plainText($signingKey->getPrivateKeyContents(), $signingKey->getPassphrase() ?? '')
        );

        return ['id_token' => $token->toString()];
    }

    private function isOpenIdRequest(AccessTokenEntityInterface $accessToken): bool
    {
        foreach ($accessToken->getScopes() as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                return true;
            }
        }

        return false;
    }
}
