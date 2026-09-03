<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer;

use function array_key_exists;
use function array_keys;

use Charithar\OpenIDConnectServer\Entities\ClaimSetInterface;

use function in_array;

use Lcobucci\JWT\Token\RegisteredClaims;

/**
 * Resolves granted scopes to the claim values they unlock. RFC 7519
 * registered claims (iss/sub/aud/exp/nbf/iat/jti) are always excluded from
 * the result: callers set those directly on their JWT builder (or, for a
 * plain JSON response like UserInfo, add them back explicitly), since
 * lcobucci's Builder::withClaim() throws if you pass one of those names.
 */
final class ClaimExtractor
{
    /** @var array<string, ClaimSetInterface> */
    private array $claimSets = [];

    /**
     * @param iterable<ClaimSetInterface> $claimSets
     */
    public function __construct(iterable $claimSets = [])
    {
        foreach ($claimSets as $claimSet) {
            $this->addClaimSet($claimSet);
        }
    }

    public function addClaimSet(ClaimSetInterface $claimSet): void
    {
        $this->claimSets[$claimSet->getScope()] = $claimSet;
    }

    public function hasClaimSet(string $scope): bool
    {
        return isset($this->claimSets[$scope]);
    }

    public function getClaimSet(string $scope): ?ClaimSetInterface
    {
        return $this->claimSets[$scope] ?? null;
    }

    /**
     * @param string[] $scopeIdentifiers Granted scope identifiers.
     * @param array<string, mixed> $availableClaims All claims the user can supply.
     * @return array<non-empty-string, mixed> Claims unlocked by the granted scopes.
     */
    public function extract(array $scopeIdentifiers, array $availableClaims): array
    {
        $requestedClaimNames = [];

        foreach ($scopeIdentifiers as $scopeIdentifier) {
            $claimSet = $this->claimSets[$scopeIdentifier] ?? null;
            if ($claimSet === null) {
                continue;
            }

            foreach ($claimSet->getClaims() as $claimName) {
                $requestedClaimNames[$claimName] = true;
            }
        }

        $extracted = [];
        foreach (array_keys($requestedClaimNames) as $claimName) {
            if (in_array($claimName, RegisteredClaims::ALL, true)) {
                continue;
            }

            if (array_key_exists($claimName, $availableClaims)) {
                $extracted[$claimName] = $availableClaims[$claimName];
            }
        }

        return $extracted;
    }
}
