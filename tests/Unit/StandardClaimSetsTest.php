<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\ClaimSets\StandardClaimSets;
use PHPUnit\Framework\TestCase;

final class StandardClaimSetsTest extends TestCase
{
    public function testOpenidScopeOnlyCarriesSub(): void
    {
        self::assertSame(['sub'], StandardClaimSets::openid()->getClaims());
    }

    public function testEmailScopeMatchesOidcCore(): void
    {
        self::assertSame(['email', 'email_verified'], StandardClaimSets::email()->getClaims());
    }

    public function testAllReturnsFiveDistinctScopes(): void
    {
        $scopes = array_map(
            static fn ($claimSet) => $claimSet->getScope(),
            StandardClaimSets::all()
        );

        self::assertSame(['openid', 'profile', 'email', 'address', 'phone'], $scopes);
    }
}
