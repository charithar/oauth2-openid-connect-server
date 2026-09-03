<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\ClaimExtractor;
use Charithar\OpenIDConnectServer\ClaimSets\StandardClaimSets;
use Charithar\OpenIDConnectServer\Entities\ClaimSetEntity;
use PHPUnit\Framework\TestCase;

final class ClaimExtractorTest extends TestCase
{
    public function testExtractsOnlyClaimsUnlockedByGrantedScopes(): void
    {
        $extractor = new ClaimExtractor(StandardClaimSets::all());

        $availableClaims = [
            'sub'   => 'user-1',
            'name'  => 'Ada Lovelace',
            'email' => 'ada@example.com',
        ];

        $extracted = $extractor->extract(['openid', 'profile'], $availableClaims);

        self::assertSame(['name' => 'Ada Lovelace'], $extracted);
    }

    public function testNeverReturnsAJwtRegisteredClaimEvenWhenScopedIn(): void
    {
        // This is the exact bug this library fixes by design: a naive
        // ClaimExtractor would let a 'sub' claim through for the 'openid'
        // scope, which then throws when a caller applies it via
        // withClaim() on top of a builder that already set 'sub' via
        // relatedTo(). Here, `sub` must never appear in the output at all -
        // callers are expected to add registered claims back explicitly.
        $extractor = new ClaimExtractor([StandardClaimSets::openid()]);

        $extracted = $extractor->extract(['openid'], ['sub' => 'user-1']);

        self::assertSame([], $extracted);
    }

    public function testIgnoresScopesWithNoRegisteredClaimSet(): void
    {
        $extractor = new ClaimExtractor([StandardClaimSets::email()]);

        $extracted = $extractor->extract(['unknown-scope', 'email'], ['email' => 'ada@example.com']);

        self::assertSame(['email' => 'ada@example.com'], $extracted);
    }

    public function testOmitsAvailableClaimNotBackedByAnyGrantedScope(): void
    {
        $extractor = new ClaimExtractor([new ClaimSetEntity('profile', ['name'])]);

        $extracted = $extractor->extract(['profile'], ['name' => 'Ada', 'ssn' => '123-45-6789']);

        self::assertSame(['name' => 'Ada'], $extracted);
    }

    public function testHasClaimSetReflectsRegisteredScopes(): void
    {
        $extractor = new ClaimExtractor([StandardClaimSets::email()]);

        self::assertTrue($extractor->hasClaimSet('email'));
        self::assertFalse($extractor->hasClaimSet('profile'));
    }

    public function testGetClaimSetReturnsTheRegisteredSetOrNull(): void
    {
        $emailClaimSet = StandardClaimSets::email();
        $extractor = new ClaimExtractor([$emailClaimSet]);

        self::assertSame($emailClaimSet, $extractor->getClaimSet('email'));
        self::assertNull($extractor->getClaimSet('profile'));
    }

    public function testAddClaimSetRegistersItAfterConstruction(): void
    {
        $extractor = new ClaimExtractor();
        self::assertFalse($extractor->hasClaimSet('email'));

        $extractor->addClaimSet(StandardClaimSets::email());

        self::assertTrue($extractor->hasClaimSet('email'));
    }
}
