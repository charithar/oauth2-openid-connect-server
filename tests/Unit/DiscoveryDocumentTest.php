<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Discovery\DiscoveryDocument;
use PHPUnit\Framework\TestCase;

final class DiscoveryDocumentTest extends TestCase
{
    public function testOmitsOptionalEndpointsWhenNotConfigured(): void
    {
        $document = new DiscoveryDocument(
            issuer: 'https://issuer.example.com',
            authorizationEndpoint: 'https://issuer.example.com/authorize',
            tokenEndpoint: 'https://issuer.example.com/token',
            userinfoEndpoint: 'https://issuer.example.com/userinfo',
            jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
            scopesSupported: ['openid'],
            claimsSupported: ['sub'],
        );

        $array = $document->toArray();

        self::assertSame('https://issuer.example.com', $array['issuer']);
        self::assertArrayNotHasKey('end_session_endpoint', $array);
        self::assertArrayNotHasKey('revocation_endpoint', $array);
        self::assertArrayNotHasKey('introspection_endpoint', $array);
    }

    public function testIncludesOptionalEndpointsWhenConfigured(): void
    {
        $document = new DiscoveryDocument(
            issuer: 'https://issuer.example.com',
            authorizationEndpoint: 'https://issuer.example.com/authorize',
            tokenEndpoint: 'https://issuer.example.com/token',
            userinfoEndpoint: 'https://issuer.example.com/userinfo',
            jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
            scopesSupported: ['openid'],
            claimsSupported: ['sub'],
            endSessionEndpoint: 'https://issuer.example.com/logout',
            revocationEndpoint: 'https://issuer.example.com/revoke',
            introspectionEndpoint: 'https://issuer.example.com/introspect',
        );

        $array = $document->toArray();

        self::assertSame('https://issuer.example.com/logout', $array['end_session_endpoint']);
        self::assertSame('https://issuer.example.com/revoke', $array['revocation_endpoint']);
        self::assertSame('https://issuer.example.com/introspect', $array['introspection_endpoint']);
    }

    public function testAdvertisesAllThreeResponseModes(): void
    {
        $document = new DiscoveryDocument(
            issuer: 'https://issuer.example.com',
            authorizationEndpoint: 'https://issuer.example.com/authorize',
            tokenEndpoint: 'https://issuer.example.com/token',
            userinfoEndpoint: 'https://issuer.example.com/userinfo',
            jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
            scopesSupported: ['openid'],
            claimsSupported: ['sub'],
        );

        self::assertSame(['query', 'fragment', 'form_post'], $document->toArray()['response_modes_supported']);
    }
}
