<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Discovery\DiscoveryDocument;
use Charithar\OpenIDConnectServer\Discovery\DiscoveryRequestHandler;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;

final class DiscoveryRequestHandlerTest extends TestCase
{
    public function testServesTheDiscoveryDocumentAsJson(): void
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

        $handler = new DiscoveryRequestHandler($document, new ResponseFactory());

        $response = $handler->handle(new ServerRequest());

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json; charset=UTF-8', $response->getHeaderLine('Content-Type'));

        $body = json_decode((string) $response->getBody(), true);

        self::assertSame('https://issuer.example.com', $body['issuer']);
        self::assertSame('https://issuer.example.com/.well-known/jwks.json', $body['jwks_uri']);
    }
}
