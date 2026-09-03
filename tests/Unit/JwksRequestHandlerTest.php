<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\Jwks\JwksFactory;
use Charithar\OpenIDConnectServer\Jwks\JwksRequestHandler;
use Charithar\OpenIDConnectServer\Tests\Fixtures\FixtureSigningKey;
use Charithar\OpenIDConnectServer\Tests\Fixtures\InMemorySigningKeyRepository;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;

final class JwksRequestHandlerTest extends TestCase
{
    public function testServesTheJwksAsCacheableJson(): void
    {
        $factory = new JwksFactory(new InMemorySigningKeyRepository(new FixtureSigningKey('kid-1')));
        $handler = new JwksRequestHandler($factory, new ResponseFactory());

        $response = $handler->handle(new ServerRequest());

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json; charset=UTF-8', $response->getHeaderLine('Content-Type'));
        self::assertSame('public, max-age=300', $response->getHeaderLine('Cache-Control'));

        $body = json_decode((string) $response->getBody(), true);

        self::assertSame('kid-1', $body['keys'][0]['kid']);
    }
}
