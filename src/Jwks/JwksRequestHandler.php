<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Jwks;

use function json_encode;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Mount at whatever path you advertise as `jwks_uri` in your discovery
 * document (conventionally /.well-known/jwks.json).
 */
final class JwksRequestHandler implements RequestHandlerInterface
{
    public function __construct(
        private readonly JwksFactory $jwksFactory,
        private readonly ResponseFactoryInterface $responseFactory
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json; charset=UTF-8')
            ->withHeader('Cache-Control', 'public, max-age=300');

        $response->getBody()->write((string) json_encode($this->jwksFactory->build()));

        return $response;
    }
}
