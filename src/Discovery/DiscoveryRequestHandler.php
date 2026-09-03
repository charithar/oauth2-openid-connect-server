<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Discovery;

use function json_encode;

use const JSON_UNESCAPED_SLASHES;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Mount at /.well-known/openid-configuration.
 */
final class DiscoveryRequestHandler implements RequestHandlerInterface
{
    public function __construct(
        private readonly DiscoveryDocument $discoveryDocument,
        private readonly ResponseFactoryInterface $responseFactory
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json; charset=UTF-8');

        $response->getBody()->write((string) json_encode($this->discoveryDocument->toArray(), JSON_UNESCAPED_SLASHES));

        return $response;
    }
}
