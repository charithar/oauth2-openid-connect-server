<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\ClientAuthentication\ClientCredentialsMiddleware;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class ClientCredentialsMiddlewareTest extends TestCase
{
    public function testDecodesPercentEncodedBasicAuthCredentials(): void
    {
        // RFC 6749 §2.3.1: client_id/client_secret are each
        // application/x-www-form-urlencoded before being joined and
        // base64-encoded, so a "+" in the secret must decode back to a
        // space - league/oauth2-server's own Basic-auth reader does not do
        // this (it just base64-decodes and splits on ":").
        $secretWithReservedChars = 'sec ret+val&ue';
        $encodedSecret = urlencode($secretWithReservedChars);
        $header = 'Basic ' . base64_encode('my-client:' . $encodedSecret);

        $request = (new ServerRequest())->withHeader('Authorization', $header);

        $capturedRequest = $this->captureRequest($request);

        self::assertSame(
            ['client_id' => 'my-client', 'client_secret' => $secretWithReservedChars],
            $capturedRequest->getParsedBody()
        );
    }

    public function testDoesNotOverwriteClientSecretPostValuesAlreadyInTheBody(): void
    {
        $header = 'Basic ' . base64_encode('basic-client:basic-secret');

        $request = (new ServerRequest())
            ->withHeader('Authorization', $header)
            ->withParsedBody(['client_id' => 'post-client', 'client_secret' => 'post-secret']);

        $capturedRequest = $this->captureRequest($request);

        self::assertSame(
            ['client_id' => 'post-client', 'client_secret' => 'post-secret'],
            $capturedRequest->getParsedBody()
        );
    }

    public function testLeavesRequestUntouchedWithoutABasicAuthorizationHeader(): void
    {
        $request = new ServerRequest();

        $capturedRequest = $this->captureRequest($request);

        self::assertNull($capturedRequest->getParsedBody());
    }

    private function captureRequest(ServerRequestInterface $request): ServerRequestInterface
    {
        $middleware = new ClientCredentialsMiddleware();

        $handler = new class () implements RequestHandlerInterface {
            public ServerRequestInterface $received;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->received = $request;

                return new Response();
            }
        };

        $middleware->process($request, $handler);

        return $handler->received;
    }
}
