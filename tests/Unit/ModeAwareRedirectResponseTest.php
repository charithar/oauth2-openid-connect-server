<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\ResponseModes\ModeAwareRedirectResponse;
use Charithar\OpenIDConnectServer\ResponseModes\ResponseMode;
use Laminas\Diactoros\Response;
use PHPUnit\Framework\TestCase;

final class ModeAwareRedirectResponseTest extends TestCase
{
    public function testQueryModeAppendsParamsToQueryString(): void
    {
        $response = new ModeAwareRedirectResponse(
            'https://client.example.com/callback',
            ['code' => 'abc', 'state' => 'xyz']
        );

        $result = $response->generateHttpResponse(new Response());

        self::assertSame(302, $result->getStatusCode());
        self::assertSame('https://client.example.com/callback?code=abc&state=xyz', $result->getHeaderLine('Location'));
    }

    public function testQueryModeAppendsToExistingQueryString(): void
    {
        $response = new ModeAwareRedirectResponse(
            'https://client.example.com/callback?foo=bar',
            ['code' => 'abc']
        );

        $result = $response->generateHttpResponse(new Response());

        self::assertSame('https://client.example.com/callback?foo=bar&code=abc', $result->getHeaderLine('Location'));
    }

    public function testFragmentModeUsesHashInsteadOfQueryString(): void
    {
        $response = new ModeAwareRedirectResponse(
            'https://client.example.com/callback',
            ['code' => 'abc', 'state' => 'xyz'],
            ResponseMode::Fragment
        );

        $result = $response->generateHttpResponse(new Response());

        self::assertSame(302, $result->getStatusCode());
        self::assertSame('https://client.example.com/callback#code=abc&state=xyz', $result->getHeaderLine('Location'));
    }

    public function testFormPostModeReturnsAutoSubmittingHtmlForm(): void
    {
        $response = new ModeAwareRedirectResponse(
            'https://client.example.com/callback',
            ['code' => 'abc'],
            ResponseMode::FormPost
        );

        $result = $response->generateHttpResponse(new Response());
        $body = (string) $result->getBody();

        self::assertSame(200, $result->getStatusCode());
        self::assertSame('text/html; charset=UTF-8', $result->getHeaderLine('Content-Type'));
        self::assertStringContainsString('action="https://client.example.com/callback"', $body);
        self::assertStringContainsString('name="code" value="abc"', $body);
    }

    public function testNullParamsAreOmitted(): void
    {
        $response = new ModeAwareRedirectResponse(
            'https://client.example.com/callback',
            ['code' => 'abc', 'state' => null]
        );

        $result = $response->generateHttpResponse(new Response());

        self::assertSame('https://client.example.com/callback?code=abc', $result->getHeaderLine('Location'));
    }
}
