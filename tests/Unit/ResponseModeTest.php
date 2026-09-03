<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Unit;

use Charithar\OpenIDConnectServer\ResponseModes\ResponseMode;
use PHPUnit\Framework\TestCase;

final class ResponseModeTest extends TestCase
{
    public function testFragment(): void
    {
        self::assertSame(ResponseMode::Fragment, ResponseMode::fromRequestValue('fragment'));
    }

    public function testFormPost(): void
    {
        self::assertSame(ResponseMode::FormPost, ResponseMode::fromRequestValue('form_post'));
    }

    public function testQueryIsTheExplicitValue(): void
    {
        self::assertSame(ResponseMode::Query, ResponseMode::fromRequestValue('query'));
    }

    public function testNullFallsBackToQuery(): void
    {
        self::assertSame(ResponseMode::Query, ResponseMode::fromRequestValue(null));
    }

    public function testUnrecognizedValueFallsBackToQuery(): void
    {
        self::assertSame(ResponseMode::Query, ResponseMode::fromRequestValue('not-a-real-mode'));
    }
}
