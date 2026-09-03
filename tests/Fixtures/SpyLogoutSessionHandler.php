<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Tests\Fixtures;

use Charithar\OpenIDConnectServer\Logout\LogoutSessionHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class SpyLogoutSessionHandler implements LogoutSessionHandlerInterface
{
    private bool $terminated = false;

    public function terminate(ServerRequestInterface $request): void
    {
        $this->terminated = true;
    }

    public function wasTerminated(): bool
    {
        return $this->terminated;
    }
}
