<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Logout;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Session teardown is app/framework-specific, so LogoutRequestHandler
 * delegates to this rather than assuming any particular session mechanism.
 */
interface LogoutSessionHandlerInterface
{
    public function terminate(ServerRequestInterface $request): void;
}
