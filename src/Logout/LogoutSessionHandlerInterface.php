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
    /**
     * Called only after id_token_hint validated. $request carries the
     * LogoutRequestHandler::ATTRIBUTE_* attributes: the validated hint, the
     * resolved client identifier and (when present) the hint's `sub`.
     */
    public function terminate(ServerRequestInterface $request): void;
}
