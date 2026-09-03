<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;

interface ClaimsAwareClientEntityInterface extends ClientEntityInterface
{
    /**
     * Registered OIDC RP-Initiated Logout redirect targets for this client.
     * A post_logout_redirect_uri not present here must be rejected.
     *
     * @return string[]
     */
    public function getPostLogoutRedirectUris(): array;
}
