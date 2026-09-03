<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Repositories;

use Charithar\OpenIDConnectServer\Entities\ClaimsAwareUserEntityInterface;

/**
 * Looks up the claims-bearing user behind an issued token. league/oauth2-server
 * only carries a user identifier string on its tokens, not the user entity
 * itself, so IdTokenResponse and UserInfoRequestHandler both need this to
 * resolve claims at response time.
 */
interface UserRepositoryInterface
{
    public function getUserEntityByIdentifier(string $identifier): ?ClaimsAwareUserEntityInterface;
}
