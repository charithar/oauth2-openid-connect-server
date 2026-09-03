<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\ClaimSets;

use Charithar\OpenIDConnectServer\Entities\ClaimSetEntity;
use Charithar\OpenIDConnectServer\Entities\ClaimSetInterface;

/**
 * Standard scope-to-claims mappings from OIDC Core 1.0 §5.4. `sub` is
 * intentionally omitted from every set here: it is a JWT-registered claim
 * that ClaimExtractor always strips, and callers add it back explicitly
 * (IdTokenResponse via the token builder, UserInfoRequestHandler directly)
 * since RFC 7519 registered claims can't be set through withClaim().
 */
final class StandardClaimSets
{
    private function __construct()
    {
    }

    public static function openid(): ClaimSetInterface
    {
        return new ClaimSetEntity('openid', ['sub']);
    }

    public static function profile(): ClaimSetInterface
    {
        return new ClaimSetEntity('profile', [
            'name',
            'family_name',
            'given_name',
            'middle_name',
            'nickname',
            'preferred_username',
            'profile',
            'picture',
            'website',
            'gender',
            'birthdate',
            'zoneinfo',
            'locale',
            'updated_at',
        ]);
    }

    public static function email(): ClaimSetInterface
    {
        return new ClaimSetEntity('email', ['email', 'email_verified']);
    }

    public static function address(): ClaimSetInterface
    {
        return new ClaimSetEntity('address', ['address']);
    }

    public static function phone(): ClaimSetInterface
    {
        return new ClaimSetEntity('phone', ['phone_number', 'phone_number_verified']);
    }

    /**
     * @return ClaimSetInterface[]
     */
    public static function all(): array
    {
        return [
            self::openid(),
            self::profile(),
            self::email(),
            self::address(),
            self::phone(),
        ];
    }
}
