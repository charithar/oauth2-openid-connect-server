<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\ResponseModes;

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices / OIDC Core `response_mode`.
 */
enum ResponseMode: string
{
    case Query = 'query';
    case Fragment = 'fragment';
    case FormPost = 'form_post';

    public static function fromRequestValue(?string $value): self
    {
        return match ($value) {
            'fragment' => self::Fragment,
            'form_post' => self::FormPost,
            default => self::Query,
        };
    }
}
