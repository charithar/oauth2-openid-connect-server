<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\ClientAuthentication;

enum ClientAuthenticationMethod: string
{
    case ClientSecretBasic = 'client_secret_basic';
    case ClientSecretPost = 'client_secret_post';
    case None = 'none';
}
