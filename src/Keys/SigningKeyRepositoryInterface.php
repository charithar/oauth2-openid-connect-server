<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Keys;

interface SigningKeyRepositoryInterface
{
    /**
     * Every key that should currently verify (used to build the JWKS).
     *
     * @return SigningKeyInterface[]
     */
    public function getActiveKeys(): array;

    /**
     * The key new id_tokens are signed with.
     */
    public function getCurrentSigningKey(): SigningKeyInterface;
}
