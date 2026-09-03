<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Keys;

/**
 * One RSA signing key, published in the JWKS under its `kid`. Supplying
 * more than one key from SigningKeyRepositoryInterface (with the previous
 * key's `kid` still active alongside a new "current" one) is what enables
 * seamless key rotation: id_tokens already issued keep verifying against
 * the old key until it is retired from getActiveKeys().
 */
interface SigningKeyInterface
{
    /**
     * The `kid` this key is published and signed under.
     *
     * @return non-empty-string
     */
    public function getIdentifier(): string;

    /**
     * JWA signing algorithm identifier. Must be "RS256" in this version -
     * IdTokenResponse always signs with RS256 and throws if a key reports
     * anything else, rather than let the JWKS `alg` field silently diverge
     * from what was actually used to sign.
     *
     * @return non-empty-string
     */
    public function getAlgorithm(): string;

    /**
     * @return non-empty-string
     */
    public function getPrivateKeyContents(): string;

    /**
     * @return non-empty-string
     */
    public function getPublicKeyContents(): string;

    public function getPassphrase(): ?string;
}
