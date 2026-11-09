<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Keys;

/**
 * One asymmetric (RSA or EC) signing key, published in the JWKS under its `kid`. Supplying
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
     * JWA signing algorithm identifier, one of SigningAlgorithm's values:
     * RS256/RS384/RS512 for an RSA key, ES256/ES384/ES512 for an EC key on
     * P-256/P-384/P-521 respectively. id_tokens are signed with exactly this
     * algorithm and the JWKS publishes it as `alg`; an unsupported value, or
     * key material of a different type/curve, throws rather than let the two
     * silently diverge.
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
