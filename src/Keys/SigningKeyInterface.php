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
     * JWA signing algorithm identifier, e.g. "RS256".
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
