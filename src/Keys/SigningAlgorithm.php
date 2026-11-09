<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Keys;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Rsa;
use RuntimeException;

use function sprintf;

/**
 * The JWA (RFC 7518) asymmetric signing algorithms a SigningKeyInterface
 * may report from getAlgorithm(). The signer is always chosen from the
 * key's own algorithm - never from a token's `alg` header - so a token
 * presented for verification can't pick a weaker or different algorithm
 * than the one its `kid` was published with.
 */
enum SigningAlgorithm: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';

    public static function fromKey(SigningKeyInterface $key): self
    {
        return self::tryFrom($key->getAlgorithm()) ?? throw new RuntimeException(sprintf(
            'Unsupported signing algorithm "%s" for kid "%s"; supported: RS256/384/512, ES256/384/512.',
            $key->getAlgorithm(),
            $key->getIdentifier()
        ));
    }

    public function signer(): Signer
    {
        return match ($this) {
            self::RS256 => new Rsa\Sha256(),
            self::RS384 => new Rsa\Sha384(),
            self::RS512 => new Rsa\Sha512(),
            self::ES256 => new Ecdsa\Sha256(),
            self::ES384 => new Ecdsa\Sha384(),
            self::ES512 => new Ecdsa\Sha512(),
        };
    }

    public function isEcdsa(): bool
    {
        return $this->ecCurve() !== null;
    }

    /**
     * JWK `crv` (RFC 7518 §6.2.1.1) of the one curve this algorithm is
     * defined for, or null for RSA.
     */
    public function ecCurve(): ?string
    {
        return match ($this) {
            self::ES256 => 'P-256',
            self::ES384 => 'P-384',
            self::ES512 => 'P-521',
            default => null,
        };
    }

    /**
     * OpenSSL's name for ecCurve(), as reported by openssl_pkey_get_details().
     */
    public function opensslCurveName(): ?string
    {
        return match ($this) {
            self::ES256 => 'prime256v1',
            self::ES384 => 'secp384r1',
            self::ES512 => 'secp521r1',
            default => null,
        };
    }

    /**
     * Byte length of one EC point coordinate: JWK `x`/`y` must be exactly
     * this long (RFC 7518 §6.2.1.2), including leading zero bytes OpenSSL
     * strips.
     */
    public function ecCoordinateLength(): int
    {
        return match ($this) {
            self::ES256 => 32,
            self::ES384 => 48,
            self::ES512 => 66,
            default => 0,
        };
    }
}
