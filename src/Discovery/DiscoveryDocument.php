<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\Discovery;

/**
 * A .well-known/openid-configuration document. Every endpoint is taken as a
 * full URL rather than assembled from a path convention, since the library
 * doesn't assume any particular routing layout - build one of these in your
 * own bootstrap/factory alongside your route definitions.
 */
final class DiscoveryDocument
{
    /**
     * @param string[] $scopesSupported
     * @param string[] $responseTypesSupported
     * @param string[] $responseModesSupported
     * @param string[] $grantTypesSupported
     * @param string[] $tokenEndpointAuthMethodsSupported
     * @param string[] $subjectTypesSupported
     * @param string[] $idTokenSigningAlgValuesSupported
     * @param string[] $claimsSupported
     */
    public function __construct(
        private readonly string $issuer,
        private readonly string $authorizationEndpoint,
        private readonly string $tokenEndpoint,
        private readonly string $userinfoEndpoint,
        private readonly string $jwksUri,
        private readonly array $scopesSupported,
        private readonly array $claimsSupported,
        private readonly array $responseTypesSupported = ['code'],
        private readonly array $responseModesSupported = ['query', 'fragment', 'form_post'],
        private readonly array $grantTypesSupported = ['authorization_code', 'refresh_token'],
        private readonly array $tokenEndpointAuthMethodsSupported = ['client_secret_basic', 'client_secret_post'],
        private readonly array $subjectTypesSupported = ['public'],
        private readonly array $idTokenSigningAlgValuesSupported = ['RS256'],
        private readonly ?string $endSessionEndpoint = null,
        private readonly ?string $revocationEndpoint = null,
        private readonly ?string $introspectionEndpoint = null
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $document = [
            'issuer'                                => $this->issuer,
            'authorization_endpoint'                 => $this->authorizationEndpoint,
            'token_endpoint'                          => $this->tokenEndpoint,
            'userinfo_endpoint'                       => $this->userinfoEndpoint,
            'jwks_uri'                                 => $this->jwksUri,
            'scopes_supported'                         => $this->scopesSupported,
            'response_types_supported'                => $this->responseTypesSupported,
            'response_modes_supported'                => $this->responseModesSupported,
            'grant_types_supported'                   => $this->grantTypesSupported,
            'token_endpoint_auth_methods_supported'   => $this->tokenEndpointAuthMethodsSupported,
            'subject_types_supported'                 => $this->subjectTypesSupported,
            'id_token_signing_alg_values_supported'   => $this->idTokenSigningAlgValuesSupported,
            'claims_supported'                        => $this->claimsSupported,
        ];

        if ($this->endSessionEndpoint !== null) {
            $document['end_session_endpoint'] = $this->endSessionEndpoint;
        }

        if ($this->revocationEndpoint !== null) {
            $document['revocation_endpoint'] = $this->revocationEndpoint;
        }

        if ($this->introspectionEndpoint !== null) {
            $document['introspection_endpoint'] = $this->introspectionEndpoint;
        }

        return $document;
    }
}
