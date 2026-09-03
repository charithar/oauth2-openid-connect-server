<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\ClientAuthentication;

use function array_key_exists;
use function base64_decode;
use function explode;
use function is_array;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function str_contains;
use function stripos;
use function substr;
use function urldecode;

/**
 * league/oauth2-server reads client_id/client_secret only from the parsed
 * request body (AbstractGrant::getClientCredentials()), falling back to raw
 * HTTP Basic credentials without decoding them. RFC 6749 §2.3.1 requires
 * client_id and client_secret to each be individually
 * application/x-www-form-urlencoded encoded before being joined with ":"
 * and base64-encoded for the Basic scheme, so a secret containing a
 * reserved character (e.g. "+" or "&") only round-trips correctly if the
 * server decodes it back on the way in. This middleware does that decoding
 * and writes the result into the parsed body, which league already
 * consults first - so client_secret_post values you already put there take
 * precedence, and public ("none") clients that send neither are unaffected.
 */
final class ClientCredentialsMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authorizationHeader = $request->getHeaderLine('Authorization');

        if (stripos($authorizationHeader, 'Basic ') === 0) {
            $decoded = base64_decode(substr($authorizationHeader, 6), true);

            if ($decoded !== false && str_contains($decoded, ':')) {
                [$clientId, $clientSecret] = explode(':', $decoded, 2);

                $parsedBody = $request->getParsedBody();
                $parsedBody = is_array($parsedBody) ? $parsedBody : [];

                if (! array_key_exists('client_id', $parsedBody)) {
                    $parsedBody['client_id'] = urldecode($clientId);
                }

                if (! array_key_exists('client_secret', $parsedBody)) {
                    $parsedBody['client_secret'] = urldecode($clientSecret);
                }

                $request = $request->withParsedBody($parsedBody);
            }
        }

        return $handler->handle($request);
    }
}
