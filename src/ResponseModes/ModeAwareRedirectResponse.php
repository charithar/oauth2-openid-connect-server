<?php

declare(strict_types=1);

namespace Charithar\OpenIDConnectServer\ResponseModes;

use const ENT_QUOTES;

use function htmlspecialchars;
use function http_build_query;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use Psr\Http\Message\ResponseInterface;

use function sprintf;
use function str_contains;

/**
 * league/oauth2-server's own RedirectResponse always builds a query-string
 * redirect (League\OAuth2\Server\ResponseTypes\RedirectResponse). This
 * variant honours the `response_mode` requested at /authorize
 * (query/fragment/form_post) when building the authorization-success
 * response.
 */
final class ModeAwareRedirectResponse extends AbstractResponseType
{
    /**
     * @param array<string, string|null> $params
     */
    public function __construct(
        private readonly string $redirectUri,
        private readonly array $params,
        private readonly ResponseMode $responseMode = ResponseMode::Query
    ) {
    }

    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        /** @var array<string, string> $params */
        $params = array_filter($this->params, static fn (?string $value): bool => $value !== null);

        return match ($this->responseMode) {
            ResponseMode::Fragment => $response
                ->withStatus(302)
                ->withHeader('Location', $this->redirectUri . '#' . http_build_query($params)),
            ResponseMode::FormPost => $this->formPostResponse($response, $params),
            ResponseMode::Query => $response
                ->withStatus(302)
                ->withHeader(
                    'Location',
                    $this->redirectUri . (str_contains($this->redirectUri, '?') ? '&' : '?') . http_build_query($params)
                ),
        };
    }

    /**
     * @param array<string, string> $params
     */
    private function formPostResponse(ResponseInterface $response, array $params): ResponseInterface
    {
        $inputs = '';
        foreach ($params as $name => $value) {
            $inputs .= sprintf(
                '<input type="hidden" name="%s" value="%s">',
                htmlspecialchars($name, ENT_QUOTES, 'UTF-8'),
                htmlspecialchars($value, ENT_QUOTES, 'UTF-8')
            );
        }

        $html = '<!DOCTYPE html><html><head><title>Continue</title></head>'
            . '<body onload="document.forms[0].submit()">'
            . sprintf('<form method="post" action="%s">', htmlspecialchars($this->redirectUri, ENT_QUOTES, 'UTF-8'))
            . $inputs
            . '<noscript><input type="submit" value="Continue"></noscript>'
            . '</form></body></html>';

        $response->getBody()->write($html);

        return $response
            ->withStatus(200)
            ->withHeader('Content-Type', 'text/html; charset=UTF-8');
    }
}
