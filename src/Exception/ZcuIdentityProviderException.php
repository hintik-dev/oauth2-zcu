<?php declare(strict_types = 1);

namespace HintikDev\OAuth2\Client\Exception;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Message\ResponseInterface;

/**
 * Thrown when the ZČU identity provider answers with an OAuth 2.0 / OIDC error payload
 * or a non-successful HTTP status.
 */
class ZcuIdentityProviderException extends IdentityProviderException
{

	/**
	 * @param mixed $data parsed response body
	 */
	public static function fromResponse(ResponseInterface $response, mixed $data): self
	{
		$error = null;
		$description = null;

		if (is_array($data)) {
			$error = isset($data['error']) && is_scalar($data['error']) ? (string) $data['error'] : null;
			$description = isset($data['error_description']) && is_scalar($data['error_description'])
				? (string) $data['error_description']
				: null;
		}

		$message = implode(': ', array_filter([$error, $description], static fn ($part) => $part !== null && $part !== ''));

		if ($message === '') {
			$message = sprintf('%d %s', $response->getStatusCode(), $response->getReasonPhrase());
		}

		return new self($message, $response->getStatusCode(), $data);
	}

	/** The OAuth 2.0 `error` code, when the provider supplied one. */
	public function getError(): ?string
	{
		$body = $this->getResponseBody();

		if (is_array($body) && isset($body['error']) && is_scalar($body['error'])) {
			return (string) $body['error'];
		}

		return null;
	}

}
