<?php declare(strict_types = 1);

namespace HintikDev\OAuth2\Client\Exception;

use RuntimeException;

/**
 * Thrown when an ID token is missing, malformed, or fails verification.
 */
class IdTokenException extends RuntimeException
{

	public static function missing(): self
	{
		return new self('The access token response did not contain an id_token. Was the "openid" scope requested?');
	}

	public static function malformed(string $reason): self
	{
		return new self(sprintf('The id_token is malformed: %s', $reason));
	}

	public static function invalidClaim(string $claim, string $reason): self
	{
		return new self(sprintf('The id_token claim "%s" is invalid: %s', $claim, $reason));
	}

	public static function verificationFailed(string $reason): self
	{
		return new self(sprintf('The id_token signature could not be verified: %s', $reason));
	}

}
