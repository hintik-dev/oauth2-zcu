<?php declare(strict_types = 1);

namespace HintikDev\OAuth2\Client\Exception;

use RuntimeException;
use Throwable;

/**
 * Single catchable failure type for {@see \HintikDev\OAuth2\Client\Flow\ZcuAuthCodeFlow::authenticate()}.
 *
 * The underlying flow can fail in five unrelated ways — the user cancelling at the IdP, a
 * malformed callback, a state mismatch, an error from the identity provider, or a bad ID
 * token — spread across the
 * league, Contributte and this package's exception hierarchies. This type wraps all of them
 * so a callback handler needs a single catch block; the original is always available through
 * {@see getPrevious()}.
 */
class AuthenticationFailedException extends RuntimeException
{

	public const REASON_ACCESS_DENIED = 'access_denied';

	public const REASON_INVALID_CALLBACK = 'invalid_callback';

	public const REASON_STATE_MISMATCH = 'state_mismatch';

	public const REASON_PROVIDER_ERROR = 'provider_error';

	public const REASON_INVALID_ID_TOKEN = 'invalid_id_token';

	public function __construct(
		private readonly string $reason,
		string $message,
		?Throwable $previous = null,
	)
	{
		parent::__construct($message, 0, $previous);
	}

	/** One of the REASON_* constants. */
	public function getReason(): string
	{
		return $this->reason;
	}

	/**
	 * Whether the failure is plausibly the user's session expiring or a stale callback URL,
	 * rather than a misconfiguration or an attack. Such failures are worth retrying.
	 */
	public function isRetryable(): bool
	{
		return in_array($this->reason, [self::REASON_INVALID_CALLBACK, self::REASON_STATE_MISMATCH], true);
	}

}
