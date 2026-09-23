<?php declare(strict_types = 1);

namespace Hintik\OAuth2\Client\Token;

use DateTimeImmutable;
use Hintik\OAuth2\Client\Exception\IdTokenException;
use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * Read-only view of an OpenID Connect ID token.
 *
 * Instances created by {@see parseUnverified()} carry claims whose signature has NOT been
 * checked. Use {@see ZcuIdTokenVerifier} before trusting anything they contain.
 */
final class ZcuIdToken
{

	/**
	 * @param mixed[] $header
	 * @param mixed[] $claims
	 */
	private function __construct(
		private readonly string $jwt,
		private readonly array $header,
		private readonly array $claims,
		private readonly bool $verified,
	)
	{
	}

	/**
	 * Decodes the JWT payload without verifying the signature.
	 *
	 * @throws IdTokenException when the token is not a well-formed JWS
	 */
	public static function parseUnverified(string $jwt): self
	{
		$segments = explode('.', $jwt);

		if (count($segments) !== 3) {
			throw IdTokenException::malformed('expected three dot-delimited segments');
		}

		return new self($jwt, self::decodeSegment($segments[0], 'header'), self::decodeSegment($segments[1], 'payload'), false);
	}

	/**
	 * Reads the `id_token` out of an access token response.
	 *
	 * @throws IdTokenException when no ID token is present or it is malformed
	 */
	public static function fromAccessToken(AccessTokenInterface $token): self
	{
		$values = $token->getValues();
		$jwt = $values['id_token'] ?? null;

		if (!is_string($jwt) || $jwt === '') {
			throw IdTokenException::missing();
		}

		return self::parseUnverified($jwt);
	}

	/** Returns null instead of throwing when the response carries no ID token. */
	public static function tryFromAccessToken(AccessTokenInterface $token): ?self
	{
		$values = $token->getValues();
		$jwt = $values['id_token'] ?? null;

		if (!is_string($jwt) || $jwt === '') {
			return null;
		}

		return self::parseUnverified($jwt);
	}

	/**
	 * @param mixed[] $header
	 * @param mixed[] $claims
	 * @internal used by {@see ZcuIdTokenVerifier} once the signature has been checked
	 */
	public static function verified(string $jwt, array $header, array $claims): self
	{
		return new self($jwt, $header, $claims, true);
	}

	/** Whether the signature and the registered claims of this token have been verified. */
	public function isVerified(): bool
	{
		return $this->verified;
	}

	public function toString(): string
	{
		return $this->jwt;
	}

	public function __toString(): string
	{
		return $this->jwt;
	}

	/**
	 * @return mixed[]
	 */
	public function getHeader(): array
	{
		return $this->header;
	}

	/**
	 * @return mixed[]
	 */
	public function getClaims(): array
	{
		return $this->claims;
	}

	public function getClaim(string $name, mixed $default = null): mixed
	{
		return $this->claims[$name] ?? $default;
	}

	public function getIssuer(): ?string
	{
		return $this->getStringClaim('iss');
	}

	public function getSubject(): ?string
	{
		return $this->getStringClaim('sub');
	}

	/**
	 * @return string[]
	 */
	public function getAudience(): array
	{
		$aud = $this->claims['aud'] ?? null;

		if (is_string($aud)) {
			return [$aud];
		}

		if (!is_array($aud)) {
			return [];
		}

		return array_values(array_filter(array_map(
			static fn ($item) => is_scalar($item) ? (string) $item : null,
			$aud,
		), static fn ($item) => $item !== null && $item !== ''));
	}

	public function getNonce(): ?string
	{
		return $this->getStringClaim('nonce');
	}

	public function getExpiresAt(): ?DateTimeImmutable
	{
		return $this->getTimeClaim('exp');
	}

	public function getIssuedAt(): ?DateTimeImmutable
	{
		return $this->getTimeClaim('iat');
	}

	public function getAuthTime(): ?DateTimeImmutable
	{
		return $this->getTimeClaim('auth_time');
	}

	/**
	 * @return mixed[]
	 */
	private static function decodeSegment(string $segment, string $what): array
	{
		$padded = strtr($segment, '-_', '+/');
		$decoded = base64_decode($padded, true);

		if ($decoded === false) {
			throw IdTokenException::malformed(sprintf('%s is not valid base64url', $what));
		}

		$data = json_decode($decoded, true);

		if (!is_array($data)) {
			throw IdTokenException::malformed(sprintf('%s is not a JSON object', $what));
		}

		return $data;
	}

	private function getStringClaim(string $name): ?string
	{
		$value = $this->claims[$name] ?? null;

		return is_scalar($value) && (string) $value !== '' ? (string) $value : null;
	}

	private function getTimeClaim(string $name): ?DateTimeImmutable
	{
		$value = $this->claims[$name] ?? null;

		if (!is_numeric($value)) {
			return null;
		}

		return (new DateTimeImmutable())->setTimestamp((int) $value);
	}

}
