<?php declare(strict_types = 1);

namespace HintikDev\OAuth2\Client\Token;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use HintikDev\OAuth2\Client\Exception\IdTokenException;
use HintikDev\OAuth2\Client\Provider\Zcu;
use League\OAuth2\Client\Token\AccessTokenInterface;
use RuntimeException;
use stdClass;
use Throwable;

/**
 * Verifies ID tokens issued by the ZČU identity provider against its published JWKS.
 *
 * Checks performed: signature, `iss`, `aud` (plus `azp` when the audience is multi-valued),
 * `exp`, `nbf`/`iat`, and optionally `nonce` and `auth_time`.
 *
 * Requires firebase/php-jwt, which is an optional dependency of this package.
 */
final class ZcuIdTokenVerifier
{

	/** @var array<string, Key>|null */
	private ?array $keys = null;

	private ?int $keysFetchedAt = null;

	/**
	 * @param int $leeway clock skew tolerance in seconds applied to exp/nbf/iat
	 * @param int $jwksTtl how long a fetched key set is reused, in seconds
	 * @param string|null $signingAlgorithm algorithm assumed for JWKS entries that carry no
	 *     `alg` member; null derives it from the key type (RSA => RS256, EC => ES256/384/512)
	 */
	public function __construct(
		private readonly Zcu $provider,
		private readonly int $leeway = 60,
		private readonly int $jwksTtl = 3600,
		private readonly ?string $signingAlgorithm = null,
	)
	{
		if (!class_exists(JWT::class)) {
			throw new RuntimeException(sprintf(
				'%s requires the optional package firebase/php-jwt. Install it with "composer require firebase/php-jwt".',
				self::class,
			));
		}
	}

	/**
	 * @param string|ZcuIdToken|AccessTokenInterface $token raw JWT, parsed ID token, or an access token carrying one
	 * @param array{nonce?: string|null, audience?: string|null, issuer?: string|null, maxAge?: int|null} $options
	 * @throws IdTokenException when the token cannot be verified
	 */
	public function verify(string|ZcuIdToken|AccessTokenInterface $token, array $options = []): ZcuIdToken
	{
		$jwt = $this->resolveJwt($token);

		$expectedIssuer = $options['issuer'] ?? $this->provider->getIssuer();
		$expectedAudience = $options['audience'] ?? $this->provider->getClientId();

		['header' => $header, 'claims' => $claims] = $this->decode($jwt);

		$this->assertIssuer($claims, $expectedIssuer);
		$this->assertAudience($claims, $expectedAudience);
		$this->assertNonce($claims, $options['nonce'] ?? null);
		$this->assertAuthTime($claims, $options['maxAge'] ?? null);

		return ZcuIdToken::verified($jwt, $header, $claims);
	}

	/** Discards the cached key set, forcing a fresh JWKS fetch on the next verification. */
	public function clearKeyCache(): void
	{
		$this->keys = null;
		$this->keysFetchedAt = null;
	}

	/**
	 * @return array{header: mixed[], claims: mixed[]}
	 */
	private function decode(string $jwt): array
	{
		$previousLeeway = JWT::$leeway;
		JWT::$leeway = $this->leeway;

		// php-jwt only fills the by-reference header argument when it is not null.
		$header = new stdClass();

		try {
			try {
				$payload = JWT::decode($jwt, $this->getKeys(false), $header);
			} catch (Throwable $e) {
				// A rotated signing key is the common cause; retry once with a fresh key set.
				if ($this->keys === null || !$this->isUnknownKeyError($e)) {
					throw IdTokenException::verificationFailed($e->getMessage());
				}

				$header = new stdClass();
				$payload = JWT::decode($jwt, $this->getKeys(true), $header);
			}
		} catch (IdTokenException $e) {
			throw $e;
		} catch (Throwable $e) {
			throw IdTokenException::verificationFailed($e->getMessage());
		} finally {
			JWT::$leeway = $previousLeeway;
		}

		return [
			'header' => self::toArray($header),
			'claims' => self::toArray($payload),
		];
	}

	/**
	 * @return mixed[]
	 */
	private static function toArray(?stdClass $value): array
	{
		if ($value === null) {
			return [];
		}

		$decoded = json_decode((string) json_encode($value), true);

		return is_array($decoded) ? $decoded : [];
	}

	/**
	 * @return array<string, Key>
	 */
	private function getKeys(bool $forceRefresh): array
	{
		$isFresh = $this->keys !== null
			&& $this->keysFetchedAt !== null
			&& (time() - $this->keysFetchedAt) < $this->jwksTtl;

		if (!$forceRefresh && $isFresh) {
			/** @var array<string, Key> $cached */
			$cached = $this->keys;

			return $cached;
		}

		$request = $this->provider->getRequest('GET', $this->provider->getJwksUrl());
		$jwks = $this->provider->getParsedResponse($request);

		if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
			throw IdTokenException::verificationFailed(sprintf(
				'the key set at %s is not a valid JWKS document',
				$this->provider->getJwksUrl(),
			));
		}

		$keys = $this->parseKeySet($jwks['keys']);

		if ($keys === []) {
			throw IdTokenException::verificationFailed(sprintf(
				'the key set at %s contains no usable signing key',
				$this->provider->getJwksUrl(),
			));
		}

		$this->keys = $keys;
		$this->keysFetchedAt = time();

		return $keys;
	}

	/**
	 * The ZČU key set publishes no `alg` member on its keys and includes an encryption key
	 * alongside the signing ones, so the keys cannot be handed to JWK::parseKeySet() as they
	 * are. Encryption keys are dropped and a per-key-type algorithm is supplied instead.
	 *
	 * @param mixed[] $jwkList
	 * @return array<string, Key>
	 */
	private function parseKeySet(array $jwkList): array
	{
		$keys = [];

		foreach ($jwkList as $index => $jwk) {
			if (!is_array($jwk) || ($jwk['use'] ?? 'sig') !== 'sig') {
				continue;
			}

			$defaultAlg = $this->signingAlgorithm ?? self::defaultAlgorithmFor($jwk);

			if ($defaultAlg === null && !isset($jwk['alg'])) {
				continue;
			}

			try {
				$key = JWK::parseKey($jwk, $defaultAlg);
			} catch (Throwable) {
				// Unsupported key type or curve; other keys in the set may still work.
				continue;
			}

			if ($key === null) {
				continue;
			}

			$keys[isset($jwk['kid']) && is_scalar($jwk['kid']) ? (string) $jwk['kid'] : (string) $index] = $key;
		}

		return $keys;
	}

	/**
	 * @param mixed[] $jwk
	 */
	private static function defaultAlgorithmFor(array $jwk): ?string
	{
		return match ($jwk['kty'] ?? null) {
			'RSA' => 'RS256',
			'OKP' => 'EdDSA',
			'EC' => match ($jwk['crv'] ?? null) {
				'P-256' => 'ES256',
				'P-384' => 'ES384',
				'P-521' => 'ES512',
				default => null,
			},
			// Symmetric keys have no place in a published key set.
			default => null,
		};
	}

	private function resolveJwt(string|ZcuIdToken|AccessTokenInterface $token): string
	{
		if (is_string($token)) {
			return $token;
		}

		if ($token instanceof ZcuIdToken) {
			return $token->toString();
		}

		return ZcuIdToken::fromAccessToken($token)->toString();
	}

	/**
	 * @param mixed[] $claims
	 */
	private function assertIssuer(array $claims, string $expected): void
	{
		$issuer = $claims['iss'] ?? null;

		if (!is_string($issuer) || !hash_equals($expected, $issuer)) {
			throw IdTokenException::invalidClaim('iss', sprintf(
				'expected "%s", got "%s"',
				$expected,
				is_scalar($issuer) ? (string) $issuer : 'none',
			));
		}
	}

	/**
	 * @param mixed[] $claims
	 */
	private function assertAudience(array $claims, string $expected): void
	{
		$aud = $claims['aud'] ?? null;
		$audiences = is_string($aud) ? [$aud] : (is_array($aud) ? $aud : []);
		$audiences = array_values(array_filter($audiences, 'is_string'));

		if (!in_array($expected, $audiences, true)) {
			throw IdTokenException::invalidClaim('aud', sprintf('does not contain the client ID "%s"', $expected));
		}

		// OIDC Core 3.1.3.7: with multiple audiences the azp claim must identify this client.
		if (count($audiences) > 1) {
			$azp = $claims['azp'] ?? null;

			if (!is_string($azp) || !hash_equals($expected, $azp)) {
				throw IdTokenException::invalidClaim('azp', 'must equal the client ID when aud is multi-valued');
			}
		}
	}

	/**
	 * @param mixed[] $claims
	 */
	private function assertNonce(array $claims, ?string $expected): void
	{
		if ($expected === null) {
			return;
		}

		$nonce = $claims['nonce'] ?? null;

		if (!is_string($nonce) || !hash_equals($expected, $nonce)) {
			throw IdTokenException::invalidClaim('nonce', 'does not match the nonce sent with the authorization request');
		}
	}

	/**
	 * @param mixed[] $claims
	 */
	private function assertAuthTime(array $claims, ?int $maxAge): void
	{
		if ($maxAge === null) {
			return;
		}

		$authTime = $claims['auth_time'] ?? null;

		if (!is_numeric($authTime)) {
			throw IdTokenException::invalidClaim('auth_time', 'is required when maxAge is enforced');
		}

		if ((time() - (int) $authTime) > ($maxAge + $this->leeway)) {
			throw IdTokenException::invalidClaim('auth_time', sprintf('the authentication is older than %d seconds', $maxAge));
		}
	}

	private function isUnknownKeyError(Throwable $e): bool
	{
		return str_contains($e->getMessage(), '"kid"') || str_contains($e->getMessage(), 'kid');
	}

}
