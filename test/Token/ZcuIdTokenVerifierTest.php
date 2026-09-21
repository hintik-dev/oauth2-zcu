<?php declare(strict_types = 1);

namespace HintikDev\OAuth2\Client\Tests\Token;

use Firebase\JWT\JWT;
use HintikDev\OAuth2\Client\Exception\IdTokenException;
use HintikDev\OAuth2\Client\Provider\Zcu;
use HintikDev\OAuth2\Client\Tests\Support\MockHttpClient;
use HintikDev\OAuth2\Client\Token\ZcuIdToken;
use HintikDev\OAuth2\Client\Token\ZcuIdTokenVerifier;
use League\OAuth2\Client\Token\AccessToken;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

final class ZcuIdTokenVerifierTest extends TestCase
{

	private const CLIENT_ID = 'oks-web';

	private const ISSUER = 'https://shib.zcu.cz/idp/shibboleth';

	/** @var array<string, OpenSSLAsymmetricKey> */
	private static array $keys = [];

	private static function key(string $kid): OpenSSLAsymmetricKey
	{
		if (!isset(self::$keys[$kid])) {
			$key = openssl_pkey_new([
				'private_key_bits' => 2048,
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
			]);

			self::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
			self::$keys[$kid] = $key;
		}

		return self::$keys[$kid];
	}

	/**
	 * Mirrors the shape the ZČU IdP actually publishes: no `alg` member on any key, and an
	 * RSA encryption key sitting alongside the signing keys.
	 *
	 * @param string[] $kids
	 * @param array<string, string> $extra additional members merged into every key
	 * @return array{keys: array<int, array<string, string>>}
	 */
	private static function jwks(array $kids, array $extra = [], bool $withEncKey = true): array
	{
		$keys = [];

		foreach ($kids as $kid) {
			$keys[] = array_merge(self::rsaJwk($kid), ['use' => 'sig'], $extra);
		}

		if ($withEncKey) {
			$keys[] = array_merge(self::rsaJwk('defaultRSAEnc'), ['use' => 'enc']);
		}

		return ['keys' => $keys];
	}

	/**
	 * @return array<string, string>
	 */
	private static function rsaJwk(string $kid): array
	{
		$details = openssl_pkey_get_details(self::key($kid));
		self::assertIsArray($details);

		return [
			'kty' => 'RSA',
			'kid' => $kid,
			'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
			'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
		];
	}

	/**
	 * @param mixed[] $overrides
	 */
	private static function sign(array $overrides = [], string $kid = 'k1'): string
	{
		$claims = array_merge([
			'iss' => self::ISSUER,
			'sub' => 'subject-1',
			'aud' => self::CLIENT_ID,
			'exp' => time() + 300,
			'iat' => time(),
			'auth_time' => time(),
			'nonce' => 'nonce-1',
		], $overrides);

		return JWT::encode(array_filter($claims, static fn ($v) => $v !== null), self::key($kid), 'RS256', $kid);
	}

	/**
	 * @param mixed[] $responses
	 */
	private function verifier(array $responses, int $leeway = 60, int $jwksTtl = 3600): ZcuIdTokenVerifier
	{
		$http = new MockHttpClient($responses);
		$provider = new Zcu(
			['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret'],
			['httpClient' => $http->client],
		);

		return new ZcuIdTokenVerifier($provider, $leeway, $jwksTtl);
	}

	public function testVerifiesAWellFormedToken(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$token = $verifier->verify(self::sign(), ['nonce' => 'nonce-1']);

		self::assertTrue($token->isVerified());
		self::assertSame('subject-1', $token->getSubject());
		self::assertSame(self::ISSUER, $token->getIssuer());
		self::assertSame('k1', $token->getHeader()['kid']);
	}

	public function testAcceptsAnAccessTokenAndAParsedIdToken(): void
	{
		$jwt = self::sign();

		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);
		self::assertTrue($verifier->verify(new AccessToken(['access_token' => 'at', 'id_token' => $jwt]))->isVerified());

		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);
		self::assertTrue($verifier->verify(ZcuIdToken::parseUnverified($jwt))->isVerified());
	}

	public function testTheKeySetIsFetchedOnceAndReused(): void
	{
		$http = new MockHttpClient([MockHttpClient::json(self::jwks(['k1']))]);
		$provider = new Zcu(
			['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret'],
			['httpClient' => $http->client],
		);
		$verifier = new ZcuIdTokenVerifier($provider);

		$verifier->verify(self::sign());
		$verifier->verify(self::sign());

		self::assertSame(1, $http->requestCount());
		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/keyset', (string) $http->requestAt(0)->getUri());
	}

	public function testAnUnknownKidTriggersOneJwksRefresh(): void
	{
		$http = new MockHttpClient([
			MockHttpClient::json(self::jwks(['k1'])),
			MockHttpClient::json(self::jwks(['k1', 'k2'])),
		]);
		$provider = new Zcu(
			['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret'],
			['httpClient' => $http->client],
		);
		$verifier = new ZcuIdTokenVerifier($provider);

		$verifier->verify(self::sign());
		$token = $verifier->verify(self::sign([], 'k2'), ['nonce' => 'nonce-1']);

		self::assertTrue($token->isVerified());
		self::assertSame(2, $http->requestCount());
	}

	public function testClearKeyCacheForcesARefetch(): void
	{
		$http = new MockHttpClient([
			MockHttpClient::json(self::jwks(['k1'])),
			MockHttpClient::json(self::jwks(['k1'])),
		]);
		$provider = new Zcu(
			['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret'],
			['httpClient' => $http->client],
		);
		$verifier = new ZcuIdTokenVerifier($provider);

		$verifier->verify(self::sign());
		$verifier->clearKeyCache();
		$verifier->verify(self::sign());

		self::assertSame(2, $http->requestCount());
	}

	public function testRejectsAnUnexpectedIssuer(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('claim "iss" is invalid');

		$verifier->verify(self::sign(['iss' => 'https://evil.test/idp']));
	}

	public function testRejectsAnAudienceThatIsNotThisClient(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('does not contain the client ID "oks-web"');

		$verifier->verify(self::sign(['aud' => 'someone-else']));
	}

	public function testAcceptsAMultiValuedAudienceWithAMatchingAzp(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$token = $verifier->verify(self::sign(['aud' => [self::CLIENT_ID, 'other'], 'azp' => self::CLIENT_ID]));

		self::assertTrue($token->isVerified());
	}

	public function testRejectsAMultiValuedAudienceWithoutAzp(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('claim "azp" is invalid');

		$verifier->verify(self::sign(['aud' => [self::CLIENT_ID, 'other']]));
	}

	public function testRejectsAMismatchedNonce(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('claim "nonce" is invalid');

		$verifier->verify(self::sign(['nonce' => 'other']), ['nonce' => 'nonce-1']);
	}

	public function testNonceIsOnlyCheckedWhenOneIsExpected(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		self::assertTrue($verifier->verify(self::sign(['nonce' => null]))->isVerified());
	}

	public function testMissingNonceIsRejectedWhenOneIsExpected(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('claim "nonce" is invalid');

		$verifier->verify(self::sign(['nonce' => null]), ['nonce' => 'nonce-1']);
	}

	public function testRejectsAnExpiredToken(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))], leeway: 0);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('signature could not be verified');

		$verifier->verify(self::sign(['exp' => time() - 10, 'iat' => time() - 3600]));
	}

	public function testLeewayAbsorbsSmallClockSkew(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))], leeway: 120);

		self::assertTrue($verifier->verify(self::sign(['exp' => time() - 30]))->isVerified());
	}

	public function testRejectsASignatureFromAForeignKey(): void
	{
		$verifier = $this->verifier([
			MockHttpClient::json(self::jwks(['k1'])),
			MockHttpClient::json(self::jwks(['k1'])),
		]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('signature could not be verified');

		// Signed with the "rogue" key but labelled with a kid the IdP publishes.
		$claims = ['iss' => self::ISSUER, 'sub' => 's', 'aud' => self::CLIENT_ID, 'exp' => time() + 300];
		$verifier->verify(JWT::encode($claims, self::key('rogue'), 'RS256', 'k1'));
	}

	public function testRejectsAnAuthenticationOlderThanMaxAge(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))], leeway: 0);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('older than 60 seconds');

		$verifier->verify(self::sign(['auth_time' => time() - 600]), ['maxAge' => 60]);
	}

	public function testMaxAgeRequiresAnAuthTimeClaim(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('claim "auth_time" is invalid');

		$verifier->verify(self::sign(['auth_time' => null]), ['maxAge' => 60]);
	}

	public function testRecentAuthenticationPassesMaxAge(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		self::assertTrue($verifier->verify(self::sign(), ['maxAge' => 600])->isVerified());
	}

	public function testExpectedIssuerAndAudienceCanBeOverridden(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))]);

		$token = $verifier->verify(
			self::sign(['iss' => 'https://other.test/idp', 'aud' => 'other-client']),
			['issuer' => 'https://other.test/idp', 'audience' => 'other-client'],
		);

		self::assertTrue($token->isVerified());
	}

	public function testTheEncryptionKeyIsNotUsableForVerification(): void
	{
		// Only the enc key is published, so nothing is left to verify with.
		$verifier = $this->verifier([MockHttpClient::json(self::jwks([], withEncKey: true))]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('contains no usable signing key');

		$verifier->verify(self::sign());
	}

	public function testAnExplicitAlgInTheKeySetIsRespected(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1'], ['alg' => 'RS256']))]);

		self::assertTrue($verifier->verify(self::sign())->isVerified());
	}

	public function testTheSigningAlgorithmCanBePinned(): void
	{
		$http = new MockHttpClient([MockHttpClient::json(self::jwks(['k1']))]);
		$provider = new Zcu(
			['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret'],
			['httpClient' => $http->client],
		);
		$verifier = new ZcuIdTokenVerifier($provider, signingAlgorithm: 'RS512');

		$jwt = JWT::encode(
			['iss' => self::ISSUER, 'sub' => 's', 'aud' => self::CLIENT_ID, 'exp' => time() + 300],
			self::key('k1'),
			'RS512',
			'k1',
		);

		self::assertTrue($verifier->verify($jwt)->isVerified());
	}

	public function testAKeySetWithUnsupportedKeysOnlyIsReported(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(['keys' => [['kty' => 'oct', 'kid' => 'x', 'k' => 'c2VjcmV0']]])]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('contains no usable signing key');

		$verifier->verify(self::sign());
	}

	public function testAMalformedKeySetIsReported(): void
	{
		$verifier = $this->verifier([MockHttpClient::json(['not-a-jwks' => true])]);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('is not a valid JWKS document');

		$verifier->verify(self::sign());
	}

	public function testGlobalJwtLeewayIsRestoredAfterVerification(): void
	{
		JWT::$leeway = 7;

		try {
			$verifier = $this->verifier([MockHttpClient::json(self::jwks(['k1']))], leeway: 300);
			$verifier->verify(self::sign());

			self::assertSame(7, JWT::$leeway);
		} finally {
			JWT::$leeway = 0;
		}
	}

}
