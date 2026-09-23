<?php declare(strict_types = 1);

namespace Hintik\OAuth2\Client\Tests\Flow;

use Contributte\OAuth2Client\Exception\Logical\InvalidArgumentException;
use Contributte\OAuth2Client\Exception\Runtime\PossibleCsrfAttackException;
use Contributte\OAuth2Client\Exception\Runtime\UserProbablyDeniedAccessException;
use Contributte\OAuth2Client\Flow\AuthCodeFlow;
use Firebase\JWT\JWT;
use Hintik\OAuth2\Client\Exception\AuthenticationFailedException;
use Hintik\OAuth2\Client\Exception\IdTokenException;
use Hintik\OAuth2\Client\Exception\ZcuIdentityProviderException;
use Hintik\OAuth2\Client\Flow\ZcuAuthCodeFlow;
use Hintik\OAuth2\Client\Provider\Zcu;
use Hintik\OAuth2\Client\Tests\Support\ArraySession;
use Hintik\OAuth2\Client\Tests\Support\MockHttpClient;
use Hintik\OAuth2\Client\Token\ZcuIdTokenVerifier;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

final class ZcuAuthCodeFlowTest extends TestCase
{

	private const CLIENT_ID = 'oks-web';

	private const REDIRECT_URI = 'https://app.test/auth/callback';

	private static ?OpenSSLAsymmetricKey $key = null;

	private ArraySession $session;

	protected function setUp(): void
	{
		$this->session = new ArraySession();
	}

	private static function key(): OpenSSLAsymmetricKey
	{
		if (self::$key === null) {
			$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
			self::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
			self::$key = $key;
		}

		return self::$key;
	}

	/**
	 * @return array{keys: array<int, array<string, string>>}
	 */
	private static function jwks(): array
	{
		$details = openssl_pkey_get_details(self::key());
		self::assertIsArray($details);

		return ['keys' => [[
			'kty' => 'RSA',
			'kid' => 'k1',
			'alg' => 'RS256',
			'use' => 'sig',
			'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
			'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
		]]];
	}

	private static function idToken(?string $nonce): string
	{
		return JWT::encode(array_filter([
			'iss' => Zcu::DEFAULT_ISSUER,
			'sub' => 'subject-1',
			'aud' => self::CLIENT_ID,
			'exp' => time() + 300,
			'iat' => time(),
			'nonce' => $nonce,
		], static fn ($v) => $v !== null), self::key(), 'RS256', 'k1');
	}

	/**
	 * @param mixed[] $responses
	 * @return array{ZcuAuthCodeFlow, MockHttpClient}
	 */
	private function createFlow(array $responses, bool $verifyIdToken = false): array
	{
		$http = new MockHttpClient($responses);
		$provider = new Zcu(
			['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret', 'redirectUri' => self::REDIRECT_URI],
			['httpClient' => $http->client],
		);

		$verifier = $verifyIdToken ? new ZcuIdTokenVerifier($provider) : null;

		return [new ZcuAuthCodeFlow($provider, $this->session, $verifier), $http];
	}

	/**
	 * @return array<string, mixed>
	 */
	private function sessionData(): array
	{
		/** @var array<string, mixed> $data */
		$data = $_SESSION['__NF']['DATA'][AuthCodeFlow::SESSION_NAMESPACE] ?? [];

		return $data;
	}

	public function testAuthorizationUrlStoresStateRedirectUriAndNonce(): void
	{
		[$flow] = $this->createFlow([]);

		$url = $flow->getAuthorizationUrl(self::REDIRECT_URI);
		parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

		$data = $this->sessionData();

		self::assertSame($query['state'], $data['state']);
		self::assertSame(self::REDIRECT_URI, $data['redirect_uri']);
		self::assertSame($query['nonce'], $data['zcu.nonce']);
		self::assertSame($flow->getProvider()->getNonce(), $data['zcu.nonce']);
	}

	public function testNoNonceIsStoredForANonOidcRequest(): void
	{
		$http = new MockHttpClient([]);
		$provider = new Zcu(
			['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret', 'scopes' => ['profile']],
			['httpClient' => $http->client],
		);
		$flow = new ZcuAuthCodeFlow($provider, $this->session);

		$flow->getAuthorizationUrl(self::REDIRECT_URI);

		self::assertNull($this->sessionData()['zcu.nonce'] ?? null);
	}

	public function testHappyPathExchangesTheCodeAndResolvesTheUser(): void
	{
		[$flow, $http] = $this->createFlow([
			MockHttpClient::json(['access_token' => 'at-1', 'token_type' => 'Bearer']),
			MockHttpClient::json(['sub' => 'subject-1', 'uid' => 'novakj', 'email' => 'novakj@zcu.cz']),
		]);

		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		$owner = $flow->getResourceOwner(['code' => 'auth-code', 'state' => $state]);

		self::assertSame('novakj', $owner->getUid());
		self::assertSame('subject-1', $owner->getId());

		$tokenBody = [];
		parse_str((string) $http->requestAt(0)->getBody(), $tokenBody);
		self::assertSame(self::REDIRECT_URI, $tokenBody['redirect_uri']);
	}

	public function testStateMismatchIsRejected(): void
	{
		[$flow] = $this->createFlow([]);

		$flow->getAuthorizationUrl(self::REDIRECT_URI);

		$this->expectException(PossibleCsrfAttackException::class);

		$flow->getAccessToken(['code' => 'auth-code', 'state' => 'forged']);
	}

	public function testTheStoredNonceIsCheckedAgainstTheIdToken(): void
	{
		[$flow] = $this->createFlow([
			MockHttpClient::json([]),
			MockHttpClient::json([]),
		], verifyIdToken: true);

		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$data = $this->sessionData();
		$state = (string) $data['state'];
		$nonce = (string) $data['zcu.nonce'];

		// Re-arm the mock now that the nonce is known.
		[$flow, $http] = $this->createFlow([
			MockHttpClient::json(['access_token' => 'at-1', 'token_type' => 'Bearer', 'id_token' => self::idToken($nonce)]),
			MockHttpClient::json(self::jwks()),
		], verifyIdToken: true);

		$token = $flow->getAccessToken(['code' => 'auth-code', 'state' => $state]);

		self::assertSame('at-1', $token->getToken());
		self::assertSame(2, $http->requestCount());
		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/keyset', (string) $http->requestAt(1)->getUri());
	}

	public function testAnIdTokenBoundToADifferentNonceIsRejected(): void
	{
		[$flow] = $this->createFlow([], verifyIdToken: true);
		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		[$flow] = $this->createFlow([
			MockHttpClient::json(['access_token' => 'at-1', 'token_type' => 'Bearer', 'id_token' => self::idToken('replayed')]),
			MockHttpClient::json(self::jwks()),
		], verifyIdToken: true);

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('claim "nonce" is invalid');

		$flow->getAccessToken(['code' => 'auth-code', 'state' => $state]);
	}

	public function testVerificationRejectsAResponseWithoutAnIdToken(): void
	{
		[$flow] = $this->createFlow([
			MockHttpClient::json(['access_token' => 'at-1', 'token_type' => 'Bearer']),
		], verifyIdToken: true);

		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('did not contain an id_token');

		$flow->getAccessToken(['code' => 'auth-code', 'state' => $state]);
	}

	public function testTheNonceIsSingleUse(): void
	{
		[$flow] = $this->createFlow([
			MockHttpClient::json(['access_token' => 'at-1', 'token_type' => 'Bearer']),
			MockHttpClient::json(['access_token' => 'at-2', 'token_type' => 'Bearer']),
		]);

		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		$flow->getAccessToken(['code' => 'auth-code', 'state' => $state]);

		self::assertArrayNotHasKey('zcu.nonce', $this->sessionData());
	}

	public function testIdTokenIsExposedWithoutAVerifier(): void
	{
		$nonce = 'n-1';
		[$flow] = $this->createFlow([
			MockHttpClient::json(['access_token' => 'at-1', 'token_type' => 'Bearer', 'id_token' => self::idToken($nonce)]),
		]);

		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		$accessToken = $flow->getAccessToken(['code' => 'auth-code', 'state' => $state]);
		$idToken = $flow->getIdToken($accessToken);

		self::assertSame('subject-1', $idToken->getSubject());
		self::assertFalse($idToken->isVerified());
	}

	public function testAuthenticateWrapsAStateMismatch(): void
	{
		[$flow] = $this->createFlow([]);
		$flow->getAuthorizationUrl(self::REDIRECT_URI);

		try {
			$flow->authenticate(['code' => 'auth-code', 'state' => 'forged']);
			self::fail('Expected AuthenticationFailedException.');
		} catch (AuthenticationFailedException $e) {
			self::assertSame(AuthenticationFailedException::REASON_STATE_MISMATCH, $e->getReason());
			self::assertTrue($e->isRetryable());
			self::assertInstanceOf(PossibleCsrfAttackException::class, $e->getPrevious());
		}
	}

	public function testAuthenticateWrapsAMalformedCallback(): void
	{
		[$flow] = $this->createFlow([]);
		$flow->getAuthorizationUrl(self::REDIRECT_URI);

		try {
			$flow->authenticate(['state' => 'whatever']);
			self::fail('Expected AuthenticationFailedException.');
		} catch (AuthenticationFailedException $e) {
			self::assertSame(AuthenticationFailedException::REASON_INVALID_CALLBACK, $e->getReason());
			self::assertTrue($e->isRetryable());
			self::assertInstanceOf(InvalidArgumentException::class, $e->getPrevious());
		}
	}

	public function testAuthenticateWrapsAProviderError(): void
	{
		[$flow] = $this->createFlow([
			MockHttpClient::json(['error' => 'invalid_grant', 'error_description' => 'Code expired'], 400),
		]);
		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		try {
			$flow->authenticate(['code' => 'stale', 'state' => $state]);
			self::fail('Expected AuthenticationFailedException.');
		} catch (AuthenticationFailedException $e) {
			self::assertSame(AuthenticationFailedException::REASON_PROVIDER_ERROR, $e->getReason());
			self::assertFalse($e->isRetryable());
			self::assertInstanceOf(ZcuIdentityProviderException::class, $e->getPrevious());
			self::assertSame('invalid_grant: Code expired', $e->getMessage());
		}
	}

	public function testAuthenticateWrapsAnIdTokenFailure(): void
	{
		[$flow] = $this->createFlow([
			MockHttpClient::json(['access_token' => 'at-1', 'token_type' => 'Bearer']),
		], verifyIdToken: true);
		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		try {
			$flow->authenticate(['code' => 'auth-code', 'state' => $state]);
			self::fail('Expected AuthenticationFailedException.');
		} catch (AuthenticationFailedException $e) {
			self::assertSame(AuthenticationFailedException::REASON_INVALID_ID_TOKEN, $e->getReason());
			self::assertFalse($e->isRetryable());
			self::assertInstanceOf(IdTokenException::class, $e->getPrevious());
		}
	}

	public function testAuthenticateReturnsTheOwnerOnTheHappyPath(): void
	{
		[$flow] = $this->createFlow([
			MockHttpClient::json(['access_token' => 'at-1', 'token_type' => 'Bearer']),
			MockHttpClient::json(['sub' => 'subject-1', 'uid' => 'novakj']),
		]);
		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		self::assertSame('novakj', $flow->authenticate(['code' => 'auth-code', 'state' => $state])->getUid());
	}

	public function testAnErrorCallbackIsReportedAsDeniedAccess(): void
	{
		[$flow] = $this->createFlow([]);
		$flow->getAuthorizationUrl(self::REDIRECT_URI);
		$state = (string) $this->sessionData()['state'];

		try {
			$flow->getAccessToken(['error' => 'access_denied', 'error_description' => 'User cancelled', 'state' => $state]);
			self::fail('Expected UserProbablyDeniedAccessException.');
		} catch (UserProbablyDeniedAccessException $e) {
			self::assertSame('access_denied: User cancelled', $e->getMessage());
		}

		self::assertArrayNotHasKey('zcu.nonce', $this->sessionData(), 'nonce must be consumed');
	}

	public function testAuthenticateWrapsDeniedAccess(): void
	{
		[$flow] = $this->createFlow([]);
		$flow->getAuthorizationUrl(self::REDIRECT_URI);

		try {
			$flow->authenticate(['error' => 'access_denied']);
			self::fail('Expected AuthenticationFailedException.');
		} catch (AuthenticationFailedException $e) {
			self::assertSame(AuthenticationFailedException::REASON_ACCESS_DENIED, $e->getReason());
			self::assertFalse($e->isRetryable());
			self::assertInstanceOf(UserProbablyDeniedAccessException::class, $e->getPrevious());
		}
	}

	public function testGetProviderReturnsTheTypedProvider(): void
	{
		[$flow] = $this->createFlow([]);

		self::assertInstanceOf(Zcu::class, $flow->getProvider());
	}

}
