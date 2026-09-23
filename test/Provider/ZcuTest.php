<?php declare(strict_types = 1);

namespace Hintik\OAuth2\Client\Tests\Provider;

use GuzzleHttp\Psr7\Response;
use Hintik\OAuth2\Client\Exception\ZcuIdentityProviderException;
use Hintik\OAuth2\Client\Provider\Zcu;
use Hintik\OAuth2\Client\Provider\ZcuResourceOwner;
use Hintik\OAuth2\Client\Tests\Support\MockHttpClient;
use InvalidArgumentException;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;

final class ZcuTest extends TestCase
{

	/**
	 * @param mixed[] $options
	 */
	private function createProvider(array $options = [], ?MockHttpClient $http = null): Zcu
	{
		return new Zcu(
			array_merge([
				'clientId' => 'oks-web',
				'clientSecret' => 's3cr3t',
				'redirectUri' => 'https://app.test/auth/callback',
			], $options),
			$http !== null ? ['httpClient' => $http->client] : [],
		);
	}

	/**
	 * @return array<string, string>
	 */
	private function queryOf(string $url): array
	{
		parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

		/** @var array<string, string> $query */
		return $query;
	}

	public function testEndpointsMatchTheDiscoveryDocument(): void
	{
		$provider = $this->createProvider();

		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/authorize', $provider->getBaseAuthorizationUrl());
		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/token', $provider->getBaseAccessTokenUrl([]));
		self::assertSame(
			'https://shib.zcu.cz/idp/profile/oidc/userinfo',
			$provider->getResourceOwnerDetailsUrl(new AccessToken(['access_token' => 'x'])),
		);
		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/keyset', $provider->getJwksUrl());
		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/end-session', $provider->getBaseLogoutUrl());
		self::assertSame('https://shib.zcu.cz/idp/shibboleth', $provider->getIssuer());
	}

	public function testBaseUrlIsConfigurableAndTrailingSlashIsStripped(): void
	{
		$provider = $this->createProvider(['baseUrl' => 'https://shib-test.zcu.cz/']);

		self::assertSame('https://shib-test.zcu.cz', $provider->getBaseUrl());
		self::assertSame('https://shib-test.zcu.cz/idp/profile/oidc/authorize', $provider->getBaseAuthorizationUrl());
	}

	public function testScopesAreSpaceDelimited(): void
	{
		$query = $this->queryOf($this->createProvider()->getAuthorizationUrl());

		self::assertSame('openid profile email', $query['scope']);
		self::assertStringNotContainsString(',', $query['scope']);
	}

	public function testDefaultScopesAreOnlyScopesTheIdpAdvertises(): void
	{
		self::assertSame(['openid', 'profile', 'email'], Zcu::DEFAULT_SCOPES);
	}

	public function testScopesCanBeOverridden(): void
	{
		$query = $this->queryOf($this->createProvider(['scopes' => ['openid', 'email']])->getAuthorizationUrl());

		self::assertSame('openid email', $query['scope']);
	}

	public function testEmptyScopeListFallsBackToDefaults(): void
	{
		$query = $this->queryOf($this->createProvider(['scopes' => []])->getAuthorizationUrl());

		self::assertSame('openid profile email', $query['scope']);
	}

	public function testAuthorizationUrlCarriesTheStandardOidcParameters(): void
	{
		$provider = $this->createProvider();
		$url = $provider->getAuthorizationUrl();
		$query = $this->queryOf($url);

		self::assertStringStartsWith('https://shib.zcu.cz/idp/profile/oidc/authorize?', $url);
		self::assertSame('code', $query['response_type']);
		self::assertSame('oks-web', $query['client_id']);
		self::assertSame('https://app.test/auth/callback', $query['redirect_uri']);
		self::assertSame($provider->getState(), $query['state']);
		self::assertArrayNotHasKey('approval_prompt', $query);
	}

	public function testNonceIsGeneratedForOidcRequestsAndExposed(): void
	{
		$provider = $this->createProvider();
		$query = $this->queryOf($provider->getAuthorizationUrl());

		self::assertArrayHasKey('nonce', $query);
		self::assertNotSame('', $query['nonce']);
		self::assertSame($provider->getNonce(), $query['nonce']);
	}

	public function testNonceDiffersBetweenRequests(): void
	{
		$provider = $this->createProvider();

		$first = $this->queryOf($provider->getAuthorizationUrl())['nonce'];
		$second = $this->queryOf($provider->getAuthorizationUrl())['nonce'];

		self::assertNotSame($first, $second);
	}

	public function testExplicitNonceIsPreserved(): void
	{
		$provider = $this->createProvider();
		$query = $this->queryOf($provider->getAuthorizationUrl(['nonce' => 'fixed-nonce']));

		self::assertSame('fixed-nonce', $query['nonce']);
		self::assertSame('fixed-nonce', $provider->getNonce());
	}

	public function testNoNonceWithoutTheOpenidScope(): void
	{
		$provider = $this->createProvider(['scopes' => ['profile']]);
		$query = $this->queryOf($provider->getAuthorizationUrl());

		self::assertArrayNotHasKey('nonce', $query);
		self::assertNull($provider->getNonce());
	}

	public function testPkceIsDisabledByDefault(): void
	{
		$query = $this->queryOf($this->createProvider()->getAuthorizationUrl());

		self::assertArrayNotHasKey('code_challenge', $query);
	}

	public function testPkceCanBeEnabled(): void
	{
		$provider = $this->createProvider(['pkceMethod' => Zcu::PKCE_METHOD_S256]);
		$query = $this->queryOf($provider->getAuthorizationUrl());

		self::assertSame('S256', $query['code_challenge_method']);
		self::assertNotEmpty($query['code_challenge']);
		self::assertNotEmpty($provider->getPkceCode());
	}

	public function testTokenRequestUsesHttpBasicAuthByDefault(): void
	{
		$http = new MockHttpClient([MockHttpClient::json(['access_token' => 'at', 'token_type' => 'Bearer'])]);
		$provider = $this->createProvider([], $http);

		$provider->getAccessToken('authorization_code', ['code' => 'abc']);

		$request = $http->lastRequest();
		$body = [];
		parse_str((string) $request->getBody(), $body);

		self::assertSame('POST', $request->getMethod());
		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/token', (string) $request->getUri());
		self::assertSame('Basic ' . base64_encode('oks-web:s3cr3t'), $request->getHeaderLine('Authorization'));
		self::assertSame('authorization_code', $body['grant_type']);
		self::assertSame('abc', $body['code']);
		self::assertArrayNotHasKey('client_secret', $body);
	}

	public function testTokenRequestCanUseClientSecretPost(): void
	{
		$http = new MockHttpClient([MockHttpClient::json(['access_token' => 'at', 'token_type' => 'Bearer'])]);
		$provider = $this->createProvider(['tokenAuthMethod' => Zcu::TOKEN_AUTH_CLIENT_SECRET_POST], $http);

		$provider->getAccessToken('authorization_code', ['code' => 'abc']);

		$request = $http->lastRequest();
		$body = [];
		parse_str((string) $request->getBody(), $body);

		self::assertFalse($request->hasHeader('Authorization'));
		self::assertSame('oks-web', $body['client_id']);
		self::assertSame('s3cr3t', $body['client_secret']);
	}

	public function testUnsupportedTokenAuthMethodIsRejected(): void
	{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Unsupported token endpoint auth method "private_key_jwt"');

		$this->createProvider(['tokenAuthMethod' => 'private_key_jwt']);
	}

	public function testUserinfoRequestIsAuthenticatedWithABearerToken(): void
	{
		$http = new MockHttpClient([
			MockHttpClient::json(['access_token' => 'at-123', 'token_type' => 'Bearer']),
			MockHttpClient::json(['sub' => 'abc', 'uid' => 'novakj']),
		]);
		$provider = $this->createProvider([], $http);

		$token = $provider->getAccessToken('authorization_code', ['code' => 'abc']);
		$owner = $provider->getResourceOwner($token);

		$userinfoRequest = $http->requestAt(1);

		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/userinfo', (string) $userinfoRequest->getUri());
		self::assertSame('Bearer at-123', $userinfoRequest->getHeaderLine('Authorization'));
		self::assertInstanceOf(ZcuResourceOwner::class, $owner);
		self::assertSame('novakj', $owner->getUid());
	}

	public function testErrorPayloadIsTurnedIntoATypedException(): void
	{
		$http = new MockHttpClient([
			MockHttpClient::json(['error' => 'invalid_grant', 'error_description' => 'Code expired'], 400),
		]);
		$provider = $this->createProvider([], $http);

		try {
			$provider->getAccessToken('authorization_code', ['code' => 'stale']);
			self::fail('Expected ZcuIdentityProviderException.');
		} catch (ZcuIdentityProviderException $e) {
			self::assertSame('invalid_grant: Code expired', $e->getMessage());
			self::assertSame('invalid_grant', $e->getError());
			self::assertSame(400, $e->getCode());
			self::assertSame(['error' => 'invalid_grant', 'error_description' => 'Code expired'], $e->getResponseBody());
		}
	}

	public function testErrorPayloadWithHttpTwoHundredIsStillAnError(): void
	{
		$http = new MockHttpClient([MockHttpClient::json(['error' => 'invalid_client'])]);
		$provider = $this->createProvider([], $http);

		$this->expectException(ZcuIdentityProviderException::class);
		$this->expectExceptionMessage('invalid_client');

		$provider->getAccessToken('authorization_code', ['code' => 'abc']);
	}

	public function testNonSuccessfulStatusWithoutPayloadIsAnError(): void
	{
		$http = new MockHttpClient([new Response(503, ['Content-Type' => 'application/json'], '{}')]);
		$provider = $this->createProvider([], $http);

		$this->expectException(ZcuIdentityProviderException::class);
		$this->expectExceptionMessage('503 Service Unavailable');

		$provider->getAccessToken('authorization_code', ['code' => 'abc']);
	}

	public function testLogoutUrl(): void
	{
		$provider = $this->createProvider();

		self::assertSame('https://shib.zcu.cz/idp/profile/oidc/end-session', $provider->getLogoutUrl());

		$url = $provider->getLogoutUrl([
			'id_token_hint' => 'jwt-value',
			'post_logout_redirect_uri' => 'https://app.test/bye',
			'state' => 'st',
		]);
		$query = $this->queryOf($url);

		self::assertStringStartsWith('https://shib.zcu.cz/idp/profile/oidc/end-session?', $url);
		self::assertSame('jwt-value', $query['id_token_hint']);
		self::assertSame('https://app.test/bye', $query['post_logout_redirect_uri']);
		self::assertSame('st', $query['state']);
	}

}
