<?php declare(strict_types = 1);

namespace HintikDev\OAuth2\Client\Tests\Token;

use HintikDev\OAuth2\Client\Exception\IdTokenException;
use HintikDev\OAuth2\Client\Token\ZcuIdToken;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;

final class ZcuIdTokenTest extends TestCase
{

	/**
	 * @param mixed[] $claims
	 * @param mixed[] $header
	 */
	private function jwt(array $claims, array $header = ['alg' => 'RS256', 'kid' => 'k1']): string
	{
		$encode = static fn (array $part): string => rtrim(strtr(base64_encode((string) json_encode($part)), '+/', '-_'), '=');

		return $encode($header) . '.' . $encode($claims) . '.c2lnbmF0dXJl';
	}

	public function testParsesHeaderAndClaims(): void
	{
		$token = ZcuIdToken::parseUnverified($this->jwt([
			'iss' => 'https://shib.zcu.cz/idp/shibboleth',
			'sub' => 'subject-1',
			'aud' => 'oks-web',
			'nonce' => 'n-1',
			'exp' => 1_700_000_600,
			'iat' => 1_700_000_000,
			'auth_time' => 1_699_999_900,
		]));

		self::assertSame('https://shib.zcu.cz/idp/shibboleth', $token->getIssuer());
		self::assertSame('subject-1', $token->getSubject());
		self::assertSame(['oks-web'], $token->getAudience());
		self::assertSame('n-1', $token->getNonce());
		self::assertSame(1_700_000_600, $token->getExpiresAt()?->getTimestamp());
		self::assertSame(1_700_000_000, $token->getIssuedAt()?->getTimestamp());
		self::assertSame(1_699_999_900, $token->getAuthTime()?->getTimestamp());
		self::assertSame(['alg' => 'RS256', 'kid' => 'k1'], $token->getHeader());
	}

	public function testParsedTokensAreNotConsideredVerified(): void
	{
		$token = ZcuIdToken::parseUnverified($this->jwt(['sub' => 'x']));

		self::assertFalse($token->isVerified());
	}

	public function testVerifiedFactoryMarksTheToken(): void
	{
		$token = ZcuIdToken::verified('a.b.c', ['alg' => 'RS256'], ['sub' => 'x']);

		self::assertTrue($token->isVerified());
		self::assertSame('a.b.c', $token->toString());
	}

	public function testMultiValuedAudience(): void
	{
		$token = ZcuIdToken::parseUnverified($this->jwt(['aud' => ['oks-web', 'other']]));

		self::assertSame(['oks-web', 'other'], $token->getAudience());
	}

	public function testMissingAudienceIsAnEmptyList(): void
	{
		self::assertSame([], ZcuIdToken::parseUnverified($this->jwt(['sub' => 'x']))->getAudience());
	}

	public function testMissingTimeClaimsAreNull(): void
	{
		$token = ZcuIdToken::parseUnverified($this->jwt(['sub' => 'x']));

		self::assertNull($token->getExpiresAt());
		self::assertNull($token->getIssuedAt());
		self::assertNull($token->getAuthTime());
		self::assertNull($token->getNonce());
	}

	public function testStringConversionReturnsTheOriginalJwt(): void
	{
		$jwt = $this->jwt(['sub' => 'x']);

		self::assertSame($jwt, (string) ZcuIdToken::parseUnverified($jwt));
	}

	public function testRawClaimAccess(): void
	{
		$token = ZcuIdToken::parseUnverified($this->jwt(['sub' => 'x', 'acr' => 'password']));

		self::assertSame('password', $token->getClaim('acr'));
		self::assertNull($token->getClaim('missing'));
		self::assertSame('d', $token->getClaim('missing', 'd'));
		self::assertSame(['sub' => 'x', 'acr' => 'password'], $token->getClaims());
	}

	public function testFromAccessToken(): void
	{
		$jwt = $this->jwt(['sub' => 'x']);
		$accessToken = new AccessToken(['access_token' => 'at', 'id_token' => $jwt]);

		self::assertSame($jwt, ZcuIdToken::fromAccessToken($accessToken)->toString());
		self::assertSame($jwt, ZcuIdToken::tryFromAccessToken($accessToken)?->toString());
	}

	public function testFromAccessTokenWithoutIdTokenThrows(): void
	{
		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('did not contain an id_token');

		ZcuIdToken::fromAccessToken(new AccessToken(['access_token' => 'at']));
	}

	public function testTryFromAccessTokenWithoutIdTokenReturnsNull(): void
	{
		self::assertNull(ZcuIdToken::tryFromAccessToken(new AccessToken(['access_token' => 'at'])));
	}

	public function testWrongSegmentCountIsRejected(): void
	{
		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('three dot-delimited segments');

		ZcuIdToken::parseUnverified('not-a-jwt');
	}

	public function testNonJsonPayloadIsRejected(): void
	{
		$this->expectException(IdTokenException::class);
		$this->expectExceptionMessage('payload is not a JSON object');

		ZcuIdToken::parseUnverified('eyJhbGciOiJSUzI1NiJ9.bm90LWpzb24.sig');
	}

}
