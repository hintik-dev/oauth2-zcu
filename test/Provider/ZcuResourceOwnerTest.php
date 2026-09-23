<?php declare(strict_types = 1);

namespace Hintik\OAuth2\Client\Tests\Provider;

use Hintik\OAuth2\Client\Provider\ZcuResourceOwner;
use PHPUnit\Framework\TestCase;

final class ZcuResourceOwnerTest extends TestCase
{

	/**
	 * @return mixed[]
	 */
	private function fullClaims(): array
	{
		return [
			'sub' => 'AAdzZWNyZXQx',
			'uid' => 'novakj',
			'eppn' => 'novakj@zcu.cz',
			'name' => 'Jan Novák',
			'given_name' => 'Jan',
			'family_name' => 'Novák',
			'preferred_username' => 'novakj',
			'email' => 'novakj@students.zcu.cz',
			'email_verified' => true,
			'groupNames' => ['ZCU', 'FAV', 'KIV'],
			'eduperson_entitlement' => ['urn:mace:dir:entitlement:common-lib-terms'],
		];
	}

	public function testAllWrappedClaims(): void
	{
		$owner = new ZcuResourceOwner($this->fullClaims());

		self::assertSame('AAdzZWNyZXQx', $owner->getId());
		self::assertSame('AAdzZWNyZXQx', $owner->getSub());
		self::assertSame('novakj', $owner->getUid());
		self::assertSame('novakj@zcu.cz', $owner->getEppn());
		self::assertSame('Jan Novák', $owner->getName());
		self::assertSame('Jan', $owner->getGivenName());
		self::assertSame('Novák', $owner->getFamilyName());
		self::assertSame('novakj', $owner->getPreferredUsername());
		self::assertSame('novakj@students.zcu.cz', $owner->getEmail());
		self::assertTrue($owner->isEmailVerified());
		self::assertSame(['ZCU', 'FAV', 'KIV'], $owner->getGroups());
		self::assertSame(['urn:mace:dir:entitlement:common-lib-terms'], $owner->getEntitlements());
	}

	public function testGetIdReturnsSubNotUid(): void
	{
		$owner = new ZcuResourceOwner(['sub' => 'pairwise-id', 'uid' => 'novakj']);

		self::assertSame('pairwise-id', $owner->getId());
		self::assertNotSame($owner->getUid(), $owner->getId());
	}

	public function testEveryGetterIsNullSafeOnAnEmptyRelease(): void
	{
		$owner = new ZcuResourceOwner([]);

		self::assertNull($owner->getId());
		self::assertNull($owner->getSub());
		self::assertNull($owner->getUid());
		self::assertNull($owner->getEppn());
		self::assertNull($owner->getName());
		self::assertNull($owner->getGivenName());
		self::assertNull($owner->getFamilyName());
		self::assertNull($owner->getPreferredUsername());
		self::assertNull($owner->getEmail());
		self::assertNull($owner->isEmailVerified());
		self::assertSame([], $owner->getGroups());
		self::assertSame([], $owner->getEntitlements());
		self::assertSame([], $owner->toArray());
	}

	public function testEmptyStringClaimIsTreatedAsAbsent(): void
	{
		$owner = new ZcuResourceOwner(['email' => '']);

		self::assertNull($owner->getEmail());
	}

	public function testEppnFallsBackToTheLongAttributeName(): void
	{
		$owner = new ZcuResourceOwner(['eduPersonPrincipalName' => 'novakj@zcu.cz']);

		self::assertSame('novakj@zcu.cz', $owner->getEppn());
	}

	public function testEppnPrefersTheDiscoveryClaimName(): void
	{
		$owner = new ZcuResourceOwner([
			'eppn' => 'short@zcu.cz',
			'eduPersonPrincipalName' => 'long@zcu.cz',
		]);

		self::assertSame('short@zcu.cz', $owner->getEppn());
	}

	public function testGroupsDeliveredAsADelimitedStringAreSplit(): void
	{
		self::assertSame(['ZCU', 'FAV'], (new ZcuResourceOwner(['groupNames' => 'ZCU;FAV']))->getGroups());
		self::assertSame(['ZCU', 'FAV'], (new ZcuResourceOwner(['groupNames' => 'ZCU FAV']))->getGroups());
	}

	public function testGroupsAreDeduplicatedAndReindexed(): void
	{
		$owner = new ZcuResourceOwner(['groupNames' => ['ZCU', 'FAV', 'ZCU', '']]);

		self::assertSame(['ZCU', 'FAV'], $owner->getGroups());
	}

	public function testGroupsOfAnUnexpectedShapeDegradeToAnEmptyList(): void
	{
		self::assertSame([], (new ZcuResourceOwner(['groupNames' => 42.5]))->getGroups());
		self::assertSame([], (new ZcuResourceOwner(['groupNames' => null]))->getGroups());
	}

	/**
	 * @dataProvider emailVerifiedProvider
	 */
	public function testEmailVerifiedAcceptsTheShapesShibbolethEmits(mixed $value, ?bool $expected): void
	{
		self::assertSame($expected, (new ZcuResourceOwner(['email_verified' => $value]))->isEmailVerified());
	}

	/**
	 * @return array<string, array{mixed, bool|null}>
	 */
	public static function emailVerifiedProvider(): array
	{
		return [
			'bool true' => [true, true],
			'bool false' => [false, false],
			'string true' => ['true', true],
			'string false' => ['false', false],
			'int one' => [1, true],
			'int zero' => [0, false],
			'garbage' => ['perhaps', null],
		];
	}

	public function testToArrayExposesTheWholeUserinfoResponse(): void
	{
		$claims = $this->fullClaims();
		$claims['some_future_claim'] = 'value';

		$owner = new ZcuResourceOwner($claims);

		self::assertSame($claims, $owner->toArray());
		self::assertSame('value', $owner->getClaim('some_future_claim'));
		self::assertTrue($owner->hasClaim('some_future_claim'));
		self::assertFalse($owner->hasClaim('nope'));
		self::assertSame('fallback', $owner->getClaim('nope', 'fallback'));
	}

}
