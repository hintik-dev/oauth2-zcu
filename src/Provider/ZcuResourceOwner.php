<?php declare(strict_types = 1);

namespace Hintik\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * Claims returned by the ZČU userinfo endpoint.
 *
 * Every getter is nullable on purpose: the Shibboleth IdP releases attributes according to
 * the attribute-filter policy registered for the client, so any claim may legitimately be
 * absent even when its scope was requested.
 */
class ZcuResourceOwner implements ResourceOwnerInterface
{

	/** @var mixed[] */
	protected array $response;

	/**
	 * @param mixed[] $response
	 */
	public function __construct(array $response)
	{
		$this->response = $response;
	}

	/**
	 * Stable subject identifier issued by the IdP (`sub`).
	 *
	 * This is the OIDC-mandated unique identifier and may be pairwise, i.e. different for
	 * every registered client. To match users against an Orion login, use {@see getUid()}.
	 */
	public function getId(): ?string
	{
		return $this->getStringClaim('sub');
	}

	/** Alias of {@see getId()}. */
	public function getSub(): ?string
	{
		return $this->getStringClaim('sub');
	}

	/** Orion login, e.g. `novakj`. Released through the `uid` claim. */
	public function getUid(): ?string
	{
		return $this->getStringClaim('uid');
	}

	/**
	 * eduPersonPrincipalName, e.g. `novakj@zcu.cz`.
	 *
	 * The IdP advertises this claim as `eppn`; the longer spelling is accepted as a
	 * fallback for deployments that map the attribute under its full name.
	 */
	public function getEppn(): ?string
	{
		return $this->getStringClaim('eppn') ?? $this->getStringClaim('eduPersonPrincipalName');
	}

	public function getName(): ?string
	{
		return $this->getStringClaim('name');
	}

	public function getGivenName(): ?string
	{
		return $this->getStringClaim('given_name');
	}

	public function getFamilyName(): ?string
	{
		return $this->getStringClaim('family_name');
	}

	public function getPreferredUsername(): ?string
	{
		return $this->getStringClaim('preferred_username');
	}

	public function getEmail(): ?string
	{
		return $this->getStringClaim('email');
	}

	public function isEmailVerified(): ?bool
	{
		$value = $this->response['email_verified'] ?? null;

		if ($value === null) {
			return null;
		}

		return filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
	}

	/**
	 * Group memberships released through the `groupNames` claim.
	 *
	 * @return string[]
	 */
	public function getGroups(): array
	{
		return $this->getStringListClaim('groupNames');
	}

	/**
	 * eduPersonEntitlement values.
	 *
	 * @return string[]
	 */
	public function getEntitlements(): array
	{
		return $this->getStringListClaim('eduperson_entitlement');
	}

	/** Raw access to any claim, including ones this class does not wrap. */
	public function getClaim(string $name, mixed $default = null): mixed
	{
		return $this->response[$name] ?? $default;
	}

	public function hasClaim(string $name): bool
	{
		return array_key_exists($name, $this->response);
	}

	/**
	 * @return mixed[]
	 */
	public function toArray(): array
	{
		return $this->response;
	}

	private function getStringClaim(string $name): ?string
	{
		$value = $this->response[$name] ?? null;

		if ($value === null || is_array($value) || is_object($value)) {
			return null;
		}

		$value = (string) $value;

		return $value === '' ? null : $value;
	}

	/**
	 * @return string[]
	 */
	private function getStringListClaim(string $name): array
	{
		$value = $this->response[$name] ?? null;

		if ($value === null) {
			return [];
		}

		// Some IdP configurations serialise multi-valued attributes as a single
		// space- or semicolon-delimited string instead of a JSON array.
		if (is_string($value)) {
			$value = preg_split('/[;\s]+/', trim($value)) ?: [];
		}

		if (!is_array($value)) {
			return [];
		}

		$items = [];

		foreach ($value as $item) {
			if (is_array($item) || is_object($item)) {
				continue;
			}

			$item = (string) $item;

			if ($item !== '') {
				$items[] = $item;
			}
		}

		return array_values(array_unique($items));
	}

}
