<?php declare(strict_types = 1);

namespace HintikDev\OAuth2\Client\Provider;

use HintikDev\OAuth2\Client\Exception\ZcuIdentityProviderException;
use InvalidArgumentException;
use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;
use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

/**
 * OpenID Connect provider for the ZČU (University of West Bohemia) Orion identity
 * provider running on Shibboleth IdP at https://shib.zcu.cz.
 *
 * Endpoints mirror the IdP discovery document published at
 * https://shib.zcu.cz/.well-known/openid-configuration.
 */
class Zcu extends AbstractProvider
{

	use BearerAuthorizationTrait;

	public const DEFAULT_BASE_URL = 'https://shib.zcu.cz';

	public const DEFAULT_ISSUER = 'https://shib.zcu.cz/idp/shibboleth';

	public const TOKEN_AUTH_CLIENT_SECRET_BASIC = 'client_secret_basic';

	public const TOKEN_AUTH_CLIENT_SECRET_POST = 'client_secret_post';

	/**
	 * Scopes advertised by the IdP: openid, profile, email, address, phone, offline_access.
	 * Attribute release is additionally governed by the IdP attribute-filter policy for
	 * the registered client, so requesting a scope is not a guarantee of receiving a claim.
	 *
	 * @var string[]
	 */
	public const DEFAULT_SCOPES = ['openid', 'profile', 'email'];

	/** Base URL of the identity provider, without a trailing slash. */
	protected string $baseUrl = self::DEFAULT_BASE_URL;

	/** Expected `iss` claim of issued ID tokens. Note it differs from the base URL. */
	protected string $issuer = self::DEFAULT_ISSUER;

	/** @var string[] */
	protected array $scopes = self::DEFAULT_SCOPES;

	/** One of the TOKEN_AUTH_* constants. */
	protected string $tokenAuthMethod = self::TOKEN_AUTH_CLIENT_SECRET_BASIC;

	/** PKCE method, one of the AbstractProvider::PKCE_METHOD_* constants, or null to disable. */
	protected ?string $pkceMethod = null;

	/** Nonce sent with the most recent authorization request. */
	protected ?string $nonce = null;

	/**
	 * @param mixed[] $options
	 * @param mixed[] $collaborators
	 */
	public function __construct(array $options = [], array $collaborators = [])
	{
		if (isset($options['baseUrl'])) {
			$options['baseUrl'] = rtrim((string) $options['baseUrl'], '/');
		}

		parent::__construct($options, $collaborators);

		if ($this->scopes === []) {
			$this->scopes = self::DEFAULT_SCOPES;
		}

		if (!isset($collaborators['optionProvider'])) {
			$this->setOptionProvider($this->createOptionProvider($this->tokenAuthMethod));
		}
	}

	public function getBaseUrl(): string
	{
		return $this->baseUrl;
	}

	public function getIssuer(): string
	{
		return $this->issuer;
	}

	public function getClientId(): string
	{
		return (string) $this->clientId;
	}

	public function getBaseAuthorizationUrl(): string
	{
		return $this->baseUrl . '/idp/profile/oidc/authorize';
	}

	/**
	 * @param mixed[] $params
	 */
	public function getBaseAccessTokenUrl(array $params): string
	{
		return $this->baseUrl . '/idp/profile/oidc/token';
	}

	public function getResourceOwnerDetailsUrl(AccessToken $token): string
	{
		return $this->baseUrl . '/idp/profile/oidc/userinfo';
	}

	/** JSON Web Key Set used to verify ID token signatures. */
	public function getJwksUrl(): string
	{
		return $this->baseUrl . '/idp/profile/oidc/keyset';
	}

	public function getBaseLogoutUrl(): string
	{
		return $this->baseUrl . '/idp/profile/oidc/end-session';
	}

	/**
	 * Builds an RP-initiated logout URL.
	 *
	 * The `post_logout_redirect_uri` must be pre-registered with the IdP, and most
	 * deployments only honour it when `id_token_hint` is supplied as well.
	 *
	 * @param mixed[] $options accepts id_token_hint, post_logout_redirect_uri and state
	 */
	public function getLogoutUrl(array $options = []): string
	{
		$params = array_filter([
			'id_token_hint' => $options['id_token_hint'] ?? null,
			'post_logout_redirect_uri' => $options['post_logout_redirect_uri'] ?? null,
			'state' => $options['state'] ?? null,
		], static fn ($value) => $value !== null);

		if ($params === []) {
			return $this->getBaseLogoutUrl();
		}

		return $this->appendQuery($this->getBaseLogoutUrl(), $this->buildQueryString($params));
	}

	/** Nonce sent with the most recent authorization request, or null when none was sent. */
	public function getNonce(): ?string
	{
		return $this->nonce;
	}

	/**
	 * @return string[]
	 */
	protected function getDefaultScopes(): array
	{
		return $this->scopes;
	}

	/**
	 * OpenID Connect and RFC 6749 both require a space-delimited scope parameter.
	 * The league default is a comma, which would make the whole list a single opaque scope.
	 */
	protected function getScopeSeparator(): string
	{
		return ' ';
	}

	protected function getPkceMethod(): ?string
	{
		return $this->pkceMethod;
	}

	/**
	 * @param mixed[] $options
	 * @return mixed[]
	 */
	protected function getAuthorizationParameters(array $options): array
	{
		$options = parent::getAuthorizationParameters($options);

		// `approval_prompt` is a Google extension that the Shibboleth OP does not understand.
		unset($options['approval_prompt']);

		if (self::isOidcScope($options['scope'] ?? null)) {
			if (!array_key_exists('nonce', $options)) {
				$options['nonce'] = $this->getRandomState();
			}

			$this->nonce = $options['nonce'] === null ? null : (string) $options['nonce'];

			if ($options['nonce'] === null) {
				unset($options['nonce']);
			}
		} else {
			$this->nonce = null;
			unset($options['nonce']);
		}

		return $options;
	}

	/**
	 * @param mixed[] $data
	 * @throws ZcuIdentityProviderException
	 */
	protected function checkResponse(ResponseInterface $response, $data): void
	{
		$hasErrorPayload = is_array($data) && (isset($data['error']) || isset($data['error_description']));

		if ($response->getStatusCode() < 400 && !$hasErrorPayload) {
			return;
		}

		throw ZcuIdentityProviderException::fromResponse($response, $data);
	}

	/**
	 * @param mixed[] $response
	 */
	protected function createResourceOwner(array $response, AccessToken $token): ZcuResourceOwner
	{
		return new ZcuResourceOwner($response);
	}

	private function createOptionProvider(string $method): HttpBasicAuthOptionProvider|PostAuthOptionProvider
	{
		return match ($method) {
			self::TOKEN_AUTH_CLIENT_SECRET_BASIC => new HttpBasicAuthOptionProvider(),
			self::TOKEN_AUTH_CLIENT_SECRET_POST => new PostAuthOptionProvider(),
			default => throw new InvalidArgumentException(sprintf(
				'Unsupported token endpoint auth method "%s", expected "%s" or "%s".',
				$method,
				self::TOKEN_AUTH_CLIENT_SECRET_BASIC,
				self::TOKEN_AUTH_CLIENT_SECRET_POST,
			)),
		};
	}

	private static function isOidcScope(mixed $scope): bool
	{
		if (is_array($scope)) {
			return in_array('openid', $scope, true);
		}

		if (!is_string($scope)) {
			return false;
		}

		return in_array('openid', preg_split('/\s+/', trim($scope)) ?: [], true);
	}

}
