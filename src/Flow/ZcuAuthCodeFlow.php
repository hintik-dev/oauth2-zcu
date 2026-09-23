<?php declare(strict_types = 1);

namespace Hintik\OAuth2\Client\Flow;

use Contributte\OAuth2Client\Exception\Logical\InvalidArgumentException;
use Contributte\OAuth2Client\Exception\Runtime\CannotAuthenticateUserException;
use Contributte\OAuth2Client\Exception\Runtime\PossibleCsrfAttackException;
use Contributte\OAuth2Client\Exception\Runtime\UserProbablyDeniedAccessException;
use Contributte\OAuth2Client\Flow\AuthCodeFlow;
use Hintik\OAuth2\Client\Exception\AuthenticationFailedException;
use Hintik\OAuth2\Client\Exception\IdTokenException;
use Hintik\OAuth2\Client\Provider\Zcu;
use Hintik\OAuth2\Client\Provider\ZcuResourceOwner;
use Hintik\OAuth2\Client\Token\ZcuIdToken;
use Hintik\OAuth2\Client\Token\ZcuIdTokenVerifier;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Nette\Http\Session;

/**
 * Authorization code flow for the ZČU identity provider.
 *
 * Extends the Contributte flow, which already stores and checks the `state` parameter, by
 * keeping the OIDC `nonce` in the same session section and binding it to the returned
 * ID token.
 *
 * Requires contributte/oauth2-client, which is an optional dependency of this package.
 */
class ZcuAuthCodeFlow extends AuthCodeFlow
{

	private const NONCE_KEY = 'zcu.nonce';

	public function __construct(
		Zcu $provider,
		Session $session,
		private readonly ?ZcuIdTokenVerifier $idTokenVerifier = null,
	)
	{
		parent::__construct($provider, $session);
	}

	/** Covariant override so callers get the typed provider without a cast. */
	public function getProvider(): Zcu
	{
		/** @var Zcu $provider */
		$provider = $this->provider;

		return $provider;
	}

	/**
	 * The parameter is left untyped to stay compatible with every contributte/oauth2-client
	 * 0.3.x release; only string, array and null are accepted.
	 *
	 * @param string|mixed[]|null $redirectUriOrOptions
	 * @param mixed[] $options
	 */
	public function getAuthorizationUrl($redirectUriOrOptions = null, array $options = []): string
	{
		$url = parent::getAuthorizationUrl($redirectUriOrOptions, $options);

		$this->session->getSection(self::SESSION_NAMESPACE)[self::NONCE_KEY] = $this->getProvider()->getNonce();

		return $url;
	}

	/**
	 * @param mixed[] $parameters
	 */
	public function getAccessToken(array $parameters, ?string $redirectUri = null): AccessTokenInterface
	{
		// The IdP redirects back with `error` instead of `code` when the user cancels the
		// login or the request is rejected; the same handling as Contributte's built-in flows.
		if (isset($parameters['error']) && is_scalar($parameters['error'])) {
			$this->pullNonce();

			throw new UserProbablyDeniedAccessException(implode(': ', array_filter([
				(string) $parameters['error'],
				isset($parameters['error_description']) && is_scalar($parameters['error_description'])
					? (string) $parameters['error_description']
					: null,
			])));
		}

		$nonce = $this->pullNonce();

		$accessToken = parent::getAccessToken($parameters, $redirectUri);

		if ($this->idTokenVerifier !== null) {
			$this->idTokenVerifier->verify($accessToken, ['nonce' => $nonce]);
		}

		return $accessToken;
	}

	/**
	 * Exchanges the authorization code and resolves the user in one step.
	 *
	 * Propagates the underlying league and Contributte exceptions. Use {@see authenticate()}
	 * if you would rather catch a single type.
	 *
	 * @param mixed[] $parameters query parameters received on the redirect URI
	 * @throws UserProbablyDeniedAccessException when the IdP redirected back with an `error`
	 * @throws InvalidArgumentException when `code` or `state` is missing from the callback
	 * @throws PossibleCsrfAttackException when `state` does not match the session
	 * @throws IdentityProviderException when the identity provider returns an error
	 * @throws IdTokenException when ID token verification is enabled and fails
	 */
	public function getResourceOwner(array $parameters, ?string $redirectUri = null): ZcuResourceOwner
	{
		$accessToken = $this->getAccessToken($parameters, $redirectUri);

		/** @var AccessToken $accessToken */
		/** @var ZcuResourceOwner $owner */
		$owner = $this->getProvider()->getResourceOwner($accessToken);

		return $owner;
	}

	/**
	 * Same as {@see getResourceOwner()}, but collapses every failure mode into a single
	 * {@see AuthenticationFailedException} so a callback handler needs one catch block.
	 *
	 * @param mixed[] $parameters query parameters received on the redirect URI
	 * @throws AuthenticationFailedException
	 */
	public function authenticate(array $parameters, ?string $redirectUri = null): ZcuResourceOwner
	{
		try {
			return $this->getResourceOwner($parameters, $redirectUri);
		} catch (InvalidArgumentException $e) {
			throw new AuthenticationFailedException(
				AuthenticationFailedException::REASON_INVALID_CALLBACK,
				$e->getMessage(),
				$e,
			);
		} catch (UserProbablyDeniedAccessException $e) {
			throw new AuthenticationFailedException(
				AuthenticationFailedException::REASON_ACCESS_DENIED,
				$e->getMessage(),
				$e,
			);
		} catch (PossibleCsrfAttackException | CannotAuthenticateUserException $e) {
			throw new AuthenticationFailedException(
				AuthenticationFailedException::REASON_STATE_MISMATCH,
				'The state parameter did not match the session; the login may simply have expired.',
				$e,
			);
		} catch (IdTokenException $e) {
			throw new AuthenticationFailedException(
				AuthenticationFailedException::REASON_INVALID_ID_TOKEN,
				$e->getMessage(),
				$e,
			);
		} catch (IdentityProviderException $e) {
			throw new AuthenticationFailedException(
				AuthenticationFailedException::REASON_PROVIDER_ERROR,
				$e->getMessage(),
				$e,
			);
		}
	}

	/**
	 * Parses the ID token out of an access token response without verifying it.
	 *
	 * @throws IdTokenException when the response carries no ID token
	 */
	public function getIdToken(AccessTokenInterface $accessToken): ZcuIdToken
	{
		return ZcuIdToken::fromAccessToken($accessToken);
	}

	/** Reads the nonce stored for the pending authorization request and clears it. */
	private function pullNonce(): ?string
	{
		$section = $this->session->getSection(self::SESSION_NAMESPACE);
		$nonce = $section[self::NONCE_KEY] ?? null;
		unset($section[self::NONCE_KEY]);

		return is_string($nonce) && $nonce !== '' ? $nonce : null;
	}

}
