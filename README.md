# ZČU Orion OIDC Provider for OAuth 2.0 Client

[![Packagist](https://img.shields.io/packagist/v/hintik-dev/oauth2-zcu.svg)](https://packagist.org/packages/hintik-dev/oauth2-zcu)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

ZČU (University of West Bohemia) Orion OpenID Connect provider for
[thephpleague/oauth2-client](https://github.com/thephpleague/oauth2-client), with optional
Nette integration on top of
[contributte/oauth2-client](https://github.com/contributte/oauth2-client).

The identity provider is a Shibboleth IdP at `https://shib.zcu.cz`; endpoints follow its
[discovery document](https://shib.zcu.cz/.well-known/openid-configuration).

## Installation

```bash
composer require hintik-dev/oauth2-zcu
```

Needs PHP 8.1+ and `league/oauth2-client` ^2.7. Two optional extras:
`contributte/oauth2-client` for the Nette authorization code flow, `firebase/php-jwt` for ID
token verification.

Client ID, client secret and the redirect URIs you may use are issued by CIV ZČU. There is no
self-service registration and no public documentation for it — ask through the
[ZČU HelpDesk](https://helpdesk.zcu.cz/wiki/Kontakt). Worth settling at the same time: which
claims your relying party gets released, and whether the client is registered for
`client_secret_basic` or `client_secret_post`.

## Usage

```php
use Hintik\OAuth2\Client\Provider\Zcu;

$provider = new Zcu([
    'clientId'     => getenv('ZCU_OIDC_CLIENT_ID'),
    'clientSecret' => getenv('ZCU_OIDC_CLIENT_SECRET'),
    'redirectUri'  => 'https://example.zcu.cz/auth/callback',
]);

if (!isset($_GET['code'])) {
    $url = $provider->getAuthorizationUrl();

    $_SESSION['oauth2state'] = $provider->getState();
    $_SESSION['oauth2nonce'] = $provider->getNonce();

    header('Location: ' . $url);
    exit;
}

if (empty($_GET['state']) || $_GET['state'] !== ($_SESSION['oauth2state'] ?? null)) {
    exit('Invalid state');
}

$accessToken = $provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);
$owner = $provider->getResourceOwner($accessToken);

echo $owner->getUid();   // novakj
echo $owner->getEmail(); // novakj@students.zcu.cz
```

## Claims

| Method | Claim | | Method | Claim |
| --- | --- | --- | --- | --- |
| `getId()` / `getSub()` | `sub` | | `getEmail()` | `email` |
| `getUid()` | `uid` | | `isEmailVerified()` | `email_verified` |
| `getEppn()` | `eppn` | | `getGroups()` | `groupNames` |
| `getName()` | `name` | | `getEntitlements()` | `eduperson_entitlement` |
| `getGivenName()` | `given_name` | | `getClaim($name)` | any |
| `getFamilyName()` | `family_name` | | `toArray()` | all |
| `getPreferredUsername()` | `preferred_username` | | | |

Two things to know:

- **`getId()` returns `sub`, not the Orion login.** `sub` is the OIDC subject identifier and
  may be pairwise, i.e. different per client. Use `getUid()` to key users on their Orion login.
- **Every getter can return `null`.** Shibboleth releases attributes through its
  `attribute-filter` policy, per relying party — requesting a scope does not guarantee the
  claim comes back.

Scopes default to `openid profile email`; the IdP also supports `address`, `phone` and
`offline_access` (for refresh tokens). Nothing else is a scope — `uid`, `eppn` and
`groupNames` are claims.

## Nette / Contributte

`ZcuAuthCodeFlow` extends the Contributte authorization code flow and keeps `state`,
`redirect_uri` and `nonce` in the Nette session, so the two requests need share nothing else.
Register it as an ordinary service:

```neon
services:
    zcuOidcProvider:
        factory: Hintik\OAuth2\Client\Provider\Zcu([
            clientId: %zcuOidc.clientId%
            clientSecret: %zcuOidc.clientSecret%
        ])
        autowired: false

    zcuOidcFlow: Hintik\OAuth2\Client\Flow\ZcuAuthCodeFlow(@zcuOidcProvider)
```

```php
public function actionZcuLogin(): void
{
    $this->redirectUrl($this->flow->getAuthorizationUrl($this->link('//zcuCallback')));
}

public function actionZcuCallback(): void
{
    try {
        $owner = $this->flow->authenticate($this->getHttpRequest()->getQuery());
    } catch (AuthenticationFailedException $e) {
        $this->logger->warning('ZCU OIDC login failed', ['reason' => $e->getReason()]);
        $this->flashMessage($e->isRetryable()
            ? 'Přihlášení vypršelo, zkuste to prosím znovu.'
            : 'Přihlášení se nezdařilo.', 'error');
        $this->redirect('in');
    }

    // …$owner->getUid() is your Orion login
}
```

`authenticate()` collapses five unrelated failure types — the user cancelling at the IdP
(`access_denied`), a malformed callback, a `state` mismatch (`invalid_callback` /
`state_mismatch`, both `isRetryable()`), an IdP error, and a bad ID token — into one
exception. Use `getResourceOwner()` instead if you want the raw
league and Contributte types; note they share no common base, so catching only
`IdentityProviderException` lets the other three become HTTP 500s.

## Configuration

| Option | Default |
| --- | --- |
| `clientId`, `clientSecret` | required |
| `redirectUri` | `null` |
| `baseUrl` | `https://shib.zcu.cz` |
| `issuer` | `https://shib.zcu.cz/idp/shibboleth` (expected `iss`, not the base URL) |
| `scopes` | `['openid', 'profile', 'email']` |
| `tokenAuthMethod` | `client_secret_basic`, or `client_secret_post` |
| `pkceMethod` | `null`; the IdP does not advertise PKCE support |

Anything else in the options array is passed through to `AbstractProvider`, so `timeout` and
`proxy` work as usual.

## ID token verification

Optional — the code is exchanged over TLS directly with the IdP, so a plain server-side login
does not need it. Worth enabling when you forward or cache the ID token, or want `nonce`
replay protection.

```php
$verifier = new ZcuIdTokenVerifier($provider, leeway: 60, jwksTtl: 3600);

$idToken = $verifier->verify($accessToken, ['nonce' => $_SESSION['oauth2nonce'] ?? null]);
```

Checks the JWKS signature (cached, refetched once on key rotation), `iss`, `aud`, `azp`,
`exp`, `nbf`/`iat`, and optionally `nonce` and `auth_time`. Throws `IdTokenException`.

The ZČU key set publishes no `alg` member on its keys and mixes an encryption key in with the
signing ones, so the algorithm is inferred per key type (`RSA` → RS256, `EC` → ES256/384/512)
and encryption keys are skipped. Pass `signingAlgorithm:` if your client is registered for
something other than the default.

Hand the verifier to `ZcuAuthCodeFlow` and it runs on every login, with the `nonce` taken
from the session automatically:

```neon
services:
    zcuOidcVerifier: Hintik\OAuth2\Client\Token\ZcuIdTokenVerifier(@zcuOidcProvider)
    zcuOidcFlow: Hintik\OAuth2\Client\Flow\ZcuAuthCodeFlow(@zcuOidcProvider, idTokenVerifier: @zcuOidcVerifier)
```

`ZcuIdToken::fromAccessToken($accessToken)` reads the claims without verifying, which is what
you want for an `id_token_hint`:

```php
$provider->getLogoutUrl([
    'id_token_hint'            => (string) ZcuIdToken::fromAccessToken($accessToken),
    'post_logout_redirect_uri' => 'https://example.zcu.cz/',
]);
```

## Development

```bash
composer install && composer tests && composer phpstan
```

## License

MIT. See [LICENSE](LICENSE).
