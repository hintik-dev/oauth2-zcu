# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Zcu` — league OAuth 2.0 provider for the ZČU Orion Shibboleth IdP, with
  configurable base URL, issuer, scopes, token endpoint auth method and optional PKCE.
- `ZcuResourceOwner` — typed, null-safe access to the ZČU userinfo claims.
- `ZcuIdToken` / `ZcuIdTokenVerifier` — ID token parsing and JWKS-backed verification
  (`iss`, `aud`, `azp`, `exp`, `nbf`/`iat`, `nonce`, `auth_time`), with key-rotation refetch.
  Handles the ZČU key set, which omits `alg` and publishes an encryption key alongside the
  signing keys.
- `ZcuAuthCodeFlow` — Contributte authorization code flow extended with session-bound `nonce`
  handling and an `authenticate()` helper that collapses all failure modes into
  `AuthenticationFailedException`. Optional; registered as a plain Nette service.
- RP-initiated logout URLs via `Zcu::getLogoutUrl()`.
