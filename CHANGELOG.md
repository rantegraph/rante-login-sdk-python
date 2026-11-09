# Changelog

## 1.0.0 (2026-11-09)

First release.

- **`RanteLoginClient`:** `create_authorization_request`, `handle_callback`, `exchange_code`,
  `validate_id_token`, `fetch_userinfo` and `from_browser_sdk_cookies`.
- **Client authentication:** `private_key_jwt` (RS256 or ES256) for server-side websites, and PKCE alone for
  browser-only websites.
- **Example:** `examples/flask`.
