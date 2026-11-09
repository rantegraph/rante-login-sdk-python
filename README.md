# Rante Login SDK for Python

"Sign in with Rante" on your Python server. The SDK:

- builds the sign-in request (authorization code with PKCE, state and nonce);
- exchanges the code, proving it is your app with `private_key_jwt`, or with PKCE alone for browser-only apps;
- validates the ID token before you trust who signed in;
- calls the userinfo endpoint.

It finishes sign-ins started by the [Rante Login browser SDK](https://github.com/rantegraph/rante-login-sdk)
too, including FedCM sign-ins in Chrome and Edge.

The SDK is a thin layer over two libraries: [PyJWT](https://pyjwt.readthedocs.io/) (with `cryptography`) does every
JWT and key operation, and [requests](https://requests.readthedocs.io/) does HTTP. It works with any web framework and
needs Python 3.10 or later.

## Install

The package isn't on PyPI. Install it from GitHub:

```sh
pip install "rante-login-sdk @ git+https://github.com/rantegraph/rante-login-sdk-python"
```

## Register your app

1. Sign in to the Rante Portal and register an app at <https://portal.rante.com/dev/apps>.
2. On the app's page, turn on Rante Login and add your redirect URI, for example
   `https://shop.example.com/auth/rante/callback`. Use `http://localhost:3000/auth/rante/callback` for the example
   in this repository.
3. Choose which information your site asks for (at least **Name**).
4. Choose the website type:
   - **Server-side website** (recommended for this SDK): your server proves itself with a Signed JWT key linked to
     the app.
     1. Make a key pair:
        `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem`, or
        `-algorithm EC -pkeyopt ec_paramgen_curve:P-256` for ES256.
     2. Make the public key: `openssl pkey -in private.pem -pubout -out public.pem`.
     3. At <https://portal.rante.com/dev/apikeys>, create a key with the **Signed JWT (RS256 or ES256)** method and paste
        `public.pem`.
     4. Link the key to the app, and note its prefix (`rk_live_…`).

     `private.pem` stays on your server.
   - **Browser-only website**: no key. The SDK sends only the PKCE verifier.
5. Copy the app's **Application (client) ID**.

## Sign people in

The example uses Flask; any framework works the same way.

```python
from pathlib import Path
from rante_login import RanteLoginClient, SigningKey

rante = RanteLoginClient(
    os.environ["RANTE_LOGIN_CLIENT_ID"],
    "https://shop.example.com/auth/rante/callback",
    # A server-side website. Leave signing_key out for a browser-only website.
    signing_key=SigningKey(os.environ["RANTE_LOGIN_KEY_PREFIX"], Path("private.pem").read_bytes()),
)

# 1. Send the browser to Rante Login, and keep the rest of the request in the server-side session.
@app.get("/auth/rante/sign-in")
def sign_in():
    auth = rante.create_authorization_request()
    session["rante_request"] = {"state": auth.state, "nonce": auth.nonce, "code_verifier": auth.code_verifier}
    return redirect(auth.url)

# 2. At the redirect URI: check the response, exchange the code and validate the ID token.
@app.get("/auth/rante/callback")
def callback():
    expected = session.pop("rante_request", None)  # each request is used once
    result = rante.handle_callback(request.args, expected)
    # result.claims["sub"] is the person's ID on your website. It's pairwise: the same for your organization's apps,
    # and different for other organizations.
```

`handle_callback` raises a `RanteLoginError` unless all of these hold:

- `state` matches;
- the response came from Rante Login (`iss`, [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207));
- the token endpoint accepted the code;
- the ID token is valid. Specifically:
  - its RS256 signature checks out with the key that its `kid` names in Rante Login's JWKS;
  - `iss` is `https://login.rante.com/common/v2.0`;
  - `aud` is your client ID (and `azp`, when present);
  - `nonce` matches;
  - `exp` hasn't passed (a minute of clock skew is allowed);
  - `iat` and `sub` are present.

Rante Login releases an email address only once the person has verified it.

### Sign-ins started by the browser SDK

Your page can show the "Sign in with Rante" button instead, using the browser SDK with `serverSide: true`:

- **Redirect sign-ins:** the SDK keeps the PKCE verifier, state and nonce in the `rante_login_pkce`,
  `rante_login_state` and `rante_login_nonce` cookies. Read them at the redirect URI, then clear them:

  ```python
  from rante_login import BROWSER_SDK_COOKIES, RanteLoginClient

  expected = RanteLoginClient.from_browser_sdk_cookies(request.cookies)  # or the Cookie header
  result = rante.handle_callback(request.args, expected)
  for name in BROWSER_SDK_COOKIES.values():
      response.delete_cookie(name, path="/")
  ```

- **FedCM sign-ins** (Chrome and Edge): the ID token comes back to the page, which posts it to your server. Because
  the page could choose any nonce, issue one per session on the server, and pass it to
  `RanteLogin.renderButton(element, { nonce })`. Then check the token against it:

  ```python
  claims = rante.validate_id_token(request.json["idToken"], nonce=session["rante_nonce"])
  ```

### Userinfo

```python
userinfo = rante.fetch_userinfo(result.access_token, expected_subject=result.claims["sub"])
```

The access token from the code exchange lasts 15 minutes. FedCM sign-ins return no access token.

## Registering people with their Rante account

A person's first "Sign in with Rante" on your website is their sign-up, like "Sign up with Google". Create your
website's account from the claims they agreed to share, keyed by `sub`. Every later sign-in finds the same account, so
your website needs no sign-up form and no password of its own.

```python
# After handle_callback (redirect) or validate_id_token (FedCM): these claims are validated.
claims = result.claims
account = db.accounts.find_one(rante_sub=claims["sub"])
if account is None:
    account = db.accounts.insert(rante_sub=claims["sub"], name=claims.get("name"), email=claims.get("email"))
```

- **Key the account on `sub`, never on email.** Email can change, and Rante shares it only once it's verified. If you
  accept more than one sign-in provider, key on the issuer and `sub` together.
- **`sub` is pairwise:** the same for every app of your organization, different for other organizations.
- **Linking an existing account:** have the person sign in to that account first, then store their `sub` on it. Don't
  link accounts because their emails match.
- **Ask only for what you need.** You choose the items in the Portal. Optional items may be missing, so give them
  defaults.

The example does this on every sign-in and shows the result under "Your account on this website". It keeps
its accounts in memory, so they are gone when the server restarts.

## API

| | |
|---|---|
| `RanteLoginClient(client_id, redirect_uri, *, scope=, signing_key=, issuer=, session=, timeout=, clock_skew=)` | `scope` defaults to `openid profile email`; request only scopes whose information the app asks for. `signing_key` is a `SigningKey(key_prefix, private_key)`: PEM text or bytes, or a `cryptography` key; RSA of at least 2048 bits (RS256) or EC P-256 (ES256). `session` is a `requests.Session`. |
| `create_authorization_request(*, nonce=, prompt=, login_hint=, max_age=)` | Returns an `AuthorizationRequest` with `url`, `state`, `nonce` and `code_verifier`. |
| `handle_callback(params, expected)` | `params` is the redirect's query: `request.args`, `request.GET`, a mapping, the URL or the query string. `expected` is an `AuthorizationRequest`, an `ExpectedTransaction`, or a mapping. Returns a `SignInResult` with `claims`, `id_token`, `access_token`, `token_type`, `expires_in` and `scope`. |
| `exchange_code(code, code_verifier)` | The token request on its own. Returns the token response. |
| `validate_id_token(id_token, *, nonce)` | Returns the claims. |
| `fetch_userinfo(access_token, *, expected_subject=None)` | Returns the userinfo claims. |
| `RanteLoginClient.from_browser_sdk_cookies(cookies)` | Returns an `ExpectedTransaction`, or `None` when a cookie is missing. |
| `client_authentication` | `"private_key_jwt"` or `"none"`. |

### Errors

Every failure is a `RanteLoginError` with a stable `code`, a `message`, and a `status` when the error came from Rante
Login:

| Code | Meaning |
|---|---|
| `invalid_configuration` | A constructor setting is wrong; the message says which. |
| `missing_transaction` | No `expected` values: the session or the browser SDK's cookies are gone. They last 10 minutes and must be on the redirect URI's origin. |
| `state_mismatch`, `issuer_mismatch`, `invalid_request` | The response doesn't belong to this sign-in, didn't come from Rante Login, or is malformed. |
| `access_denied`, `login_required`, `consent_required`, … | Rante Login's own error. `access_denied` means the person cancelled. |
| `invalid_client` | The token endpoint refused the app's authentication. Check the key prefix, that the key is linked to the app and not expired, and that the private key matches. A browser-only app must not have a key. |
| `invalid_grant` | The code was used already, is older than 60 seconds, or doesn't match the redirect URI or the PKCE verifier. |
| `invalid_id_token` | The ID token failed a check; the message says which. |
| `invalid_token`, `userinfo_subject_mismatch`, `userinfo_failed` | Userinfo refused the access token, answered for another person, or failed. |
| `discovery_failed`, `network_error`, `invalid_token_response`, `token_request_failed` | Rante Login couldn't be reached, or answered in an unexpected way. |

## Example

[`examples/flask`](examples/flask) is a small Flask website that signs people in three ways:

- the browser SDK's button, with FedCM in Chrome and Edge;
- the browser SDK's button with the redirect flow, elsewhere;
- a sign-in link that works without JavaScript, where the server starts the sign-in.

It also shows the person's claims and their userinfo, and sends a Content Security Policy that allows the browser SDK
and FedCM.

```sh
python -m venv .venv
.venv/bin/pip install -e . -r examples/flask/requirements.txt    # Windows: .venv\Scripts\pip ...
cd examples/flask
RANTE_LOGIN_CLIENT_ID=… RANTE_LOGIN_KEY_PREFIX=rk_live_… RANTE_LOGIN_PRIVATE_KEY_FILE=../../private.pem ../../.venv/bin/python app.py
```

Then open <http://localhost:3000>. In PowerShell, set the variables first, for example
`$env:RANTE_LOGIN_CLIENT_ID = '…'`.

| Variable | Default | Meaning |
|---|---|---|
| `RANTE_LOGIN_CLIENT_ID` | (required) | The app's Application (client) ID. |
| `RANTE_LOGIN_REDIRECT_URI` | `http://localhost:3000/auth/rante/callback` | Exactly as registered. The example handles the callback at its path, and listens on its port. |
| `RANTE_LOGIN_KEY_PREFIX`, `RANTE_LOGIN_PRIVATE_KEY_FILE` | (none) | Server-side websites: the Signed JWT key's prefix, and its PEM private key. |
| `RANTE_LOGIN_SCOPE` | `openid profile email` | |
| `PORT`, `HOST` | the redirect URI's port, `127.0.0.1` | |
| `SESSION_SECRET` | random at each start | Signs Flask's session cookie. |

Open the site on the redirect URI's origin: browsers keep the sign-in cookies per host, so `localhost` and `127.0.0.1`
don't mix.

The example uses Flask's development server, with its request log turned off because it would record the
authorization code. Use a WSGI server such as Gunicorn or Waitress in production.

## Tests

```sh
pip install -e ".[test]"
pytest
```

The tests run offline. `tests/idp.py` is a local OpenID provider shaped like Rante Login:

- it publishes discovery and a JWKS, with keys generated for each run;
- it issues codes, and checks each token request: PKCE, the redirect URI, and the app's `private_key_jwt` assertion
  (algorithm, `kid`, `iss`, `sub`, `aud`, lifetime, a `jti` used once);
- it signs ID tokens, and serves userinfo.

The tests cover:

- successful sign-ins with RS256, ES256 and PKCE alone;
- every refusal: state, issuer, nonce, audience, `azp`, expiry, a foreign key, HS256 and `alg: none`;
- userinfo, configuration errors and network errors.

## Verified against Rante Login

On 9 November 2026 this version and its example signed in against the live `login.rante.com`, with a test app
registered in the Rante Portal and a real Rante account:

| Sign-in | App type | Client authentication |
|---|---|---|
| Redirect, started by the browser SDK's button | Server-side website | `private_key_jwt` with an RS256 key |
| Redirect, started by the server | Server-side website | `private_key_jwt` with an ES256 key |
| Redirect, started by the server | Browser-only website | none: PKCE alone |
| FedCM in Microsoft Edge | Browser-only website | none: the browser hands over the ID token |

In every run the server validated the ID token: the signature against the JWKS, `iss`, `aud` and `azp`, the nonce
and the expiry. The redirect runs also checked that:

- the browser SDK's cookies were cleared after a sign-in its button started;
- userinfo, called after the RS256 sign-in, returned the ID token's `sub`;
- signing out of the example worked.

The offline tests passed, and so did 21 checks against the running example (refusals, escaping and Origin checks).

## Production notes

- **HTTPS:** register an `https` redirect URI, and keep the state, nonce and verifier on the server.
- **Logs:** don't log the redirect URI's query: it carries the one-time code.
- **Signing out:** signing out of your website doesn't sign the person out of Rante.
- **Redirect URIs:** Rante Login accepts only `https`, or `http://localhost` / `http://127.0.0.1` with the exact
  port.
- **Grants:** it has no refresh tokens and no device code flow.

## License

[MIT](LICENSE)
