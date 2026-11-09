"""The Rante Login client: "Sign in with Rante" on a Python server, built on PyJWT and requests.

Rante Login is an OpenID Connect provider (issuer https://login.rante.com/common/v2.0) with:

- the authorization code flow with PKCE (S256), state and nonce, and the ``iss`` response parameter (RFC 9207);
- client authentication by ``private_key_jwt`` (RFC 7523, a Signed JWT key linked to the app) for server-side
  websites, or none (PKCE alone) for browser-only websites;
- RS256 ID tokens, a pairwise ``sub``, and a userinfo endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ISSUER = "https://login.rante.com/common/v2.0"

#: The cookies the Rante Login browser SDK writes with ``serverSide: true`` (SameSite=Lax, 10 minutes, Path=/).
BROWSER_SDK_COOKIES = {"code_verifier": "rante_login_pkce", "state": "rante_login_state", "nonce": "rante_login_nonce"}

_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_ASSERTION_LIFETIME_SECONDS = 60  # Rante Login accepts at most 300.
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_KEY_PREFIX = re.compile(r"rk_live_[0-9a-f]{24}")
_SCOPES = ("openid", "profile", "email", "phone", "address", "rante.organization")
_PROMPTS = ("none", "login", "consent", "select_account")
_ERROR_CODE = re.compile(r"[a-z0-9_]{1,64}")


class RanteLoginError(Exception):
    """Every failure the SDK reports. ``code`` is stable and safe to show; OAuth errors keep their own codes."""

    def __init__(self, code: str, message: str = "", *, status: int | None = None) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.status = status


@dataclass(frozen=True)
class SigningKey:
    """A Signed JWT key linked to the app: its prefix as the Rante Portal shows it, and the private key.

    ``private_key`` is PEM text or bytes, or a ``cryptography`` private key: RSA of at least 2048 bits (RS256) or
    EC P-256 (ES256).
    """

    key_prefix: str
    private_key: Any


@dataclass(frozen=True)
class AuthorizationRequest:
    """Send the browser to ``url``; keep ``state``, ``nonce`` and ``code_verifier`` on the server until it comes back."""

    url: str
    state: str
    nonce: str
    code_verifier: str


@dataclass(frozen=True)
class ExpectedTransaction:
    """What a sign-in must match at the redirect URI."""

    state: str
    nonce: str
    code_verifier: str


@dataclass(frozen=True)
class SignInResult:
    claims: dict[str, Any]
    id_token: str
    access_token: str
    token_type: str
    expires_in: int | None
    scope: str | None


class RanteLoginClient:
    """A Rante Login client for one app.

    :param client_id: the app's Application (client) ID.
    :param redirect_uri: exactly as registered on the app.
    :param scope: default ``openid profile email``.
    :param signing_key: server-side websites: the Signed JWT key linked to the app. Without it the client
        authenticates with PKCE alone (browser-only websites).
    :param issuer: default https://login.rante.com/common/v2.0.
    :param session: a ``requests.Session`` for the calls to Rante Login.
    :param timeout: seconds for each request to Rante Login.
    :param clock_skew: seconds of clock skew allowed for the ID token.
    """

    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        *,
        scope: str = "openid profile email",
        signing_key: SigningKey | None = None,
        issuer: str = ISSUER,
        session: requests.Session | None = None,
        timeout: float = 10.0,
        clock_skew: int = 60,
    ) -> None:
        self.client_id = _normalize_client_id(client_id)
        self.redirect_uri = _normalize_redirect_uri(redirect_uri)
        self.scope = _normalize_scope(scope)
        self.issuer = _normalize_issuer(issuer)
        self._signing_key = _load_signing_key(signing_key) if signing_key is not None else None
        self._session = session or requests.Session()
        self._timeout = timeout
        self._clock_skew = clock_skew
        self._provider: dict[str, Any] | None = None
        self._provider_lock = threading.Lock()

    @property
    def client_authentication(self) -> str:
        """``private_key_jwt`` with the app's Signed JWT key, or ``none`` (PKCE alone)."""
        return "private_key_jwt" if self._signing_key else "none"

    # ------------------------------------------------------------------------------------------------ the flow

    def create_authorization_request(
        self,
        *,
        nonce: str | None = None,
        prompt: str | None = None,
        login_hint: str | None = None,
        max_age: int | None = None,
    ) -> AuthorizationRequest:
        """Starts a sign-in on the server: the URL to send the browser to, and the values to keep until it comes back."""
        nonce = _random_token() if nonce is None else _check_nonce(nonce)
        prompt = _check_prompt(prompt)
        if login_hint is not None and (not isinstance(login_hint, str) or len(login_hint) > 256):
            raise RanteLoginError("invalid_request", "login_hint must be a string of at most 256 characters.")
        if max_age is not None and (isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0):
            raise RanteLoginError("invalid_request", "max_age must be a whole number of seconds.")
        state = _random_token()
        code_verifier = _random_token()
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest()),
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        if login_hint:
            params["login_hint"] = login_hint
        if max_age is not None:
            params["max_age"] = str(max_age)
        endpoint = urlsplit(self._discover()["authorization_endpoint"])
        query = "&".join(part for part in (endpoint.query, urlencode(params)) if part)
        url = urlunsplit((endpoint.scheme, endpoint.netloc, endpoint.path, query, ""))
        return AuthorizationRequest(url=url, state=state, nonce=nonce, code_verifier=code_verifier)

    def handle_callback(self, params: Any, expected: Any) -> SignInResult:
        """Finishes a redirect sign-in at the redirect URI.

        Checks the response against the values kept for it, exchanges the code and validates the ID token.

        :param params: the redirect's query: Flask's ``request.args``, Django's ``request.GET``, a mapping, the full
            URL or the query string.
        :param expected: the ``AuthorizationRequest`` from ``create_authorization_request``, the
            ``ExpectedTransaction`` from ``from_browser_sdk_cookies``, or a mapping with ``state``, ``nonce`` and
            ``code_verifier``.
        """
        query = _read_callback_params(params)
        transaction = _read_expected(expected)
        if transaction is None:
            raise RanteLoginError("missing_transaction", "No sign-in is in progress for this browser, or it expired.")
        if not _safe_equal(query.get("state"), transaction.state):
            raise RanteLoginError("state_mismatch", "The response does not belong to the sign-in this browser started.")
        if query.get("iss") != self.issuer:
            raise RanteLoginError("issuer_mismatch", "The response did not come from Rante Login.")
        error = query.get("error")
        if error:
            raise RanteLoginError(error if _ERROR_CODE.fullmatch(error) else "authorization_failed",
                                  _clean(query.get("error_description")) or error)
        code = query.get("code")
        if not code:
            raise RanteLoginError("invalid_request", "The response has no code.")

        tokens = self.exchange_code(code, transaction.code_verifier)
        claims = self.validate_id_token(tokens["id_token"], nonce=transaction.nonce)
        return SignInResult(
            claims=claims,
            id_token=tokens["id_token"],
            access_token=tokens["access_token"],
            token_type=tokens["token_type"],
            expires_in=tokens.get("expires_in"),
            scope=tokens.get("scope"),
        )

    def exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        """The token request: the code, the PKCE verifier and the app's client authentication."""
        if not _is_text(code) or not _is_text(code_verifier):
            raise RanteLoginError("invalid_request", "code and code_verifier are required.")
        token_endpoint = self._discover()["token_endpoint"]
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": code_verifier,
        }
        if self._signing_key:
            form["client_assertion_type"] = _ASSERTION_TYPE
            form["client_assertion"] = self._client_assertion(token_endpoint)
        response = self._send("POST", token_endpoint, data=form, headers={"Accept": "application/json"})
        body = _read_json(response)
        if response.status_code != 200:
            error = body.get("error") if isinstance(body, dict) else None
            description = body.get("error_description") if isinstance(body, dict) else None
            raise RanteLoginError(error if isinstance(error, str) and _ERROR_CODE.fullmatch(error) else "token_request_failed",
                                  _clean(description) or f"The token endpoint answered {response.status_code}.",
                                  status=response.status_code)
        if (not isinstance(body, dict) or not _is_text(body.get("id_token")) or not _is_text(body.get("access_token"))
                or str(body.get("token_type", "")).lower() != "bearer"):
            raise RanteLoginError("invalid_token_response", "The token response has no ID token or no Bearer access token.")
        return body

    def validate_id_token(self, id_token: str, *, nonce: str) -> dict[str, Any]:
        """Validates an ID token before you trust it, and returns its claims.

        Checks the RS256 signature with the key its ``kid`` names in Rante Login's JWKS, ``iss``, ``aud`` (and
        ``azp``), ``exp`` (with clock skew), ``iat``, ``sub`` and the nonce you expect.
        """
        if not _is_text(nonce):
            raise RanteLoginError("invalid_request", "The expected nonce is required.")
        if not _is_text(id_token):
            raise RanteLoginError("invalid_id_token", "The ID token is missing.")
        jwks: jwt.PyJWKClient = self._discover()["jwks"]
        try:
            signing_key = jwks.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.client_id,
                leeway=self._clock_skew,
                options={"require": ["iss", "aud", "exp", "iat", "sub", "nonce"]},
            )
        except jwt.exceptions.PyJWKClientConnectionError as error:
            raise RanteLoginError("network_error", "Rante Login's signing keys could not be fetched.") from error
        except jwt.exceptions.PyJWTError as error:
            raise RanteLoginError("invalid_id_token", f"The ID token failed validation ({type(error).__name__}).") from error
        if not _safe_equal(claims.get("nonce"), nonce):
            raise RanteLoginError("invalid_id_token", "The ID token was issued for another sign-in (nonce).")
        azp = claims.get("azp")
        audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if (azp is not None and azp != self.client_id) or (azp is None and len(audiences) > 1):
            raise RanteLoginError("invalid_id_token", "The ID token was issued to another app (azp).")
        if not _is_text(claims.get("sub")):
            raise RanteLoginError("invalid_id_token", "The ID token has no sub.")
        return claims

    def fetch_userinfo(self, access_token: str, *, expected_subject: str | None = None) -> dict[str, Any]:
        """The person's claims from the userinfo endpoint, with the access token from the code exchange (15 minutes).

        Pass the ID token's ``sub`` as ``expected_subject``: OpenID Connect requires that both match.
        """
        if not _is_text(access_token):
            raise RanteLoginError("invalid_request", "An access token is required.")
        response = self._send("GET", self._discover()["userinfo_endpoint"],
                              headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"})
        if response.status_code == 401:
            raise RanteLoginError("invalid_token",
                                  "The access token was refused: it expired, or the person removed their consent.",
                                  status=401)
        body = _read_json(response)
        if response.status_code != 200 or not isinstance(body, dict) or not _is_text(body.get("sub")):
            raise RanteLoginError("userinfo_failed", f"The userinfo endpoint answered {response.status_code}.",
                                  status=response.status_code)
        if expected_subject is not None and body["sub"] != expected_subject:
            raise RanteLoginError("userinfo_subject_mismatch", "The userinfo sub is not the ID token's sub.")
        return body

    @staticmethod
    def from_browser_sdk_cookies(cookies: Mapping[str, str] | str | None) -> ExpectedTransaction | None:
        """The values the browser SDK (``serverSide: true``) kept for a redirect sign-in, from the request's cookies.

        ``cookies`` is a mapping such as Flask's ``request.cookies``, or the Cookie header. Returns None when any is
        missing. Clear the three cookies (``BROWSER_SDK_COOKIES``) once read: each sign-in uses them once.
        """
        if isinstance(cookies, str):
            parsed = SimpleCookie()
            try:
                parsed.load(cookies)
            except Exception:  # noqa: BLE001 - a malformed header counts as no cookies
                return None
            values = {name: morsel.value for name, morsel in parsed.items()}
        else:
            values = cookies or {}
        state = values.get(BROWSER_SDK_COOKIES["state"])
        nonce = values.get(BROWSER_SDK_COOKIES["nonce"])
        code_verifier = values.get(BROWSER_SDK_COOKIES["code_verifier"])
        if _is_text(state) and _is_text(nonce) and _is_text(code_verifier):
            return ExpectedTransaction(state=state, nonce=nonce, code_verifier=code_verifier)
        return None

    # ------------------------------------------------------------------------------------------------ internals

    def _discover(self) -> dict[str, Any]:
        """The discovery document, fetched once, and a JWKS client that caches the keys and fetches them again when a
        token names a kid it doesn't know (key rotation), at most every 30 seconds."""
        with self._provider_lock:
            if self._provider is None:
                response = self._send("GET", f"{self.issuer}/.well-known/openid-configuration",
                                      headers={"Accept": "application/json"})
                metadata = _read_json(response)
                if response.status_code != 200 or not isinstance(metadata, dict):
                    raise RanteLoginError("discovery_failed", f"The discovery document answered {response.status_code}.",
                                          status=response.status_code)
                if metadata.get("issuer") != self.issuer:
                    raise RanteLoginError("discovery_failed", "The discovery document names another issuer.")
                for name in ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"):
                    if not _is_text(metadata.get(name)):
                        raise RanteLoginError("discovery_failed", f"The discovery document has no {name}.")
                self._provider = {
                    "authorization_endpoint": metadata["authorization_endpoint"],
                    "token_endpoint": metadata["token_endpoint"],
                    "userinfo_endpoint": metadata["userinfo_endpoint"],
                    "jwks": jwt.PyJWKClient(metadata["jwks_uri"], cache_jwk_set=True, lifespan=600,
                                            timeout=self._timeout),
                }
            return self._provider

    def _client_assertion(self, token_endpoint: str) -> str:
        """private_key_jwt (RFC 7523): a short-lived JWT signed with the app's private key."""
        key, alg, kid = self._signing_key
        now = int(time.time())
        claims = {
            "iss": self.client_id,  # iss and sub: the client ID
            "sub": self.client_id,
            "aud": token_endpoint,  # aud: the token endpoint
            "iat": now,
            "exp": now + _ASSERTION_LIFETIME_SECONDS,
            "jti": str(uuid.uuid4()),  # Rante Login accepts each assertion once
        }
        return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid, "typ": "JWT"})  # kid: the key's prefix

    def _send(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        try:
            return self._session.request(method, url, timeout=self._timeout, allow_redirects=False, **kwargs)
        except requests.RequestException as error:
            raise RanteLoginError("network_error", f"Rante Login could not be reached ({type(error).__name__}).") from error


# ------------------------------------------------------------------------------------------------------ helpers

def _config_error(message: str) -> RanteLoginError:
    return RanteLoginError("invalid_configuration", message)


def _normalize_client_id(value: Any) -> str:
    client_id = value.strip().lower() if isinstance(value, str) else ""
    if not _GUID.fullmatch(client_id):
        raise _config_error("client_id must be the app's Application (client) ID from the Rante Portal.")
    return client_id


def _normalize_redirect_uri(value: Any) -> str:
    """Rante Login matches redirect URIs exactly, and stores them with the scheme and host in lower case."""
    text = value.strip() if isinstance(value, str) else ""
    uri = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*", lambda m: m.group(0).lower(), text)
    try:
        parts = urlsplit(uri)
        loopback = parts.hostname in ("localhost", "127.0.0.1")
        valid = (bool(parts.hostname) and "#" not in uri and parts.username is None and parts.password is None
                 and len(uri) <= 512 and (parts.scheme == "https" or (parts.scheme == "http" and loopback)))
    except ValueError:
        valid = False
    if not valid:
        raise _config_error("redirect_uri must be the absolute https URI registered on the app "
                            "(http only for localhost or 127.0.0.1), without a fragment.")
    return uri


def _normalize_scope(value: Any) -> str:
    parts = value.split() if isinstance(value, str) else []
    if "openid" not in parts or any(part not in _SCOPES for part in parts):
        raise _config_error(f"scope must include openid and only these scopes: {', '.join(_SCOPES)}.")
    return " ".join(dict.fromkeys(parts))


def _normalize_issuer(value: Any) -> str:
    parts = urlsplit(value) if isinstance(value, str) else None
    loopback = parts is not None and parts.hostname in ("localhost", "127.0.0.1")
    if (parts is None or parts.query or parts.fragment
            or not (parts.scheme == "https" or (parts.scheme == "http" and loopback))):
        raise _config_error("issuer must be an https URL.")
    return value.rstrip("/")


def _load_signing_key(signing_key: SigningKey) -> tuple[Any, str, str]:
    if not isinstance(signing_key.key_prefix, str) or not _KEY_PREFIX.fullmatch(signing_key.key_prefix):
        raise _config_error("signing_key.key_prefix must be the key prefix the Rante Portal shows: rk_live_ and 24 hex digits.")
    key = signing_key.private_key
    if isinstance(key, (str, bytes)):
        try:
            key = serialization.load_pem_private_key(key.encode("ascii") if isinstance(key, str) else key, password=None)
        except (ValueError, TypeError) as error:
            raise _config_error(f"signing_key.private_key is not an unencrypted PEM private key: {error}") from error
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
        return key, "RS256", signing_key.key_prefix
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
        return key, "ES256", signing_key.key_prefix
    raise _config_error("signing_key.private_key must be an RSA key of at least 2048 bits (RS256) or an EC P-256 key (ES256).")


def _check_nonce(nonce: Any) -> str:
    if not isinstance(nonce, str) or not re.fullmatch(r"[\x21-\x7e]{1,256}", nonce):
        raise RanteLoginError("invalid_request", "nonce must be 1 to 256 printable ASCII characters without spaces.")
    return nonce


def _check_prompt(prompt: Any) -> str | None:
    if prompt is None or prompt == "":
        return None
    parts = prompt.split() if isinstance(prompt, str) else []
    if not parts or any(part not in _PROMPTS for part in parts) or ("none" in parts and len(parts) > 1):
        raise RanteLoginError("invalid_request", f"prompt must be {', '.join(_PROMPTS)} (none alone).")
    return " ".join(parts)


def _read_callback_params(params: Any) -> dict[str, str | None]:
    """The redirect's parameters. A repeated parameter is refused rather than guessed."""
    if isinstance(params, str):
        query = urlsplit(params).query if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", params) else params.lstrip("?")
        values = parse_qs(query, keep_blank_values=True)

        def getlist(name: str) -> list[str]:
            return values.get(name, [])
    elif hasattr(params, "getlist"):  # Flask/Werkzeug MultiDict, Django QueryDict
        def getlist(name: str) -> list[str]:
            return list(params.getlist(name))
    elif isinstance(params, Mapping):
        def getlist(name: str) -> list[str]:
            value = params.get(name)
            if value is None:
                return []
            return [item for item in value if isinstance(item, str)] if isinstance(value, (list, tuple)) else [value]
    else:
        raise RanteLoginError("invalid_request", "The redirect parameters are missing.")
    out: dict[str, str | None] = {}
    for name in ("code", "state", "iss", "error", "error_description"):
        found = getlist(name)
        if len(found) > 1:
            raise RanteLoginError("invalid_request", f"The response repeats {name}.")
        out[name] = found[0] if found and isinstance(found[0], str) else None
    return out


def _read_expected(expected: Any) -> ExpectedTransaction | None:
    if expected is None:
        return None
    if isinstance(expected, Mapping):
        state, nonce, verifier = expected.get("state"), expected.get("nonce"), expected.get("code_verifier")
    else:
        state = getattr(expected, "state", None)
        nonce = getattr(expected, "nonce", None)
        verifier = getattr(expected, "code_verifier", None)
    if _is_text(state) and _is_text(nonce) and _is_text(verifier):
        return ExpectedTransaction(state=state, nonce=nonce, code_verifier=verifier)
    return None


def _read_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _random_token() -> str:
    return _b64url(secrets.token_bytes(32))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _safe_equal(a: Any, b: Any) -> bool:
    return isinstance(a, str) and isinstance(b, str) and hmac.compare_digest(a.encode(), b.encode())


def _clean(value: Any) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", value)[:300] if isinstance(value, str) else ""


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0
