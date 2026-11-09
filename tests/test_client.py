from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from idp import LocalIdp

from rante_login import (
    BROWSER_SDK_COOKIES,
    ExpectedTransaction,
    RanteLoginClient,
    RanteLoginError,
    SigningKey,
)

WEB_CLIENT = "11111111-2222-4333-8444-555555555555"
BROWSER_CLIENT = "66666666-7777-4888-9999-aaaaaaaaaaaa"
# The fake key prefixes, split so secret scanners don't take them for Stripe restricted keys (rk_live_ + 24 characters).
RSA_PREFIX = "rk_live_" + "0123456789abcdef01234567"
EC_PREFIX = "rk_live_" + "89abcdef0123456789abcdef"
REDIRECT_URI = "http://localhost:3000/auth/rante/callback"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
RSA_PEM = RSA_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.fixture(scope="module")
def idp():
    server = LocalIdp()
    server.register_client(WEB_CLIENT, "Web", {RSA_PREFIX: RSA_KEY.public_key(), EC_PREFIX: EC_KEY.public_key()})
    server.register_client(BROWSER_CLIENT, "BrowserOnly")
    yield server
    server.close()


def web_client(idp, **overrides):
    options = {"issuer": idp.issuer, "signing_key": SigningKey(RSA_PREFIX, RSA_PEM), **overrides}
    return RanteLoginClient(WEB_CLIENT, REDIRECT_URI, **options)


def authorize(idp, request, client_id, claims=None):
    """The authorize step, as the test IdP sees it: a code bound to the request's PKCE challenge and nonce."""
    params = {name: values[0] for name, values in parse_qs(urlsplit(request.url).query).items()}
    return idp.issue_code(client_id=client_id, redirect_uri=params["redirect_uri"], code_challenge=params["code_challenge"],
                          nonce=params["nonce"], claims=claims or {"sub": "pairwise-subject-1", "name": "Test Person"})


def last_token_form(idp):
    return {name: values[0] for name, values in [r for r in idp.requests if r["path"].endswith("/token")][-1]["form"].items()}


def assert_code(code, call, *args, **kwargs):
    with pytest.raises(RanteLoginError) as caught:
        call(*args, **kwargs)
    assert caught.value.code == code, caught.value.message
    return caught.value


class TestCreateAuthorizationRequest:
    def test_builds_the_authorize_url_with_pkce_state_and_nonce(self, idp):
        request = web_client(idp).create_authorization_request()
        url = urlsplit(request.url)
        assert f"{url.scheme}://{url.netloc}{url.path}" == idp.endpoints["authorization"]
        params = {name: values[0] for name, values in parse_qs(url.query).items()}
        assert sorted(params) == ["client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri",
                                  "response_type", "scope", "state"]
        assert params["client_id"] == WEB_CLIENT
        assert params["response_type"] == "code"
        assert params["redirect_uri"] == REDIRECT_URI
        assert params["scope"] == "openid profile email"
        assert params["code_challenge_method"] == "S256"
        expected_challenge = base64.urlsafe_b64encode(hashlib.sha256(request.code_verifier.encode()).digest()).rstrip(b"=")
        assert params["code_challenge"] == expected_challenge.decode()
        assert params["state"] == request.state and params["nonce"] == request.nonce
        assert len(request.code_verifier) == 43
        other = web_client(idp).create_authorization_request()
        assert other.state != request.state and other.nonce != request.nonce and other.code_verifier != request.code_verifier

    def test_passes_nonce_prompt_login_hint_and_max_age_and_refuses_bad_ones(self, idp):
        client = web_client(idp)
        request = client.create_authorization_request(nonce="server-nonce-1", prompt="login",
                                                      login_hint="person@example.com", max_age=0)
        params = {name: values[0] for name, values in parse_qs(urlsplit(request.url).query).items()}
        assert request.nonce == params["nonce"] == "server-nonce-1"
        assert params["prompt"] == "login" and params["login_hint"] == "person@example.com" and params["max_age"] == "0"
        assert_code("invalid_request", client.create_authorization_request, nonce="has space")
        assert_code("invalid_request", client.create_authorization_request, prompt="none login")
        assert_code("invalid_request", client.create_authorization_request, prompt="always")
        assert_code("invalid_request", client.create_authorization_request, max_age=-1)


class TestHandleCallback:
    def test_server_side_website_signs_in_with_a_private_key_jwt_rs256_assertion(self, idp):
        client = web_client(idp)
        assert client.client_authentication == "private_key_jwt"
        request = client.create_authorization_request()
        code = authorize(idp, request, WEB_CLIENT)
        result = client.handle_callback(f"{REDIRECT_URI}?{urlencode({'code': code, 'state': request.state, 'iss': idp.issuer})}", request)
        assert result.claims["sub"] == "pairwise-subject-1"
        assert result.claims["name"] == "Test Person"
        assert result.claims["nonce"] == request.nonce
        assert result.token_type == "Bearer" and result.id_token and result.access_token

        form = last_token_form(idp)
        assert form["grant_type"] == "authorization_code"
        assert form["redirect_uri"] == REDIRECT_URI
        assert form["client_id"] == WEB_CLIENT
        assert form["code_verifier"] == request.code_verifier
        assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        header, payload = idp.last_assertion["header"], idp.last_assertion["payload"]
        assert header["alg"] == "RS256" and header["kid"] == RSA_PREFIX
        assert payload["iss"] == payload["sub"] == WEB_CLIENT
        assert payload["aud"] == idp.endpoints["token"]
        assert payload["exp"] - payload["iat"] <= 300
        assert len(payload["jti"]) == 36

    def test_es256_keys_sign_es256_assertions(self, idp):
        client = web_client(idp, signing_key=SigningKey(EC_PREFIX, EC_KEY))
        request = client.create_authorization_request()
        result = client.handle_callback({"code": authorize(idp, request, WEB_CLIENT), "state": request.state, "iss": idp.issuer}, request)
        assert result.claims["sub"] == "pairwise-subject-1"
        assert idp.last_assertion["header"]["alg"] == "ES256"
        assert idp.last_assertion["header"]["kid"] == EC_PREFIX

    def test_browser_only_website_sends_no_client_credential(self, idp):
        client = RanteLoginClient(BROWSER_CLIENT, REDIRECT_URI, issuer=idp.issuer)
        assert client.client_authentication == "none"
        request = client.create_authorization_request()
        result = client.handle_callback({"code": authorize(idp, request, BROWSER_CLIENT), "state": request.state, "iss": idp.issuer},
                                        {"state": request.state, "nonce": request.nonce, "code_verifier": request.code_verifier})
        assert result.claims["aud"] == BROWSER_CLIENT
        form = last_token_form(idp)
        assert "client_assertion" not in form and "client_assertion_type" not in form and "client_secret" not in form

    def test_refuses_bad_responses_before_any_token_request(self, idp):
        client = web_client(idp)
        request = client.create_authorization_request()
        code = authorize(idp, request, WEB_CLIENT)
        before = len(idp.requests)
        assert_code("state_mismatch", client.handle_callback, {"code": code, "state": "another", "iss": idp.issuer}, request)
        assert_code("issuer_mismatch", client.handle_callback, {"code": code, "state": request.state}, request)
        assert_code("issuer_mismatch", client.handle_callback,
                    {"code": code, "state": request.state, "iss": "https://login.example.com/common/v2.0"}, request)
        assert_code("invalid_request", client.handle_callback,
                    {"code": code, "state": [request.state, request.state], "iss": idp.issuer}, request)
        assert_code("missing_transaction", client.handle_callback, {"code": code, "state": request.state, "iss": idp.issuer}, None)
        assert_code("missing_transaction", client.handle_callback, {"code": code, "state": request.state, "iss": idp.issuer},
                    {"state": request.state})
        assert_code("invalid_request", client.handle_callback, {"state": request.state, "iss": idp.issuer}, request)
        assert len(idp.requests) == before

    def test_reports_the_providers_error(self, idp):
        client = web_client(idp)
        request = client.create_authorization_request()
        error = assert_code("access_denied", client.handle_callback,
                            {"error": "access_denied", "error_description": "The person cancelled the sign-in.",
                             "state": request.state, "iss": idp.issuer}, request)
        assert error.message == "The person cancelled the sign-in."

    def test_token_endpoint_errors_keep_their_code_and_status(self, idp):
        client = web_client(idp)
        request = client.create_authorization_request()
        params = {"code": authorize(idp, request, WEB_CLIENT), "state": request.state, "iss": idp.issuer}
        client.handle_callback(params, request)
        error = assert_code("invalid_grant", client.handle_callback, params, request)
        assert error.status == 400

    def test_a_key_that_is_not_linked_to_the_app_gets_invalid_client(self, idp):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client = web_client(idp, signing_key=SigningKey("rk_live_" + "f" * 24, other))
        request = client.create_authorization_request()
        error = assert_code("invalid_client", client.handle_callback,
                            {"code": authorize(idp, request, WEB_CLIENT), "state": request.state, "iss": idp.issuer}, request)
        assert error.status == 401


class TestValidateIdToken:
    NONCE = "expected-nonce"

    def valid(self, idp, **claims):
        return idp.mint_id_token({"aud": WEB_CLIENT, "azp": WEB_CLIENT, "nonce": self.NONCE, **claims})

    def test_accepts_a_valid_token(self, idp):
        claims = web_client(idp).validate_id_token(self.valid(idp, name="Test Person"), nonce=self.NONCE)
        assert claims["sub"] == "pairwise-subject-1" and claims["name"] == "Test Person"

    def test_refuses_tokens_that_fail_any_check(self, idp):
        client = web_client(idp)
        now = int(time.time())
        stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        def b64(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

        body = {"iss": idp.issuer, "sub": "s", "aud": WEB_CLIENT, "azp": WEB_CLIENT, "iat": now, "exp": now + 600, "nonce": self.NONCE}
        hs256_input = f"{b64({'alg': 'HS256', 'kid': 'test-key-1', 'typ': 'JWT'})}.{b64(body)}"
        hs256 = f"{hs256_input}.{base64.urlsafe_b64encode(hmac.new(b'secret', hs256_input.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()}"
        cases = {
            "another key, same kid": idp.mint_id_token({"aud": WEB_CLIENT, "nonce": self.NONCE}, key=stranger),
            "unknown kid": idp.mint_id_token({"aud": WEB_CLIENT, "nonce": self.NONCE}, key=stranger, kid="not-a-rante-key"),
            "another issuer": self.valid(idp, iss="https://login.example.com/common/v2.0"),
            "another audience": self.valid(idp, aud="99999999-2222-4333-8444-555555555555", azp=None),
            "another azp": self.valid(idp, azp="99999999-2222-4333-8444-555555555555"),
            "expired": self.valid(idp, iat=now - 1200, exp=now - 600),
            "another nonce": self.valid(idp, nonce="other-nonce"),
            "no nonce": self.valid(idp, nonce=None),
            "no sub": self.valid(idp, sub=None),
            "HS256": hs256,
            "alg none": f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(body)}.",
            "not a JWT": "not-a-jwt",
        }
        for name, token in cases.items():
            with pytest.raises(RanteLoginError) as caught:
                client.validate_id_token(token, nonce=self.NONCE)
            assert caught.value.code == "invalid_id_token", f"{name}: {caught.value.message}"
        assert_code("invalid_request", client.validate_id_token, self.valid(idp), nonce="")

    def test_allows_a_minute_of_clock_skew(self, idp):
        now = int(time.time())
        web_client(idp).validate_id_token(self.valid(idp, iat=now - 630, exp=now - 30), nonce=self.NONCE)

    def test_uses_a_key_that_rante_login_adds_later(self, idp):
        added = idp.add_signing_key("test-key-2")
        token = idp.mint_id_token({"aud": WEB_CLIENT, "nonce": self.NONCE}, key=added["private_key"], kid="test-key-2")
        assert web_client(idp).validate_id_token(token, nonce=self.NONCE)["sub"] == "pairwise-subject-1"


class TestFetchUserinfo:
    def test_returns_the_claims_and_checks_the_sub(self, idp):
        client = web_client(idp)
        request = client.create_authorization_request()
        result = client.handle_callback({"code": authorize(idp, request, WEB_CLIENT), "state": request.state, "iss": idp.issuer}, request)
        userinfo = client.fetch_userinfo(result.access_token, expected_subject=result.claims["sub"])
        assert userinfo == {"sub": "pairwise-subject-1", "name": "Test Person"}
        sent = [r for r in idp.requests if r["path"].endswith("/userinfo")][-1]
        assert sent["headers"]["Authorization"] == f"Bearer {result.access_token}"
        assert_code("userinfo_subject_mismatch", client.fetch_userinfo, result.access_token, expected_subject="someone-else")
        error = assert_code("invalid_token", client.fetch_userinfo, "expired-or-unknown")
        assert error.status == 401


class TestBrowserSdkCookies:
    def test_reads_the_three_cookies_from_a_mapping_or_a_cookie_header(self):
        expected = ExpectedTransaction(state="s1", nonce="n1", code_verifier="v" * 43)
        cookies = {BROWSER_SDK_COOKIES["state"]: "s1", BROWSER_SDK_COOKIES["nonce"]: "n1", BROWSER_SDK_COOKIES["code_verifier"]: "v" * 43}
        assert RanteLoginClient.from_browser_sdk_cookies(cookies) == expected
        header = f"other=1; rante_login_pkce={'v' * 43}; rante_login_state=s1; rante_login_nonce=n1"
        assert RanteLoginClient.from_browser_sdk_cookies(header) == expected
        assert RanteLoginClient.from_browser_sdk_cookies({"rante_login_state": "s1"}) is None
        assert RanteLoginClient.from_browser_sdk_cookies(None) is None


class TestConfiguration:
    def test_refuses_bad_settings(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        p384 = ec.generate_private_key(ec.SECP384R1())
        public_pem = RSA_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        bad = {
            "client ID": dict(client_id="my-app"),
            "http redirect URI": dict(redirect_uri="http://shop.example.com/callback"),
            "redirect URI with a fragment": dict(redirect_uri="https://shop.example.com/callback#x"),
            "scope without openid": dict(scope="profile email"),
            "unknown scope": dict(scope="openid offline_access"),
            "key prefix": dict(signing_key=SigningKey("my-key", RSA_PEM)),
            "RSA 1024": dict(signing_key=SigningKey(RSA_PREFIX, weak)),
            "EC P-384": dict(signing_key=SigningKey(RSA_PREFIX, p384)),
            "a public key": dict(signing_key=SigningKey(RSA_PREFIX, public_pem)),
            "http issuer": dict(issuer="http://login.example.com/common/v2.0"),
        }
        for name, options in bad.items():
            arguments = {"client_id": WEB_CLIENT, "redirect_uri": REDIRECT_URI, **options}
            with pytest.raises(RanteLoginError) as caught:
                RanteLoginClient(arguments.pop("client_id"), arguments.pop("redirect_uri"), **arguments)
            assert caught.value.code == "invalid_configuration", name

    def test_normalizes_the_client_id_and_redirect_uri_like_the_browser_sdk(self):
        client = RanteLoginClient(WEB_CLIENT.upper(), "HTTPS://Shop.Example.com/Auth/Callback")
        assert client.client_id == WEB_CLIENT
        assert client.redirect_uri == "https://shop.example.com/Auth/Callback"
        assert client.issuer == "https://login.rante.com/common/v2.0"

    def test_refuses_a_discovery_document_that_names_another_issuer(self, idp):
        idp.discovery_issuer = "https://login.example.com/common/v2.0"
        try:
            assert_code("discovery_failed", web_client(idp).create_authorization_request)
        finally:
            idp.discovery_issuer = idp.issuer

    def test_reports_an_unreachable_provider_as_network_error(self):
        client = RanteLoginClient(WEB_CLIENT, REDIRECT_URI, issuer="http://127.0.0.1:9/common/v2.0", timeout=2)
        assert_code("network_error", client.create_authorization_request)
