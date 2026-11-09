"""A local OpenID provider for the tests, shaped like Rante Login.

It serves discovery, JWKS, token and userinfo endpoints on 127.0.0.1. It issues codes that the tests hand it (standing
in for the authorize step), checks each token request (PKCE, redirect URI, client authentication, single-use
assertions) and signs ID tokens with a key generated for the run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class LocalIdp:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.issuer = f"{self.origin}/common/v2.0"
        self.endpoints = {
            "authorization": f"{self.origin}/common/oauth2/v2.0/authorize",
            "token": f"{self.origin}/common/oauth2/v2.0/token",
            "userinfo": f"{self.origin}/common/oidc/v2.0/userinfo",
            "jwks": f"{self.origin}/common/discovery/v2.0/keys",
        }
        self.discovery_issuer = self.issuer
        self.signing_keys = [self._new_signing_key("test-key-1")]
        self.clients: dict[str, dict[str, Any]] = {}
        self.codes: dict[str, dict[str, Any]] = {}
        self.access_tokens: dict[str, dict[str, Any]] = {}
        self.used_assertions: set[str] = set()
        self.requests: list[dict[str, Any]] = []
        self.last_assertion: dict[str, Any] | None = None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    @staticmethod
    def _new_signing_key(kid: str) -> dict[str, Any]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
        jwk.update(kid=kid, alg="RS256", use="sig")
        return {"kid": kid, "private_key": private_key, "jwk": jwk}

    def add_signing_key(self, kid: str) -> dict[str, Any]:
        key = self._new_signing_key(kid)
        self.signing_keys.append(key)
        return key

    def register_client(self, client_id: str, client_type: str, keys: dict[str, Any] | None = None) -> None:
        """client_type is Web (keys: {prefix: public key}) or BrowserOnly."""
        self.clients[client_id] = {"type": client_type, "keys": keys or {}}

    def issue_code(self, *, client_id: str, redirect_uri: str, code_challenge: str, nonce: str, claims: dict[str, Any]) -> str:
        """Stands in for the authorize step: a code for these values."""
        code = secrets.token_hex(32)
        self.codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "code_challenge": code_challenge,
                            "nonce": nonce, "claims": claims}
        return code

    def mint_id_token(self, claims: dict[str, Any] | None = None, *, key: Any = None, kid: str | None = None,
                      alg: str = "RS256") -> str:
        """An ID token like Rante Login's. Override any claim (None removes it), or sign with another key or kid."""
        now = int(time.time())
        payload = {"iss": self.issuer, "sub": "pairwise-subject-1", "iat": now, "exp": now + 600, "auth_time": now}
        payload.update(claims or {})
        payload = {name: value for name, value in payload.items() if value is not None}
        return jwt.encode(payload, key if key is not None else self.signing_keys[0]["private_key"], algorithm=alg,
                          headers={"kid": kid or self.signing_keys[0]["kid"], "typ": "JWT"})

    # ---------------------------------------------------------------------------------------------- the server

    def _handler(self):
        idp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # quiet test output
                pass

            def _send(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802 - http.server's naming
                idp.requests.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
                if self.path == "/common/v2.0/.well-known/openid-configuration":
                    return self._send(200, {
                        "issuer": idp.discovery_issuer,
                        "authorization_endpoint": idp.endpoints["authorization"],
                        "token_endpoint": idp.endpoints["token"],
                        "userinfo_endpoint": idp.endpoints["userinfo"],
                        "jwks_uri": idp.endpoints["jwks"],
                        "response_types_supported": ["code"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"],
                        "code_challenge_methods_supported": ["S256"],
                        "authorization_response_iss_parameter_supported": True,
                    })
                if self.path == "/common/discovery/v2.0/keys":
                    return self._send(200, {"keys": [key["jwk"] for key in idp.signing_keys]})
                if self.path == "/common/oidc/v2.0/userinfo":
                    authorization = self.headers.get("Authorization", "")
                    claims = idp.access_tokens.get(authorization[7:]) if authorization.startswith("Bearer ") else None
                    if not claims:
                        return self._send(401, {}, {"WWW-Authenticate": 'Bearer error="invalid_token"'})
                    return self._send(200, claims)
                return self._send(404, {})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                form = {name: values for name, values in parse_qs(self.rfile.read(length).decode(), keep_blank_values=True).items()}
                idp.requests.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "form": form})
                if self.path != "/common/oauth2/v2.0/token":
                    return self._send(404, {})
                status, body = idp._token(form, dict(self.headers))
                return self._send(status, body)

        return Handler

    def _token(self, form: dict[str, list[str]], headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        def one(name: str) -> str | None:
            values = form.get(name)
            return values[0] if values and len(values) == 1 else None

        def refuse(status: int, error: str) -> tuple[int, dict[str, Any]]:
            return status, {"error": error, "error_description": f"test IdP: {error}"}

        client_id = one("client_id")
        client = self.clients.get(client_id or "")
        if client is None or "client_secret" in form or "Authorization" in headers:
            return refuse(401, "invalid_client")
        if client["type"] == "Web":
            assertion = one("client_assertion")
            if one("client_assertion_type") != ASSERTION_TYPE or not assertion:
                return refuse(401, "invalid_client")
            try:
                header = jwt.get_unverified_header(assertion)
                key = client["keys"].get(header.get("kid"))
                if key is None:
                    return refuse(401, "invalid_client")
                payload = jwt.decode(assertion, key, algorithms=["RS256", "ES256"], issuer=client_id,
                                     audience=self.endpoints["token"], options={"require": ["sub", "jti", "exp"]})
            except jwt.PyJWTError:
                return refuse(401, "invalid_client")
            if payload["sub"] != client_id or payload["exp"] - payload.get("iat", 0) > 300 or payload["jti"] in self.used_assertions:
                return refuse(401, "invalid_client")
            self.used_assertions.add(payload["jti"])
            self.last_assertion = {"header": header, "payload": payload}
        elif "client_assertion" in form or "client_assertion_type" in form:
            return refuse(401, "invalid_client")
        issued = self.codes.pop(one("code") or "", None)
        verifier = one("code_verifier") or ""
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if (issued is None or issued["client_id"] != client_id or issued["redirect_uri"] != one("redirect_uri")
                or issued["code_challenge"] != challenge):
            return refuse(400, "invalid_grant")
        id_token = self.mint_id_token({"aud": client_id, "azp": client_id, "nonce": issued["nonce"], **issued["claims"]})
        access_token = str(uuid.uuid4())
        self.access_tokens[access_token] = {"sub": issued["claims"]["sub"], "name": issued["claims"].get("name")}
        return 200, {"access_token": access_token, "token_type": "Bearer", "expires_in": 900, "id_token": id_token,
                     "scope": "openid profile email"}
