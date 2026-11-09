"""Sign in with Rante: a Flask website that signs people in with the Rante Login SDK for Python.

Three ways in, all finished and checked on this server:

- "Sign in with Rante" button (static/signin.js): the browser SDK with ``serverSide: true``. In Chrome and Edge it uses
  FedCM and posts the ID token to /auth/rante/fedcm; elsewhere it redirects, and the code comes back to the redirect
  URI with the SDK's ``rante_login_*`` cookies.
- "Sign in without JavaScript" link: /auth/rante/sign-in builds the authorize request here
  (``create_authorization_request``) and keeps its state, nonce and PKCE verifier in the session.
- Either redirect ends at the redirect URI, where ``handle_callback`` exchanges the code (private_key_jwt or PKCE
  alone) and validates the ID token.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, redirect, render_template, request, session

from rante_login import BROWSER_SDK_COOKIES, RanteLoginClient, RanteLoginError, SigningKey

SDK_SRC = "https://login.rante.com/sdk/v1/rante-login.js"
SDK_INTEGRITY = "sha384-2W12/NktCjRqFuXWiUtHr1yEtdrjBlCRWnJ+//FZMiqd1KRX/K+YMWLoMgF9R7wf"

key_prefix = os.environ.get("RANTE_LOGIN_KEY_PREFIX", "").strip()
key_file = os.environ.get("RANTE_LOGIN_PRIVATE_KEY_FILE", "").strip()
if bool(key_prefix) != bool(key_file):
    sys.exit("Set both RANTE_LOGIN_KEY_PREFIX and RANTE_LOGIN_PRIVATE_KEY_FILE (a server-side website), or neither (browser-only).")
try:
    rante = RanteLoginClient(
        os.environ.get("RANTE_LOGIN_CLIENT_ID", ""),
        os.environ.get("RANTE_LOGIN_REDIRECT_URI") or "http://localhost:3000/auth/rante/callback",
        scope=os.environ.get("RANTE_LOGIN_SCOPE") or "openid profile email",
        signing_key=SigningKey(key_prefix, Path(key_file).read_bytes()) if key_file else None,
    )
except (RanteLoginError, OSError) as error:
    sys.exit(str(error))

redirect_parts = urlsplit(rante.redirect_uri)
SITE_ORIGIN = f"{redirect_parts.scheme}://{redirect_parts.netloc}"
CALLBACK_PATH = redirect_parts.path
if CALLBACK_PATH in ("", "/", "/auth/rante/sign-in", "/auth/rante/fedcm", "/auth/sign-out", "/userinfo"):
    sys.exit("Give RANTE_LOGIN_REDIRECT_URI a path of its own, for example /auth/rante/callback.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SESSION_SECRET") or secrets.token_hex(32),
    SESSION_COOKIE_NAME="rante_flask_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SITE_ORIGIN.startswith("https:"),
    PERMANENT_SESSION_LIFETIME=8 * 60 * 60,
    MAX_CONTENT_LENGTH=64 * 1024,
)


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = "; ".join([
        "default-src 'self'",
        "script-src 'self' https://login.rante.com",  # the browser SDK, pinned by its integrity hash
        "connect-src 'self' https://login.rante.com",  # FedCM fetches the identity provider's configuration
        "img-src 'self' data:",
        "style-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ])
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/")
def index():
    if "user" in session:
        page = render_template("signed_in.html", user=session["user"], rows=rows_of(session["user"]["claims"]))
    else:
        # FedCM hands the ID token to the page, so its nonce must be one the page can't choose: issue it here and keep
        # it in the session. The browser SDK sends the same nonce in its redirect flow.
        nonce = session.setdefault("rante_nonce", secrets.token_urlsafe(32))
        page = render_template("signin.html", client_id=rante.client_id, redirect_uri=rante.redirect_uri,
                               scope=rante.scope, nonce=nonce, sdk_src=SDK_SRC, sdk_integrity=SDK_INTEGRITY)
    response = app.make_response(page)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/auth/rante/sign-in")
def sign_in():
    """The server starts the sign-in: no JavaScript needed."""
    try:
        auth = rante.create_authorization_request()
    except RanteLoginError as error:
        return error_page(error)
    session["rante_request"] = {"state": auth.state, "nonce": auth.nonce, "code_verifier": auth.code_verifier}
    return redirect(auth.url, code=303)


def callback():
    """The redirect URI: Rante Login comes back with ?code=...&state=...&iss=... (or ?error=...)."""
    # A sign-in this server started is in the session; one the browser SDK started is in its cookies. Both are used once.
    started = session.pop("rante_request", None)
    from_browser = RanteLoginClient.from_browser_sdk_cookies(request.cookies)
    by_server = bool(started) and started["state"] == request.args.get("state")
    try:
        result = rante.handle_callback(request.args, started if by_server else (from_browser or started))
        start_session({
            "claims": result.claims,
            "access_token": result.access_token,
            "method": f"{'Redirect started by the server' if by_server else 'Redirect started by the browser SDK'}, "
                      f"{rante.client_authentication}",
        })
        response = redirect("/", code=303)
    except RanteLoginError as error:
        response = error_page(error)
    except Exception:  # noqa: BLE001 - shown as a generic error, logged with details
        app.logger.exception("Sign-in failed")
        response = error_page(None)
    for name in BROWSER_SDK_COOKIES.values():
        response.delete_cookie(name, path="/")
    return response


app.add_url_rule(CALLBACK_PATH, "callback", callback)


@app.post("/auth/rante/fedcm")
def fedcm_sign_in():
    """FedCM: the page posts the ID token the browser's account dialog returned."""
    if request.headers.get("Origin") != SITE_ORIGIN:
        return jsonify(error="origin_not_allowed"), 403
    try:
        nonce = session.get("rante_nonce")
        if not nonce:
            raise RanteLoginError("missing_transaction", "This browser session has no sign-in nonce. Reload the page.")
        body = request.get_json(silent=True)
        claims = rante.validate_id_token(body.get("idToken") if isinstance(body, dict) else None, nonce=nonce)
        start_session({"claims": claims, "method": "FedCM"})
        return "", 204
    except RanteLoginError as error:
        app.logger.warning("FedCM sign-in failed: %s: %s", error.code, error.message)
        return jsonify(error=error.code), 400


@app.get("/userinfo")
def userinfo():
    """The person's claims from Rante Login's userinfo endpoint, with the access token from the code exchange."""
    user = session.get("user")
    if not user:
        return redirect("/", code=303)
    if not user.get("access_token"):
        return render_template("message.html", title="Userinfo",
                               message="FedCM sign-ins return only an ID token, so there is no access token to call userinfo with.")
    try:
        claims = rante.fetch_userinfo(user["access_token"], expected_subject=user["claims"]["sub"])
    except RanteLoginError as error:
        return error_page(error)
    response = app.make_response(render_template("userinfo.html", rows=rows_of(claims)))
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/auth/sign-out")
def sign_out():
    origin = request.headers.get("Origin")
    if origin and origin != SITE_ORIGIN:
        return "", 403
    # Signs out of this website only; the person stays signed in to Rante.
    session.clear()
    return redirect("/", code=303)


def start_session(user: dict) -> None:
    """A fresh session for the person who signed in: the old values, and the used nonce, are dropped."""
    session.clear()
    session.permanent = True
    session["user"] = {**user, "signed_in_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def rows_of(claims: dict) -> dict[str, str]:
    return {name: json.dumps(value) if isinstance(value, (dict, list)) else str(value) for name, value in claims.items()}


def error_page(error: RanteLoginError | None):
    if error:
        # Log the reason, never the code, the cookies or a token.
        app.logger.warning("Sign-in failed: %s: %s", error.code, error.message)
    message = ("The sign-in was cancelled on the Rante Login page." if error and error.code == "access_denied"
               else error.message if error else "Something went wrong on this server. Its log has the details.")
    return app.make_response((render_template("error.html", code=error.code if error else "server_error", message=message),
                              400 if error else 500))


if __name__ == "__main__":
    print(f"Sign in with Rante (Flask example): {SITE_ORIGIN}/ - client {rante.client_id}, {rante.client_authentication}", flush=True)
    # The development server's request log would write every callback URL, authorization code included.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT") or redirect_parts.port or (443 if redirect_parts.scheme == "https" else 80)))
