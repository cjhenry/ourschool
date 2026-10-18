# OurSchool - Homeschool Management System
# Copyright (C) 2025 Dustan Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""OIDC provider and login tests; no external network requests."""

import base64
import hashlib
import json
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import settings
from app.models.user import User, UserRole
from app.routers import oidc, auth


@pytest.fixture()
def provider(monkeypatch, db_session, admin_token):
    oidc._cache.clear()
    auth._login_failures.clear()
    for key, value in {
        "oidc_enabled": True,
        "oidc_issuer_url": "https://id.example",
        "oidc_client_id": "school",
        "oidc_client_secret": None,
        "oidc_redirect_uri": "http://localhost/auth/oidc/callback",
        "oidc_auto_provision": False,
        "oidc_user_match_claim": "email",
        "oidc_allow_unverified_email": False,
        "oidc_default_role": "student",
        "oidc_disable_local_login": False,
    }.items():
        monkeypatch.setattr(settings, key, value)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public["kid"] = "test"
    suffix = uuid.uuid4().hex
    user = User(
        username="oidc-" + suffix,
        email=suffix + "@example.com",
        first_name="Test",
        last_name="User",
        hashed_password="!",
        role=UserRole.STUDENT,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    state = {"key": key, "user": user, "claims": {}, "posts": []}

    async def send(client, request, **kwargs):
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            data = {
                "issuer": settings.oidc_issuer_url,
                "authorization_endpoint": "https://id.example/authorize",
                "token_endpoint": "https://id.example/token",
                "jwks_uri": "https://id.example/jwks",
            }
            data.update(state.get("discovery", {}))
        elif path == "/jwks":
            state["jwks_calls"] = state.get("jwks_calls", 0) + 1
            data = {"keys": [public]}
        elif path == "/userinfo":
            data = state["userinfo"]
        elif path == "/token":
            state["posts"].append(parse_qs(request.content.decode()))
            claims = {
                "iss": "https://id.example",
                "aud": "school",
                "sub": "subject",
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
                "nonce": state["nonce"],
                "email": user.email.upper(),
                "email_verified": True,
                "preferred_username": user.username.upper(),
            }
            claims.update(state["claims"])
            for name in state.get("omit_claims", []):
                claims.pop(name, None)
            data = {
                "access_token": "provider-access-token",
                "id_token": jwt.encode(
                    claims, state["key"], algorithm="RS256", headers={"kid": "test"}
                ),
            }
        else:
            raise AssertionError(f"Unexpected provider request: {path}")
        return httpx.Response(200, json=data, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return state


def begin(client, provider):
    response = client.get("/api/auth/oidc/start")
    assert response.status_code == 200, response.text
    query = parse_qs(urlsplit(response.json()["authorization_url"]).query)
    provider["nonce"] = query["nonce"][0]
    return query


def finish(client, query):
    return client.post(
        "/api/auth/oidc/callback",
        json={"code": "test-code", "state": query["state"][0]},
    )


def test_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "oidc_enabled", False)
    monkeypatch.setattr(settings, "oidc_disable_local_login", True)
    assert client.get("/api/auth/oidc/config").json() == {
        "enabled": False,
        "button_label": "Sign in with SSO",
        "local_login_enabled": True,
    }
    assert client.get("/api/auth/oidc/start").status_code == 404
    assert finish(client, {"state": ["bad"]}).status_code == 404
    assert (
        client.post(
            "/api/auth/login", data={"username": "absent", "password": "bad"}
        ).status_code
        == 401
    )


def test_missing_config(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "oidc_client_id", "")
    assert client.get("/api/auth/oidc/start").status_code == 503
    assert finish(client, {"state": ["bad"]}).status_code == 503


def test_start_and_login(client, provider):
    query = begin(client, provider)
    assert query["code_challenge_method"] == ["S256"]
    cookie = client.cookies.get(oidc._COOKIE)
    transaction = jwt.decode(
        cookie, settings.secret_key, algorithms=["HS256"], audience="school"
    )
    assert (
        query["code_challenge"][0]
        == base64.urlsafe_b64encode(
            hashlib.sha256(transaction["verifier"].encode()).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    response = finish(client, query)
    assert response.status_code == 200, response.text
    assert response.json()["session"]["user"]["id"] == provider["user"].id
    assert provider["posts"][0]["code_verifier"] == [transaction["verifier"]]
    assert oidc._COOKIE not in client.cookies
    assert (
        client.get(
            "/api/auth/session",
            headers={"Authorization": "Bearer " + response.json()["access_token"]},
        ).status_code
        == 200
    )


def test_username_match(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "oidc_user_match_claim", "preferred_username")
    provider["claims"] = {"email_verified": False}
    assert finish(client, begin(client, provider)).status_code == 200


@pytest.mark.parametrize(
    "claims",
    [
        {"nonce": "wrong"},
        {"aud": "wrong"},
        {"iss": "https://wrong.example"},
        {"email_verified": False},
        {"email_verified": "true"},
        {"email": "unknown@example.com"},
        {"exp": 1},
        {"iat": int(time.time()) + 600},
        {"aud": ["school", "other"]},
        {"azp": "other"},
    ],
)
def test_invalid_claims(client, provider, claims):
    provider["claims"] = claims
    response = finish(client, begin(client, provider))
    assert response.status_code == 401
    assert oidc._COOKIE not in client.cookies


def test_bad_signature(client, provider):
    provider["key"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert finish(client, begin(client, provider)).status_code == 401


@pytest.mark.parametrize("missing", [False, True])
def test_state(client, provider, missing):
    query = begin(client, provider)
    if missing:
        client.cookies.clear()
    else:
        query["state"] = ["wrong"]
    assert finish(client, query).status_code == 401
    assert not provider["posts"]


def test_inactive(client, provider, db_session):
    provider["user"].is_active = False
    db_session.commit()
    assert finish(client, begin(client, provider)).status_code == 401


def test_provision(client, provider, monkeypatch, db_session):
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    suffix = uuid.uuid4().hex
    provider["claims"] = {
        "email": suffix + "@example.com",
        "preferred_username": suffix,
    }
    response = finish(client, begin(client, provider))
    assert response.status_code == 200, response.text
    user = db_session.query(User).filter(User.username == suffix).one()
    assert user.role == UserRole.STUDENT
    assert user.is_active and not user.must_change_password


def test_collision(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    provider["claims"] = {"email": "other@example.com"}
    assert finish(client, begin(client, provider)).status_code == 401


def test_disable_password(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "oidc_disable_local_login", True)
    assert not client.get("/api/auth/oidc/config").json()["local_login_enabled"]
    assert (
        client.post(
            "/api/auth/login", data={"username": "x", "password": "y"}
        ).status_code
        == 403
    )


def test_discovery_mismatch(client, provider):
    provider["discovery"] = {"issuer": "https://wrong.example"}
    assert client.get("/api/auth/oidc/start").status_code == 503


def test_jwks_rotation(client, provider):
    oidc._cache["https://id.example/jwks"] = (time.monotonic() + 300, {"keys": []})
    assert finish(client, begin(client, provider)).status_code == 200
    assert provider["jwks_calls"] == 1


@pytest.mark.parametrize("subject", ["subject", "different-subject"])
def test_userinfo(client, provider, subject):
    provider["discovery"] = {"userinfo_endpoint": "https://id.example/userinfo"}
    provider["omit_claims"] = ["email", "email_verified"]
    provider["userinfo"] = {
        "sub": subject,
        "email": provider["user"].email,
        "email_verified": True,
    }
    response = finish(client, begin(client, provider))
    assert response.status_code == (200 if subject == "subject" else 401)


@pytest.mark.parametrize("method", ["client_secret_basic", "client_secret_post"])
def test_confidential_client(client, provider, monkeypatch, method):
    monkeypatch.setattr(settings, "oidc_client_secret", "test-only-client-secret")
    provider["discovery"] = {"token_endpoint_auth_methods_supported": [method]}
    assert finish(client, begin(client, provider)).status_code == 200
    assert ("client_secret" in provider["posts"][0]) == (method == "client_secret_post")


def test_secure_cookie(client, provider, monkeypatch):
    monkeypatch.setattr(
        settings, "oidc_redirect_uri", "https://school.example/auth/oidc/callback"
    )
    response = client.get("/api/auth/oidc/start")
    cookie = response.headers["set-cookie"]
    for value in (
        "HttpOnly",
        "Secure",
        "SameSite=lax",
        "Path=/api/auth/oidc",
        "Max-Age=600",
    ):
        assert value in cookie


def test_expired_cookie(client, provider):
    query = begin(client, provider)
    transaction = jwt.decode(
        client.cookies.get(oidc._COOKIE),
        settings.secret_key,
        algorithms=["HS256"],
        audience="school",
    )
    transaction["exp"] = 1
    client.cookies.clear()
    client.cookies.set(
        oidc._COOKIE,
        jwt.encode(transaction, settings.secret_key, algorithm="HS256"),
        path=oidc._PATH,
    )
    assert finish(client, query).status_code == 401
    assert not provider["posts"]


def test_unverified_override(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "oidc_allow_unverified_email", True)
    provider["claims"] = {"email_verified": False}
    assert finish(client, begin(client, provider)).status_code == 200


def test_admin_provisioning_refused(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    monkeypatch.setattr(settings, "oidc_default_role", "admin")
    assert client.get("/api/auth/oidc/start").status_code == 503


def test_password_change_requirement_preserved(client, provider, db_session):
    provider["user"].must_change_password = True
    db_session.commit()
    response = finish(client, begin(client, provider))
    assert response.status_code == 200
    assert response.json()["session"]["user"]["must_change_password"]
    headers = {"Authorization": "Bearer " + response.json()["access_token"]}
    assert client.get("/api/auth/session", headers=headers).status_code == 200
    assert client.get("/api/users/", headers=headers).status_code == 403


def test_userinfo_verified_email(client, provider):
    provider["discovery"] = {"userinfo_endpoint": "https://id.example/userinfo"}
    provider["omit_claims"] = ["email_verified"]
    provider["userinfo"] = {"sub": "subject", "email_verified": True}
    assert finish(client, begin(client, provider)).status_code == 200
