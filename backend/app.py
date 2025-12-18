import os
from functools import wraps

import requests
import jwt
from jwt import PyJWKClient

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ========= CORS =========
CORS(app, resources={r"/*": {"origins": ["http://localhost:5500"]}})

# ========= Keycloak Config =========
KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8081")
REALM = os.getenv("KEYCLOAK_REALM", "secured-library")
AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "backend-client")

OIDC_CONFIG_URL = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/.well-known/openid-configuration"

_oidc = None
_jwks_client = None

# ========= DB Config =========
DATABASE_URL = os.getenv("DATABASE_URL")  # postgresql://postgres@localhost:5432/secured_library
engine = create_engine(DATABASE_URL, pool_pre_ping=True) if DATABASE_URL else None


# ========= Keycloak Helpers =========
def get_oidc():
    global _oidc, _jwks_client
    if _oidc is None:
        r = requests.get(OIDC_CONFIG_URL, timeout=10)
        r.raise_for_status()
        _oidc = r.json()
        _jwks_client = PyJWKClient(_oidc["jwks_uri"])
    return _oidc, _jwks_client


def extract_roles(payload: dict) -> set:
    roles = set(payload.get("realm_access", {}).get("roles", []))
    ra = payload.get("resource_access", {})
    for _, data in ra.items():
        roles.update(data.get("roles", []))
    return roles


def require_roles(required=None):
    required = set(required or [])

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify(error="Missing bearer token"), 401

            token = auth.split(" ", 1)[1].strip()

            try:
                _, jwks_client = get_oidc()
                signing_key = jwks_client.get_signing_key_from_jwt(token).key

                payload = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    audience=[AUDIENCE, "frontend-client", "backend-client", "account"],
                    options={"verify_exp": True},
                )

                user_roles = extract_roles(payload)

                if required and not (user_roles & required):
                    return jsonify(error="Forbidden (insufficient role)"), 403

                request.user = {
                    "username": payload.get("preferred_username"),
                    "roles": sorted(list(user_roles)),
                }

            except jwt.ExpiredSignatureError:
                return jsonify(error="Token expired"), 401
            except Exception as e:
                return jsonify(error="Invalid token", details=str(e)), 401

            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ========= Utils =========
def _ensure_db():
    if engine is None:
        return False, (jsonify(error="DATABASE_URL is not set"), 500)
    return True, None


# ========= Public =========
@app.get("/public")
def public():
    return jsonify(message="Public endpoint"), 200


@app.get("/me")
@require_roles()
def me():
    return jsonify(user=request.user), 200


# ========= BOOKS (✔️ مربوطة بالـ PostgreSQL) =========
@app.get("/books")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def list_books():
    ok, resp = _ensure_db()
    if not ok:
        return resp

    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, title, author, available
                    FROM books
                    ORDER BY id
                """)
            )
            books = [dict(row) for row in result.mappings().all()]

        return jsonify(books=books), 200

    except SQLAlchemyError as e:
        return jsonify(error="DB error", details=str(e)), 500


@app.post("/books")
@require_roles(["crud_no_delete", "full_crud"])
def create_book():
    ok, resp = _ensure_db()
    if not ok:
        return resp

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    author = (data.get("author") or "").strip()

    if not title or not author:
        return jsonify(error="title and author are required"), 400

    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("""
                    INSERT INTO books (title, author)
                    VALUES (:t, :a)
                    RETURNING id, title, author, available
                """),
                {"t": title, "a": author},
            )
            book = dict(result.mappings().first())

        return jsonify(book=book), 201

    except SQLAlchemyError as e:
        return jsonify(error="DB error", details=str(e)), 500


@app.delete("/books/<int:book_id>")
@require_roles(["full_crud"])
def delete_book(book_id):
    ok, resp = _ensure_db()
    if not ok:
        return resp

    try:
        with engine.begin() as conn:
            res = conn.execute(
                text("DELETE FROM books WHERE id = :id"),
                {"id": book_id},
            )

        if res.rowcount == 0:
            return jsonify(error="Book not found"), 404

        return jsonify(message=f"Book {book_id} deleted"), 200

    except SQLAlchemyError as e:
        return jsonify(error="DB error", details=str(e)), 500


# ========= RUN =========
if __name__ == "__main__":
    app.run(port=5000, debug=True)
