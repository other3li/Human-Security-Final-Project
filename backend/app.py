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

# ✅ CORS (عشان الفرونت على 5500 ينادي الباك على 5000)
CORS(app, resources={r"/*": {"origins": ["http://localhost:5500"]}})

# ========= Keycloak Config =========
KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8081")
REALM = os.getenv("KEYCLOAK_REALM", "secured-library")
AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "backend-client")

OIDC_CONFIG_URL = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/.well-known/openid-configuration"

_oidc = None
_jwks_client = None

# ========= DB Config =========
DATABASE_URL = os.getenv("DATABASE_URL")  # مثال: postgresql://postgres@localhost:5432/secured_library
engine = None
if DATABASE_URL:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)


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

    # resource_access ممكن تحتوي roles لكل client
    ra = payload.get("resource_access", {})
    for _, data in ra.items():
        roles.update(data.get("roles", []))

    return roles


def require_roles(required=None):
    """
    ✅ التحقق من التوكن داخل try
    ✅ استدعاء الـ endpoint نفسه برا try (عشان أي Error في الـ endpoint مايتسمّاش Invalid token)
    """
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

                # ✅ حل مشكلة Audience: نقبل أكتر من قيمة
                acceptable_audiences = [AUDIENCE, "frontend-client", "backend-client", "account"]

                payload = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    audience=acceptable_audiences,
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

            # ✅ هنا استدعاء الـ endpoint بعد ما التوكن اتأكد
            return fn(*args, **kwargs)

        return wrapper

    return decorator


@app.get("/public")
def public():
    return jsonify(message="Public endpoint"), 200


@app.get("/me")
@require_roles()
def me():
    return jsonify(user=getattr(request, "user", {})), 200


# ====== أمثلة RBAC (حسب الأدوار اللي عندك) ======

@app.get("/books")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def list_books():
    return jsonify(message="GET /books allowed"), 200


@app.post("/books")
@require_roles(["crud_no_delete", "full_crud"])
def create_book():
    return jsonify(message="POST /books allowed"), 201


@app.delete("/books/<int:book_id>")
@require_roles(["full_crud"])
def delete_book(book_id):
    return jsonify(message=f"DELETE /books/{book_id} allowed"), 200


# ====== Notes (PostgreSQL) ======

def _ensure_db():
    if engine is None:
        return False, (jsonify(error="DATABASE_URL is not set"), 500)
    return True, None


@app.get("/notes")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def list_my_notes():
    ok, resp = _ensure_db()
    if not ok:
        return resp

    username = request.user.get("username")
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, title, content, owner_username, created_at
                    FROM notes
                    WHERE owner_username = :u
                    ORDER BY id DESC
                """),
                {"u": username},
            )

            # ✅ أهم سطر: رجّعها dict عشان JSON
            rows = result.mappings().all()
            notes = [dict(r) for r in rows]

        return jsonify(user=username, notes=notes), 200

    except SQLAlchemyError as e:
        return jsonify(error="DB error", details=str(e)), 500


@app.post("/notes")
@require_roles(["crud_no_delete", "full_crud"])
def create_note():
    ok, resp = _ensure_db()
    if not ok:
        return resp

    username = request.user.get("username")
    data = request.get_json(silent=True) or {}

    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()

    if not title or not content:
        return jsonify(error="title and content are required"), 400

    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("""
                    INSERT INTO notes (title, content, owner_username)
                    VALUES (:t, :c, :u)
                    RETURNING id, title, content, owner_username, created_at
                """),
                {"t": title, "c": content, "u": username},
            )

            created = result.mappings().first()
            created_note = dict(created) if created else {}

        return jsonify(note=created_note), 201

    except SQLAlchemyError as e:
        return jsonify(error="DB error", details=str(e)), 500


@app.delete("/notes/<int:note_id>")
@require_roles(["full_crud"])
def delete_note(note_id):
    ok, resp = _ensure_db()
    if not ok:
        return resp

    username = request.user.get("username")
    try:
        with engine.begin() as conn:
            # ✅ امسح نوت المستخدم نفسه فقط
            res = conn.execute(
                text("DELETE FROM notes WHERE id=:id AND owner_username=:u"),
                {"id": note_id, "u": username},
            )

        if res.rowcount == 0:
            return jsonify(error="Not found or not allowed"), 404

        return jsonify(message=f"Note {note_id} deleted"), 200

    except SQLAlchemyError as e:
        return jsonify(error="DB error", details=str(e)), 500


if __name__ == "__main__":
    app.run(port=5000, debug=True)
