import os
import uuid
from functools import wraps
from datetime import datetime

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

# ======================
# CORS (frontend origin)
# ======================
# Support both localhost and 127.0.0.1 (common cause of "Failed to fetch")
FRONTEND_ORIGINS = os.getenv(
    "FRONTEND_ORIGINS",
    "http://localhost:5500,http://127.0.0.1:5500"
).split(",")

CORS(
    app,
    resources={r"/*": {"origins": [o.strip() for o in FRONTEND_ORIGINS if o.strip()]}},
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "DELETE", "OPTIONS"],
)

# ======================
# Keycloak Config
# ======================
# If Keycloak older (has /auth), set KEYCLOAK_BASE_URL=http://localhost:8081/auth
KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8081").rstrip("/")
REALM = os.getenv("KEYCLOAK_REALM", "secured-library")

# Token audience: usually "frontend-client". We accept multiple for flexibility.
AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "frontend-client")

OIDC_CONFIG_URL = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/.well-known/openid-configuration"

_oidc = None
_jwks_client = None

# ======================
# DB Config (Postgres)
# ======================
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is missing. Example:\n"
        "DATABASE_URL=postgresql://postgres:postgres123@localhost:5432/secured_library"
    )

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)


def init_database():
    """
    Creates tables if they don't exist (idempotent).
    NOTE: This does NOT DROP data. For a full reset run library.sql manually.
    """
    try:
        with engine.begin() as conn:
            # 1) Users (synced from Keycloak / upserted on login)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS app_users (
                  keycloak_id UUID PRIMARY KEY,
                  username     VARCHAR(150) NOT NULL UNIQUE,
                  email        VARCHAR(255) UNIQUE,
                  first_name   VARCHAR(150),
                  last_name    VARCHAR(150),
                  roles        TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
                  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
                  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))

            # 2) Books
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS books (
                  id          BIGSERIAL PRIMARY KEY,
                  title       VARCHAR(255) NOT NULL,
                  author      VARCHAR(255) NOT NULL,
                  available   BOOLEAN NOT NULL DEFAULT TRUE,
                  created_by  UUID NULL REFERENCES app_users(keycloak_id) ON DELETE SET NULL,
                  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))

            # 3) Notes
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS notes (
                  id         BIGSERIAL PRIMARY KEY,
                  user_id    UUID NOT NULL REFERENCES app_users(keycloak_id) ON DELETE CASCADE,
                  username   VARCHAR(150) NOT NULL,
                  title      VARCHAR(255) NOT NULL,
                  content    TEXT,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))

            # Indexes
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_notes_user_created ON notes(user_id, created_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_books_created_at ON books(created_at DESC)"))

            # updated_at triggers
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION set_updated_at()
                RETURNS TRIGGER AS $$
                BEGIN
                  NEW.updated_at = NOW();
                  RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
            """))

            conn.execute(text("DROP TRIGGER IF EXISTS trg_app_users_updated_at ON app_users"))
            conn.execute(text("""
                CREATE TRIGGER trg_app_users_updated_at
                BEFORE UPDATE ON app_users
                FOR EACH ROW EXECUTE FUNCTION set_updated_at();
            """))

            conn.execute(text("DROP TRIGGER IF EXISTS trg_books_updated_at ON books"))
            conn.execute(text("""
                CREATE TRIGGER trg_books_updated_at
                BEFORE UPDATE ON books
                FOR EACH ROW EXECUTE FUNCTION set_updated_at();
            """))

            conn.execute(text("DROP TRIGGER IF EXISTS trg_notes_updated_at ON notes"))
            conn.execute(text("""
                CREATE TRIGGER trg_notes_updated_at
                BEFORE UPDATE ON notes
                FOR EACH ROW EXECUTE FUNCTION set_updated_at();
            """))

            # Seed books if empty
            count = conn.execute(text("SELECT COUNT(*) FROM books")).scalar() or 0
            if count == 0:
                conn.execute(text("""
                    INSERT INTO books (title, author) VALUES
                    ('Human Security Principles', 'Dr. Alex Johnson'),
                    ('Zero Trust Architecture', 'Sarah Miller'),
                    ('Privacy Engineering', 'Michael Chen'),
                    ('Secure Software Development', 'Emily Davis')
                """))

        print("Database schema ensured (Postgres).")
    except Exception as e:
        print(f"Database init failed: {e}")
        raise


init_database()

# ======================
# Keycloak Helpers
# ======================
def get_oidc():
    global _oidc, _jwks_client
    if _oidc is None:
        r = requests.get(OIDC_CONFIG_URL, timeout=10)
        r.raise_for_status()
        _oidc = r.json()
        _jwks_client = PyJWKClient(_oidc["jwks_uri"])
        print(f"Connected to Keycloak issuer: {_oidc.get('issuer')}")
    return _oidc, _jwks_client


def extract_roles(payload: dict) -> list:
    roles = set(payload.get("realm_access", {}).get("roles", []))
    ra = payload.get("resource_access", {})
    for _, data in ra.items():
        roles.update(data.get("roles", []))
    return sorted(list(roles))


def upsert_user_in_db(user: dict):
    """
    Sync user info into app_users (so notes/books can FK to it).
    """
    try:
        # Keycloak "sub" is UUID string. Validate/cast.
        kc_id = str(uuid.UUID(user["user_id"]))
        roles = user.get("roles", [])

        with engine.begin() as conn:
            conn.execute(
                text("""
                    INSERT INTO app_users (keycloak_id, username, email, first_name, last_name, roles, enabled)
                    VALUES (CAST(:kid AS uuid), :username, :email, :first_name, :last_name, :roles, :enabled)
                    ON CONFLICT (keycloak_id) DO UPDATE SET
                      username   = EXCLUDED.username,
                      email      = EXCLUDED.email,
                      first_name = EXCLUDED.first_name,
                      last_name  = EXCLUDED.last_name,
                      roles      = EXCLUDED.roles,
                      enabled    = EXCLUDED.enabled,
                      updated_at = NOW()
                """),
                {
                    "kid": kc_id,
                    "username": user.get("username"),
                    "email": user.get("email"),
                    "first_name": user.get("first_name"),
                    "last_name": user.get("last_name"),
                    "roles": roles,
                    "enabled": True,
                },
            )
    except Exception:
        # Don't block auth if DB sync fails; log and continue.
        import traceback
        traceback.print_exc()


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
                oidc, jwks_client = get_oidc()
                signing_key = jwks_client.get_signing_key_from_jwt(token).key

                payload = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    audience=[AUDIENCE, "frontend-client", "backend-client", "account"],
                    issuer=oidc["issuer"],
                    options={"verify_exp": True, "verify_iss": True},
                )

                user_roles = extract_roles(payload)

                if required and not (set(user_roles) & required):
                    return jsonify(error="Forbidden (insufficient role)"), 403

                request.user = {
                    "username": payload.get("preferred_username", "unknown"),
                    "roles": user_roles,
                    "user_id": payload.get("sub", ""),
                    "email": payload.get("email"),
                    "first_name": payload.get("given_name") or payload.get("name"),
                    "last_name": payload.get("family_name"),
                }

                # Keep app_users table in sync
                upsert_user_in_db(request.user)

            except jwt.ExpiredSignatureError:
                return jsonify(error="Token expired"), 401
            except Exception as e:
                return jsonify(error="Invalid token", details=str(e)), 401

            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ======================
# Public Endpoints
# ======================
@app.get("/public")
def public():
    return jsonify(message="Public endpoint - No authentication required"), 200


@app.get("/me")
@require_roles()
def me():
    return jsonify(user=request.user), 200


@app.get("/health")
def health_check():
    keycloak_status = "connected" if _oidc else "disconnected"
    db_status = "connected"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"disconnected ({e})"

    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": db_status,
        "keycloak": keycloak_status,
        "frontend_origins": FRONTEND_ORIGINS,
        "endpoints": {
            "public": "/public",
            "user_info": "/me",
            "health": "/health",
            "books": ["GET /books", "POST /books", "DELETE /books/:id"],
            "notes": ["GET /notes", "POST /notes", "DELETE /notes/:id"],
            "stats": "GET /stats",
            "users": "GET /users (admin)"
        }
    }), 200


# ======================
# USERS (Admin helper)
# ======================
@app.get("/users")
@require_roles(["full_crud"])
def list_users():
    try:
        with engine.connect() as conn:
            res = conn.execute(text("""
                SELECT keycloak_id, username, email, first_name, last_name, roles, enabled, created_at, updated_at
                FROM app_users
                ORDER BY created_at DESC
                LIMIT 500
            """))
            users = [dict(r) for r in res.mappings().all()]
        return jsonify(users=users), 200
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


# ======================
# BOOKS
# ======================
@app.get("/books")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def list_books():
    try:
        with engine.connect() as conn:
            res = conn.execute(text("""
                SELECT id, title, author, available, created_by, created_at, updated_at
                FROM books
                ORDER BY id
            """))
            books = [dict(row) for row in res.mappings().all()]
        return jsonify(books=books), 200
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


@app.post("/books")
@require_roles(["crud_no_delete", "full_crud"])
def create_book():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    author = (data.get("author") or "").strip()

    if not title or not author:
        return jsonify(error="title and author are required"), 400

    try:
        with engine.begin() as conn:
            row = conn.execute(
                text("""
                    INSERT INTO books (title, author, created_by)
                    VALUES (:t, :a, CAST(:uid AS uuid))
                    RETURNING id, title, author, available, created_by, created_at, updated_at
                """),
                {"t": title, "a": author, "uid": request.user["user_id"]},
            ).mappings().first()

        return jsonify(book=dict(row)), 201
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500
    except Exception as e:
        return jsonify(error="Unexpected error", details=str(e)), 500


@app.delete("/books/<int:book_id>")
@require_roles(["full_crud"])
def delete_book(book_id):
    try:
        with engine.begin() as conn:
            res = conn.execute(text("DELETE FROM books WHERE id = :id"), {"id": book_id})

        if res.rowcount == 0:
            return jsonify(error="Book not found"), 404

        return jsonify(message=f"Book {book_id} deleted successfully"), 200
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


# ======================
# NOTES
# ======================
@app.get("/notes")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def list_notes():
    try:
        with engine.connect() as conn:
            res = conn.execute(text("""
                SELECT id, title, content, created_at, updated_at
                FROM notes
                WHERE user_id = CAST(:user_id AS uuid)
                ORDER BY created_at DESC
            """), {"user_id": request.user["user_id"]})
            notes = [dict(row) for row in res.mappings().all()]
        return jsonify(notes=notes), 200
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


@app.post("/notes")
@require_roles(["crud_no_delete", "full_crud"])
def create_note():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()

    if not title:
        return jsonify(error="title is required"), 400

    try:
        with engine.begin() as conn:
            row = conn.execute(text("""
                INSERT INTO notes (user_id, username, title, content)
                VALUES (CAST(:uid AS uuid), :username, :title, :content)
                RETURNING id, title, content, created_at, updated_at
            """), {
                "uid": request.user["user_id"],
                "username": request.user["username"],
                "title": title,
                "content": content
            }).mappings().first()

        return jsonify(note=dict(row)), 201
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


@app.delete("/notes/<int:note_id>")
@require_roles(["full_crud"])
def delete_note(note_id):
    try:
        with engine.begin() as conn:
            res = conn.execute(text("""
                DELETE FROM notes
                WHERE id = :id AND user_id = CAST(:user_id AS uuid)
            """), {"id": note_id, "user_id": request.user["user_id"]})

        if res.rowcount == 0:
            return jsonify(error="Note not found or not authorized to delete"), 404

        return jsonify(message=f"Note {note_id} deleted successfully"), 200
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


# ======================
# STATS
# ======================
@app.get("/stats")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def get_stats():
    try:
        with engine.connect() as conn:
            total_books = conn.execute(text("SELECT COUNT(*) FROM books")).scalar() or 0
            available_books = conn.execute(text("SELECT COUNT(*) FROM books WHERE available = TRUE")).scalar() or 0
            user_notes = conn.execute(
                text("SELECT COUNT(*) FROM notes WHERE user_id = CAST(:user_id AS uuid)"),
                {"user_id": request.user["user_id"]}
            ).scalar() or 0

        return jsonify(stats={
            "user": request.user["username"],
            "books": {"total": total_books, "available": available_books},
            "notes": {"user_notes": user_notes},
            "timestamp": datetime.now().isoformat()
        }), 200
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


# ======================
# Errors
# ======================
@app.errorhandler(404)
def not_found(_):
    return jsonify(error="Endpoint not found"), 404


@app.errorhandler(500)
def internal_error(_):
    return jsonify(error="Internal server error"), 500


if __name__ == "__main__":
    print("=" * 60)
    print("SECURE LIBRARY BACKEND - HUMAN SECURITY SYSTEM")
    print("=" * 60)
    print("Server URL: http://127.0.0.1:5000")
    print("Frontend Origins:", FRONTEND_ORIGINS)
    print(f"Keycloak URL: {KEYCLOAK_BASE_URL}")
    print(f"Realm: {REALM}")
    print(f"DB: {DATABASE_URL}")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
