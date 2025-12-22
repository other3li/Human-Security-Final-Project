import os
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
# ✅ مهم: اسمح بـ localhost و 127.0.0.1 عشان اختلاف السيرفر اللي بيشغل الفرونت
CORS(
    app,
    resources={r"/*": {"origins": ["http://localhost:5500", "http://127.0.0.1:5500"]}},
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "DELETE", "OPTIONS"],
)

# ======================
# Keycloak Config
# ======================
KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8081").rstrip("/")
REALM = os.getenv("KEYCLOAK_REALM", "secured-library")
AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "frontend-client")

OIDC_CONFIG_URL = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/.well-known/openid-configuration"

_oidc = None
_jwks_client = None

# ======================
# DB Config
# ======================
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///secure_library.db"

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
DIALECT = engine.dialect.name  # 'postgresql' or 'sqlite' ...


def init_database():
    """Create tables if they don't exist (handles PostgreSQL vs SQLite)"""
    try:
        with engine.begin() as conn:
            if DIALECT == "postgresql":
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS books (
                        id SERIAL PRIMARY KEY,
                        title VARCHAR(255) NOT NULL,
                        author VARCHAR(255) NOT NULL,
                        available BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))

                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS notes (
                        id SERIAL PRIMARY KEY,
                        user_id VARCHAR(255) NOT NULL,
                        username VARCHAR(255) NOT NULL,
                        title VARCHAR(255) NOT NULL,
                        content TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            else:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS books (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title VARCHAR(255) NOT NULL,
                        author VARCHAR(255) NOT NULL,
                        available BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))

                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS notes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id VARCHAR(255) NOT NULL,
                        username VARCHAR(255) NOT NULL,
                        title VARCHAR(255) NOT NULL,
                        content TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))

            # seed books if empty
            result = conn.execute(text("SELECT COUNT(*) FROM books"))
            if (result.scalar() or 0) == 0:
                conn.execute(text("""
                    INSERT INTO books (title, author) VALUES
                    ('Human Security Principles', 'Dr. Alex Johnson'),
                    ('Zero Trust Architecture', 'Sarah Miller'),
                    ('Privacy Engineering', 'Michael Chen'),
                    ('Secure Software Development', 'Emily Davis')
                """))

        print(f"Database initialized (dialect={DIALECT})")
    except Exception as e:
        print(f"Database init failed: {e}")


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
        print(f"Connected to Keycloak: {_oidc.get('issuer')}")
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

                if required and not (user_roles & required):
                    return jsonify(error="Forbidden (insufficient role)"), 403

                request.user = {
                    "username": payload.get("preferred_username", "unknown"),
                    "roles": sorted(list(user_roles)),
                    "user_id": payload.get("sub", ""),
                }

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
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": "connected" if engine else "disconnected",
        "keycloak": keycloak_status,
        "dialect": DIALECT,
        "endpoints": {
            "public": "/public",
            "user_info": "/me",
            "health": "/health",
            "books": ["GET /books", "POST /books", "DELETE /books/:id"],
            "notes": ["GET /notes", "POST /notes", "DELETE /notes/:id"],
            "stats": "GET /stats"
        }
    }), 200


# ======================
# BOOKS
# ======================
@app.get("/books")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def list_books():
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT id, title, author, available, created_at
                FROM books ORDER BY id
            """))
            books = [dict(row) for row in result.mappings().all()]
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
            if DIALECT == "postgresql":
                book = conn.execute(text("""
                    INSERT INTO books (title, author)
                    VALUES (:t, :a)
                    RETURNING id, title, author, available, created_at
                """), {"t": title, "a": author}).mappings().first()
            else:
                res = conn.execute(text("""
                    INSERT INTO books (title, author)
                    VALUES (:t, :a)
                """), {"t": title, "a": author})

                book_id = res.lastrowid if hasattr(res, "lastrowid") else None
                if book_id is None:
                    row = conn.execute(text("SELECT id FROM books ORDER BY id DESC LIMIT 1")).mappings().first()
                    book_id = row["id"]

                book = conn.execute(text("""
                    SELECT id, title, author, available, created_at
                    FROM books WHERE id = :id
                """), {"id": book_id}).mappings().first()

        return jsonify(book=dict(book)), 201
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


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
            result = conn.execute(text("""
                SELECT id, title, content, created_at
                FROM notes
                WHERE user_id = :user_id
                ORDER BY created_at DESC
            """), {"user_id": request.user["user_id"]})
            notes = [dict(row) for row in result.mappings().all()]
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
            if DIALECT == "postgresql":
                note = conn.execute(text("""
                    INSERT INTO notes (user_id, username, title, content)
                    VALUES (:user_id, :username, :title, :content)
                    RETURNING id, title, content, created_at
                """), {
                    "user_id": request.user["user_id"],
                    "username": request.user["username"],
                    "title": title,
                    "content": content
                }).mappings().first()
            else:
                res = conn.execute(text("""
                    INSERT INTO notes (user_id, username, title, content)
                    VALUES (:user_id, :username, :title, :content)
                """), {
                    "user_id": request.user["user_id"],
                    "username": request.user["username"],
                    "title": title,
                    "content": content
                })

                note_id = res.lastrowid if hasattr(res, "lastrowid") else None
                if note_id is None:
                    row = conn.execute(text("SELECT id FROM notes ORDER BY id DESC LIMIT 1")).mappings().first()
                    note_id = row["id"]

                note = conn.execute(text("""
                    SELECT id, title, content, created_at
                    FROM notes WHERE id = :id
                """), {"id": note_id}).mappings().first()

        return jsonify(note=dict(note)), 201
    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


@app.delete("/notes/<int:note_id>")
@require_roles(["full_crud"])
def delete_note(note_id):
    try:
        with engine.begin() as conn:
            res = conn.execute(text("""
                DELETE FROM notes
                WHERE id = :id AND user_id = :user_id
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
            if DIALECT == "postgresql":
                available_books = conn.execute(text("SELECT COUNT(*) FROM books WHERE available = TRUE")).scalar() or 0
            else:
                available_books = conn.execute(text("SELECT COUNT(*) FROM books WHERE available = 1")).scalar() or 0

            user_notes = conn.execute(
                text("SELECT COUNT(*) FROM notes WHERE user_id = :user_id"),
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
    print("CORS Origins: http://localhost:5500 , http://127.0.0.1:5500")
    print(f"Keycloak URL: {KEYCLOAK_BASE_URL}")
    print(f"Realm: {REALM}")
    print(f"DB: {DATABASE_URL}")
    print(f"Dialect: {DIALECT}")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
