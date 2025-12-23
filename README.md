# Secure Library — Human Security Management System  
**Keycloak (OIDC + PKCE) • Flask API • PostgreSQL • RBAC Demo**

Secure Library is a Human Security themed demo system that showcases **authentication**, **authorization (RBAC)**, and **secure API access** using **Keycloak** as the Identity Provider, a **Flask** backend enforcing roles, and a lightweight **HTML/JS** frontend.

---

## Table of Contents
- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Environment Variables](#environment-variables)
- [Database Setup (PostgreSQL)](#database-setup-postgresql)
- [Keycloak Setup (Realm / Clients / Roles)](#keycloak-setup-realm--clients--roles)
- [Run the Backend (Flask)](#run-the-backend-flask)
- [Run the Frontend](#run-the-frontend)
- [RBAC Matrix](#rbac-matrix)
- [API Reference](#api-reference)
- [Optional: Excel → Keycloak User Import](#optional-excel--keycloak-user-import)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [Author](#author)

---

## Overview
This project implements a secure mini “library management” system that allows authenticated users to:
- View books and notes
- Create books/notes depending on roles
- Delete books/notes depending on roles

Authentication happens via **Keycloak** using the **Authorization Code Flow with PKCE**.  
Authorization is enforced on the backend using roles extracted from the JWT (realm roles + client roles).

---

## Tech Stack
- **Identity & Access**: Keycloak (OIDC)
- **Backend**: Python Flask + SQLAlchemy (Core) + JWT validation via JWKS
- **Database**: PostgreSQL (fallback to SQLite for quick testing)
- **Frontend**: HTML/CSS/JavaScript (runs on port **5500**)
- **Optional**: Node.js script to import users from Excel into Keycloak

---

## Key Features
- ✅ **OIDC Login with PKCE** (public client safe flow)
- ✅ **JWT Verification** on backend using Keycloak JWKS
- ✅ **RBAC enforcement** per endpoint via roles:
  - `read_only` (viewer)
  - `crud_no_delete` (editor)
  - `full_crud` (admin)
- ✅ **Books endpoints** (GET/POST/DELETE)
- ✅ **Notes endpoints** scoped to the authenticated user
- ✅ **Health + stats endpoints** for monitoring
- ✅ **CORS configured** for `http://localhost:5500`

---

## Project Structure
Typical layout:
```
Final Project/
└── secured-library/
    ├── backend/              # Flask API (JWT validation + RBAC + DB)
    ├── frontend/             # UI (HTML/JS) served via Live Server on 5500
    ├── database/             # SQL files (schema.sql / library.sql) if provided
    ├── keycloak/             # Theme / realm resources (if included)
    └── user-import/          # Optional Node script to import users from Excel into Keycloak
```

---

## Prerequisites
- Python 3.10+
- Node.js 18+ (optional, for user import)
- PostgreSQL installed and running
- Keycloak running locally
- Recommended: VS Code + Live Server extension

---

## Environment Variables
Backend uses a `.env` file (example):

```env
DATABASE_URL=postgresql://postgres:postgres123@localhost:5432/secured_library
KEYCLOAK_BASE_URL=http://localhost:8081
KEYCLOAK_REALM=secured-library
KEYCLOAK_AUDIENCE=backend-client
```

> If your Keycloak version uses `/auth` in the base URL:
> `KEYCLOAK_BASE_URL=http://localhost:8081/auth`

---

## Database Setup (PostgreSQL)
1) Create database:
```sql
CREATE DATABASE secured_library;
```

2) (Optional) Run SQL scripts if you have them:
- `secured-library/database/schema.sql`
- `secured-library/database/library.sql`

> Note: Backend also auto-creates required tables (`books`, `notes`) on startup if missing.

---

## Keycloak Setup (Realm / Clients / Roles)

### 1) Create Realm
- Realm name: `secured-library`

### 2) Create Clients

#### A) `frontend-client` (Public Client)
Used by the frontend to login using PKCE.

Recommended settings:
- **Client type**: Public
- **Standard Flow**: ON
- **PKCE**: S256
- **Valid Redirect URIs**:
  - `http://localhost:5500/*`
- **Web Origins**:
  - `http://localhost:5500`

#### B) `backend-client` (Used for audience flexibility)
The backend accepts tokens with audience including:
- `backend-client`
- `frontend-client`
- `account`

Set audience env:
- `KEYCLOAK_AUDIENCE=backend-client`

### 3) Create Realm Roles
Create these realm roles:
- `read_only`
- `crud_no_delete`
- `full_crud`

### 4) Assign Roles to Users
Assign roles from:
- Users → select user → Role mapping → Realm roles

Example:
- Admin user → `full_crud`
- Editor user → `crud_no_delete`
- Viewer user → `read_only`

---

## Run the Backend (Flask)
From:
`secured-library/backend`

1) Install dependencies:
```bash
pip install -r requirements.txt
```

2) Run:
```bash
python app.py
```

Backend URL:
- `http://127.0.0.1:5000`

Check:
- `GET http://127.0.0.1:5000/health`

---

## Run the Frontend
Run with Live Server (recommended):
- Open: `secured-library/frontend/index.html`
- Start Live Server on port **5500**

Frontend URL:
- `http://localhost:5500`

---

## RBAC Matrix
| Feature / Endpoint | read_only | crud_no_delete | full_crud |
|---|:---:|:---:|:---:|
| `GET /me` | ✅ | ✅ | ✅ |
| `GET /books` | ✅ | ✅ | ✅ |
| `POST /books` | ❌ | ✅ | ✅ |
| `DELETE /books/:id` | ❌ | ❌ | ✅ |
| `GET /notes` (user scoped) | ✅ | ✅ | ✅ |
| `POST /notes` | ❌ | ✅ | ✅ |
| `DELETE /notes/:id` | ❌ | ❌ | ✅ (must be owned) |
| `GET /stats` | ✅ | ✅ | ✅ |

---

## API Reference

### Public / Health
- `GET /public`  
  Returns a public message (no authentication).
- `GET /health`  
  Returns service status + endpoints list.

### Session
- `GET /me`  
  Requires Bearer token, returns:
  - `username`
  - `roles`
  - `user_id`

### Books
- `GET /books`  
  Roles: `read_only` / `crud_no_delete` / `full_crud`  
  Returns list of books.
- `POST /books`  
  Roles: `crud_no_delete` / `full_crud`  
  Body JSON:
  ```json
  { "title": "Book Title", "author": "Author Name" }
  ```
- `DELETE /books/<id>`  
  Roles: `full_crud`

### Notes (User Scoped)
- `GET /notes`  
  Roles: `read_only` / `crud_no_delete` / `full_crud`  
  Returns notes only for the authenticated user.
- `POST /notes`  
  Roles: `crud_no_delete` / `full_crud`  
  Body JSON:
  ```json
  { "title": "Note Title", "content": "..." }
  ```
- `DELETE /notes/<id>`  
  Roles: `full_crud`  
  Also checks ownership by `user_id`.

---

## Optional: Excel → Keycloak User Import
If you have:
`secured-library/user-import/`

Typical usage:
1) Install:
```bash
npm install
```

2) Create `.env` for the script (example):
```env
KEYCLOAK_BASE_URL=http://localhost:8081
KEYCLOAK_REALM=secured-library
KEYCLOAK_CLIENT_ID=import-script
KEYCLOAK_CLIENT_SECRET=YOUR_SECRET_HERE
EXCEL_FILE=Humans_Excel.xlsx
```

3) Run:
```bash
node import-users.js
```

Excel columns usually expected (based on your script):
- `username`
- `email`
- `password`
- `role`

Roles supported:
- `read_only`
- `crud_no_delete`
- `full_crud`

---

## Troubleshooting

### 1) “Network Error: Failed to fetch”
This usually means the frontend cannot reach the backend:
- Ensure backend is running on `http://127.0.0.1:5000`
- Check browser console → Network tab
- If frontend is served from another port, update CORS:
  - Backend currently allows: `http://localhost:5500`

### 2) 401 “Invalid token”
- Check realm name and Keycloak base URL
- Verify `KEYCLOAK_AUDIENCE` matches token `aud`
- Make sure realm roles are in token (assigned correctly)

### 3) 403 “Forbidden (insufficient role)”
- User is logged in but does not have required role
- Assign role in Keycloak and login again

### 4) DB connection errors
- Ensure PostgreSQL is running
- Confirm `DATABASE_URL` is correct
- Ensure database `secured_library` exists

---

## Security Notes
This is a demo project for educational purposes:
- Tokens are stored in `localStorage` for simplicity.
- In production, consider:
  - HTTPS everywhere
  - Secure cookies/session storage patterns
  - Strict CORS rules
  - Proper refresh token management & rotation
  - Rate limiting and logging

---

## Authors
1.Ali Mohamed 
2.Rana Ashraf
3.rewan elwardany
4.farah elhenawy
5.hana emad
6.philopater ashraf


Human Security — Final Project
