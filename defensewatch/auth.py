"""
JWT-based authentication and RBAC for DefenseWatch.

Opt-in via config: when auth is not enabled, require_auth() is a no-op.
"""

import logging
import os
import secrets
import time

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status

from defensewatch.config import AuthConfig

logger = logging.getLogger(__name__)

VALID_ROLES = ("admin", "analyst", "viewer")


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _get_jwt_secret(config: AuthConfig | None = None) -> str:
    """Resolve the JWT secret from config, env var, or generate a warning default."""
    if config and config.jwt_secret:
        return config.jwt_secret
    env_secret = os.environ.get("DEFENSEWATCH_JWT_SECRET")
    if env_secret:
        return env_secret
    logger.warning("No JWT secret configured; generating a random ephemeral secret")
    return _ephemeral_secret


# Generated once per process; tokens won't survive restarts without a configured secret
_ephemeral_secret = secrets.token_hex(32)


def create_token(
    user_id: int,
    username: str,
    role: str,
    secret: str,
    expiry_hours: int = 24,
    token_type: str = "access",
) -> str:
    """Create a signed JWT token."""
    now = time.time()
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": now + (expiry_hours * 3600),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str, secret: str) -> dict:
    """Decode and validate a JWT token. Raises on invalid/expired."""
    return jwt.decode(token, secret, algorithms=["HS256"])


# ---------------------------------------------------------------------------
# DB table creation (called during migration)
# ---------------------------------------------------------------------------

AUTH_TABLES_SQL = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        is_active INTEGER NOT NULL DEFAULT 1,
        last_login REAL,
        created_at REAL NOT NULL DEFAULT (unixepoch('now')),
        updated_at REAL NOT NULL DEFAULT (unixepoch('now'))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_jti TEXT UNIQUE NOT NULL,
        token_type TEXT NOT NULL DEFAULT 'access',
        issued_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        ip_address TEXT,
        user_agent TEXT,
        created_at REAL NOT NULL DEFAULT (unixepoch('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_jti ON sessions(token_jti);
"""


async def ensure_auth_tables(db):
    """Create auth tables if they don't exist. Safe to call repeatedly."""
    await db.executescript(AUTH_TABLES_SQL)
    await db.commit()


# ---------------------------------------------------------------------------
# User CRUD
# ---------------------------------------------------------------------------

async def create_user(db, username: str, password: str, role: str = "viewer") -> dict:
    """Create a new user. Returns the user dict (without password_hash)."""
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of {VALID_ROLES}")
    pw_hash = hash_password(password)
    now = time.time()
    try:
        cursor = await db.execute(
            """INSERT INTO users (username, password_hash, role, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (username, pw_hash, role, now, now),
        )
        await db.commit()
        return {
            "id": cursor.lastrowid,
            "username": username,
            "role": role,
            "is_active": 1,
            "last_login": None,
            "created_at": now,
        }
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise ValueError(f"Username '{username}' already exists") from exc
        raise


async def get_user_by_username(db, username: str) -> dict | None:
    """Fetch a user row as a dict, or None."""
    row = await db.execute_fetchall(
        "SELECT id, username, password_hash, role, is_active, last_login, created_at, updated_at "
        "FROM users WHERE username = ?",
        (username,),
    )
    if not row:
        return None
    r = row[0]
    return {
        "id": r[0],
        "username": r[1],
        "password_hash": r[2],
        "role": r[3],
        "is_active": r[4],
        "last_login": r[5],
        "created_at": r[6],
        "updated_at": r[7],
    }


async def get_user_by_id(db, user_id: int) -> dict | None:
    """Fetch a user row by ID as a dict, or None."""
    row = await db.execute_fetchall(
        "SELECT id, username, password_hash, role, is_active, last_login, created_at, updated_at "
        "FROM users WHERE id = ?",
        (user_id,),
    )
    if not row:
        return None
    r = row[0]
    return {
        "id": r[0],
        "username": r[1],
        "password_hash": r[2],
        "role": r[3],
        "is_active": r[4],
        "last_login": r[5],
        "created_at": r[6],
        "updated_at": r[7],
    }


async def list_users(db) -> list[dict]:
    """List all users (without password hashes)."""
    rows = await db.execute_fetchall(
        "SELECT id, username, role, is_active, last_login, created_at, updated_at "
        "FROM users ORDER BY id"
    )
    return [
        {
            "id": r[0],
            "username": r[1],
            "role": r[2],
            "is_active": r[3],
            "last_login": r[4],
            "created_at": r[5],
            "updated_at": r[6],
        }
        for r in rows
    ]


async def update_user(db, user_id: int, *, role: str | None = None, password: str | None = None, is_active: bool | None = None) -> bool:
    """Update user fields. Returns True if a row was modified."""
    sets = []
    params = []
    if role is not None:
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}. Must be one of {VALID_ROLES}")
        sets.append("role = ?")
        params.append(role)
    if password is not None:
        sets.append("password_hash = ?")
        params.append(hash_password(password))
    if is_active is not None:
        sets.append("is_active = ?")
        params.append(int(is_active))
    if not sets:
        return False
    sets.append("updated_at = ?")
    params.append(time.time())
    params.append(user_id)
    cursor = await db.execute(
        f"UPDATE users SET {', '.join(sets)} WHERE id = ?", params
    )
    await db.commit()
    return cursor.rowcount > 0


async def delete_user(db, user_id: int) -> bool:
    """Delete a user and their sessions. Returns True if deleted."""
    cursor = await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await db.commit()
    return cursor.rowcount > 0


async def user_count(db) -> int:
    """Return the total number of users."""
    rows = await db.execute_fetchall("SELECT COUNT(*) FROM users")
    return rows[0][0]


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

async def authenticate(db, username: str, password: str, config: AuthConfig | None = None) -> dict | None:
    """
    Authenticate a user. Returns a dict with access_token, refresh_token, and user info,
    or None if authentication fails.
    """
    user = await get_user_by_username(db, username)
    if not user:
        return None
    if not user["is_active"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None

    secret = _get_jwt_secret(config)
    expiry_hours = config.token_expiry_hours if config else 24
    refresh_hours = config.refresh_expiry_hours if config else 168

    now = time.time()

    # Create access token
    access_jti = secrets.token_hex(16)
    access_token = jwt.encode(
        {
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
            "type": "access",
            "jti": access_jti,
            "iat": now,
            "exp": now + (expiry_hours * 3600),
        },
        secret,
        algorithm="HS256",
    )

    # Create refresh token
    refresh_jti = secrets.token_hex(16)
    refresh_token = jwt.encode(
        {
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
            "type": "refresh",
            "jti": refresh_jti,
            "iat": now,
            "exp": now + (refresh_hours * 3600),
        },
        secret,
        algorithm="HS256",
    )

    # Record sessions
    await db.execute(
        """INSERT INTO sessions (user_id, token_jti, token_type, issued_at, expires_at)
           VALUES (?, ?, 'access', ?, ?)""",
        (user["id"], access_jti, now, now + (expiry_hours * 3600)),
    )
    await db.execute(
        """INSERT INTO sessions (user_id, token_jti, token_type, issued_at, expires_at)
           VALUES (?, ?, 'refresh', ?, ?)""",
        (user["id"], refresh_jti, now, now + (refresh_hours * 3600)),
    )

    # Update last_login
    await db.execute(
        "UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?",
        (now, now, user["id"]),
    )
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": expiry_hours * 3600,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        },
    }


async def refresh_access_token(db, refresh_token_str: str, config: AuthConfig | None = None) -> dict | None:
    """
    Issue a new access token from a valid refresh token.
    Returns a dict with the new access_token, or None on failure.
    """
    secret = _get_jwt_secret(config)
    try:
        payload = jwt.decode(refresh_token_str, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None

    if payload.get("type") != "refresh":
        return None

    jti = payload.get("jti")
    if not jti:
        return None

    # Check session not revoked
    rows = await db.execute_fetchall(
        "SELECT id, user_id, revoked FROM sessions WHERE token_jti = ?", (jti,)
    )
    if not rows or rows[0][2]:
        return None

    user_id = payload["sub"]
    user = await get_user_by_id(db, user_id)
    if not user or not user["is_active"]:
        return None

    expiry_hours = config.token_expiry_hours if config else 24
    now = time.time()
    access_jti = secrets.token_hex(16)
    access_token = jwt.encode(
        {
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
            "type": "access",
            "jti": access_jti,
            "iat": now,
            "exp": now + (expiry_hours * 3600),
        },
        secret,
        algorithm="HS256",
    )

    await db.execute(
        """INSERT INTO sessions (user_id, token_jti, token_type, issued_at, expires_at)
           VALUES (?, ?, 'access', ?, ?)""",
        (user["id"], access_jti, now, now + (expiry_hours * 3600)),
    )
    await db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expiry_hours * 3600,
    }


async def revoke_session(db, jti: str):
    """Revoke a session by its JTI."""
    await db.execute("UPDATE sessions SET revoked = 1 WHERE token_jti = ?", (jti,))
    await db.commit()


async def revoke_all_user_sessions(db, user_id: int):
    """Revoke all sessions for a user."""
    await db.execute(
        "UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0", (user_id,)
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Bootstrap: create initial admin user if no users exist
# ---------------------------------------------------------------------------

async def bootstrap_admin(db, username: str = "admin", password: str = "admin") -> dict | None:
    """Create the initial admin user if the users table is empty. Returns the user or None."""
    count = await user_count(db)
    if count > 0:
        return None
    return await create_user(db, username, password, role="admin")


# ---------------------------------------------------------------------------
# FastAPI dependency: get_current_user / require_auth
# ---------------------------------------------------------------------------

# Module-level config reference (set during app lifespan)
_auth_config: AuthConfig | None = None


def set_auth_config(config: AuthConfig | None):
    """Set the module-level auth config. Called during app lifespan."""
    global _auth_config
    _auth_config = config


def _extract_token(request: Request) -> str | None:
    """Extract JWT token from Authorization header or dw_token cookie."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    # Fall back to cookie
    return request.cookies.get("dw_token")


async def get_current_user(request: Request) -> dict | None:
    """
    Extract and validate the current user from the request.
    Returns user dict or None if no valid auth is present.
    """
    token_str = _extract_token(request)
    if not token_str:
        return None

    secret = _get_jwt_secret(_auth_config)
    try:
        payload = jwt.decode(token_str, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None

    if payload.get("type") != "access":
        return None

    # Check session not revoked (if jti present)
    jti = payload.get("jti")
    if jti:
        from defensewatch.database import get_db
        db = get_db()
        rows = await db.execute_fetchall(
            "SELECT revoked FROM sessions WHERE token_jti = ?", (jti,)
        )
        if rows and rows[0][0]:
            return None

    return {
        "id": payload["sub"],
        "username": payload["username"],
        "role": payload["role"],
    }


def require_auth(*roles: str):
    """
    FastAPI dependency factory that enforces authentication and optional role checks.

    Usage:
        @router.get("/admin-only", dependencies=[require_auth("admin")])
        @router.get("/any-authed-user", dependencies=[require_auth()])
        user = require_auth("admin", "analyst")  # in Depends()

    When auth is disabled (_auth_config.enabled is False), the dependency is a no-op
    and returns a synthetic admin user for backwards compatibility.
    """
    async def dependency(request: Request) -> dict:
        # If auth is not enabled, allow everything (backwards compatible)
        if not _auth_config or not _auth_config.enabled:
            return {"id": 0, "username": "system", "role": "admin"}

        user = await get_current_user(request)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check role if roles are specified
        if roles and user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {' or '.join(roles)}",
            )

        return user

    return Depends(dependency)
