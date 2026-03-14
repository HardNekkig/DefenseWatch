"""
Auth API endpoints for DefenseWatch.

Provides login, logout, user management, token refresh, and bootstrap.
"""

import logging
import time

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel

from defensewatch.config import AuthConfig
from defensewatch.auth import (
    authenticate,
    bootstrap_admin,
    create_user,
    delete_user,
    ensure_auth_tables,
    get_current_user,
    get_user_by_id,
    list_users,
    refresh_access_token,
    require_auth,
    revoke_all_user_sessions,
    revoke_session,
    set_auth_config,
    update_user,
    user_count,
    VALID_ROLES,
    _extract_token,
    _get_jwt_secret,
)
from defensewatch.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_config: AuthConfig | None = None


def set_api_auth_config(config: AuthConfig | None):
    """Set the auth config for the API module."""
    global _config
    _config = config
    set_auth_config(config)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    role: str | None = None
    password: str | None = None
    is_active: bool | None = None


class BootstrapRequest(BaseModel):
    username: str = "admin"
    password: str = "admin"


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response):
    """Authenticate and return JWT tokens."""
    db = get_db()
    await ensure_auth_tables(db)

    result = await authenticate(db, body.username, body.password, _config)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Update session with request metadata
    import jwt as pyjwt
    secret = _get_jwt_secret(_config)
    payload = pyjwt.decode(result["access_token"], secret, algorithms=["HS256"])
    jti = payload.get("jti")
    if jti:
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent", "")[:500]
        await db.execute(
            "UPDATE sessions SET ip_address = ?, user_agent = ? WHERE token_jti = ?",
            (ip, ua, jti),
        )
        await db.commit()

    # Set cookie as well for browser-based access
    response.set_cookie(
        key="dw_token",
        value=result["access_token"],
        httponly=True,
        samesite="lax",
        max_age=result["expires_in"],
    )

    return result


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Revoke the current session and clear the cookie."""
    db = get_db()
    token_str = _extract_token(request)
    if token_str:
        import jwt as pyjwt
        secret = _get_jwt_secret(_config)
        try:
            payload = pyjwt.decode(token_str, secret, algorithms=["HS256"])
            jti = payload.get("jti")
            if jti:
                await revoke_session(db, jti)
        except pyjwt.PyJWTError:
            pass  # Token already invalid, that's fine

    response.delete_cookie("dw_token")
    return {"status": "ok", "message": "Logged out"}


@router.post("/refresh")
async def refresh(body: RefreshRequest):
    """Issue a new access token from a refresh token."""
    db = get_db()
    result = await refresh_access_token(db, body.refresh_token, _config)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return result


@router.get("/me")
async def me(request: Request, user: dict = require_auth()):
    """Return the current user's information."""
    # Fetch fresh data from DB
    db = get_db()
    full_user = await get_user_by_id(db, user["id"])
    if not full_user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": full_user["id"],
        "username": full_user["username"],
        "role": full_user["role"],
        "is_active": full_user["is_active"],
        "last_login": full_user["last_login"],
        "created_at": full_user["created_at"],
    }


@router.post("/users", status_code=201)
async def create_user_endpoint(
    body: CreateUserRequest,
    user: dict = require_auth("admin"),
):
    """Create a new user (admin only)."""
    db = get_db()
    await ensure_auth_tables(db)
    try:
        new_user = await create_user(db, body.username, body.password, body.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return new_user


@router.get("/users")
async def list_users_endpoint(user: dict = require_auth("admin")):
    """List all users (admin only)."""
    db = get_db()
    await ensure_auth_tables(db)
    users = await list_users(db)
    return {"users": users}


@router.delete("/users/{user_id}")
async def delete_user_endpoint(
    user_id: int,
    user: dict = require_auth("admin"),
):
    """Delete a user (admin only). Cannot delete yourself."""
    if user["id"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    db = get_db()
    # Revoke all sessions first
    await revoke_all_user_sessions(db, user_id)
    deleted = await delete_user(db, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "message": f"User {user_id} deleted"}


@router.patch("/users/{user_id}")
async def update_user_endpoint(
    user_id: int,
    body: UpdateUserRequest,
    user: dict = require_auth("admin"),
):
    """Update a user's role, password, or active status (admin only)."""
    db = get_db()

    # Prevent admin from deactivating themselves
    if user["id"] == user_id and body.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    # Prevent admin from demoting themselves
    if user["id"] == user_id and body.role and body.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    target = await get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        updated = await update_user(
            db,
            user_id,
            role=body.role,
            password=body.password,
            is_active=body.is_active,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not updated:
        raise HTTPException(status_code=400, detail="No fields to update")

    # If password changed or account deactivated, revoke their sessions
    if body.password is not None or body.is_active is False:
        await revoke_all_user_sessions(db, user_id)

    fresh = await get_user_by_id(db, user_id)
    return {
        "id": fresh["id"],
        "username": fresh["username"],
        "role": fresh["role"],
        "is_active": fresh["is_active"],
        "last_login": fresh["last_login"],
        "created_at": fresh["created_at"],
        "updated_at": fresh["updated_at"],
    }


@router.post("/bootstrap")
async def bootstrap(body: BootstrapRequest = BootstrapRequest()):
    """
    Create the initial admin user. Only works when no users exist.
    No authentication required.
    """
    db = get_db()
    await ensure_auth_tables(db)

    count = await user_count(db)
    if count > 0:
        raise HTTPException(
            status_code=400,
            detail="Bootstrap not allowed: users already exist",
        )

    user = await bootstrap_admin(db, body.username, body.password)
    if user is None:
        raise HTTPException(status_code=400, detail="Bootstrap failed")

    return {
        "status": "ok",
        "message": f"Admin user '{user['username']}' created",
        "user": user,
    }
