from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings, get_settings
from app.db.base import utcnow
from app.db.models import User, UserSession
from app.schemas.auth import CurrentUserOut
from app.services.audit import create_audit_log


PASSWORD_ALGORITHM = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 260_000
SESSION_TOKEN_BYTES = 48


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return "$".join(
        (
            PASSWORD_ALGORITHM,
            str(PASSWORD_ITERATIONS),
            _b64encode(salt),
            _b64encode(digest),
        )
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = password_hash.split("$", 3)
        if algorithm != PASSWORD_ALGORITHM:
            return False
        iterations = int(iterations_raw)
        salt = _b64decode(salt_raw)
        expected = _b64decode(digest_raw)
    except (TypeError, ValueError):
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual, expected)


def ensure_bootstrap_admin(
    db: Session,
    *,
    settings: Settings | None = None,
) -> User | None:
    settings = settings or get_settings()
    if has_active_superuser(db):
        return None

    username = settings.bootstrap_admin_username.strip()
    password = settings.bootstrap_admin_password
    if not username or not password:
        return None

    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        user = User(
            username=username,
            display_name=settings.bootstrap_admin_display_name.strip() or username,
            password_hash=hash_password(password),
            is_superuser=True,
            is_active=True,
        )
    else:
        user.display_name = user.display_name or settings.bootstrap_admin_display_name
        user.password_hash = hash_password(password)
        user.is_superuser = True
        user.is_active = True

    db.add(user)
    db.flush()
    create_audit_log(
        db,
        action="auth.bootstrap_admin_created",
        resource_type="user",
        resource_id=user.id,
        actor_type="system",
        summary=f"Bootstrapped administrator {username}.",
        details={"username": username},
    )
    db.commit()
    db.refresh(user)
    return user


def create_initial_admin(
    db: Session,
    *,
    username: str,
    password: str,
    display_name: str | None = None,
) -> User | None:
    if has_active_superuser(db):
        return None

    normalized_username = username.strip()
    normalized_display_name = display_name.strip() if display_name else None
    if not normalized_username:
        return None

    user = db.scalar(select(User).where(User.username == normalized_username))
    if user is None:
        user = User(
            username=normalized_username,
            display_name=normalized_display_name or normalized_username,
            password_hash=hash_password(password),
            is_superuser=True,
            is_active=True,
        )
    else:
        user.display_name = (
            normalized_display_name or user.display_name or normalized_username
        )
        user.password_hash = hash_password(password)
        user.is_superuser = True
        user.is_active = True

    db.add(user)
    db.flush()
    create_audit_log(
        db,
        action="auth.initial_admin_created",
        resource_type="user",
        resource_id=user.id,
        actor_type="system",
        summary=f"Initial administrator {normalized_username} created.",
        details={"username": normalized_username},
    )
    db.commit()
    db.refresh(user)
    return user


def has_active_superuser(db: Session) -> bool:
    return (
        db.scalar(
            select(User.id).where(
                User.is_superuser.is_(True),
                User.is_active.is_(True),
            )
        )
        is not None
    )


def authenticate_user(
    db: Session,
    *,
    username: str,
    password: str,
    settings: Settings | None = None,
) -> User | None:
    ensure_bootstrap_admin(db, settings=settings)
    normalized_username = username.strip()
    user = db.scalar(select(User).where(User.username == normalized_username))
    password_hash = (
        user.password_hash
        if user is not None and user.is_active
        else _dummy_password_hash()
    )
    password_valid = verify_password(password, password_hash)
    if user is None or not user.is_active or not password_valid:
        return None
    return user


def create_user_session(
    db: Session,
    user: User,
    *,
    settings: Settings | None = None,
) -> tuple[str, UserSession]:
    settings = settings or get_settings()
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    now = utcnow()
    session = UserSession(
        user_id=user.id,
        token_hash=hash_session_token(token),
        expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
        last_seen_at=now,
    )
    user.last_login_at = now
    db.add(session)
    db.add(user)
    create_audit_log(
        db,
        action="auth.login_success",
        resource_type="user",
        resource_id=user.id,
        actor_type="user",
        actor_id=user.id,
        summary=f"User {user.username} logged in.",
        details=user_audit_details(user),
    )
    db.commit()
    db.refresh(session)
    db.refresh(user)
    return token, session


def revoke_user_session(db: Session, token: str | None) -> bool:
    if not token:
        return False
    session = get_session_by_token(db, token)
    if session is None or session.revoked_at is not None:
        return False
    session.revoked_at = utcnow()
    db.add(session)
    create_audit_log(
        db,
        action="auth.logout",
        resource_type="user_session",
        resource_id=session.id,
        actor_type="user",
        actor_id=session.user_id,
        summary="User logged out.",
        details={"user_id": session.user_id},
    )
    db.commit()
    return True


def get_session_by_token(db: Session, token: str) -> UserSession | None:
    return db.scalar(
        select(UserSession)
        .options(selectinload(UserSession.user))
        .where(UserSession.token_hash == hash_session_token(token))
    )


def get_user_for_session_token(db: Session, token: str | None) -> User | None:
    if not token:
        return None
    session = get_session_by_token(db, token)
    if session is None or session.revoked_at is not None:
        return None
    if _ensure_aware(session.expires_at) <= utcnow():
        return None
    if not session.user.is_active:
        return None

    session.last_seen_at = utcnow()
    db.add(session)
    db.commit()
    return session.user


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def to_current_user_out(user: User) -> CurrentUserOut:
    return CurrentUserOut(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        is_superuser=user.is_superuser,
    )


def user_audit_details(user: User) -> dict[str, object | None]:
    return {
        "actor_username": user.username,
        "actor_display_name": user.display_name,
    }


@lru_cache
def _dummy_password_hash() -> str:
    return hash_password(secrets.token_urlsafe(32))


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
