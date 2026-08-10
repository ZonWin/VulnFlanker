from __future__ import annotations

from math import ceil

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.exceptions import HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_current_user, require_superuser
from app.core.client_ip import ClientAddress, resolve_request_client
from app.core.config import get_settings
from app.db.base import utcnow
from app.db.models import AuthIpPenalty, User
from app.schemas.auth import (
    AuthIpPenaltyOut,
    AuthIpPenaltyReleaseRequest,
    CaptchaOut,
    CurrentUserOut,
    LoginRequest,
    LoginResponse,
    SetupAdminRequest,
    SetupStatusOut,
)
from app.services.auth import (
    authenticate_user,
    create_initial_admin,
    create_user_session,
    ensure_bootstrap_admin,
    has_active_superuser,
    revoke_user_session,
    to_current_user_out,
)
from app.services.login_security import (
    IpSecurityState,
    LoginRateLimited,
    LoginSecurityService,
    LoginSecurityUnavailable,
    get_login_security_service,
)

router = APIRouter()


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )


@router.post("/captcha", response_model=CaptchaOut)
def create_captcha(
    request: Request,
    response: Response,
    security: LoginSecurityService = Depends(get_login_security_service),
) -> CaptchaOut:
    client = _resolve_client(request)
    try:
        challenge = security.create_captcha(client)
    except LoginRateLimited as exc:
        raise _rate_limit_exception(exc.retry_after_seconds) from exc
    except LoginSecurityUnavailable as exc:
        raise _security_unavailable_exception() from exc
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return CaptchaOut(
        captcha_id=challenge.captcha_id,
        image_base64=challenge.image_base64,
        expires_in=challenge.expires_in,
    )


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    security: LoginSecurityService = Depends(get_login_security_service),
) -> LoginResponse:
    settings = get_settings()
    client = _resolve_client(request)
    try:
        blocked = security.get_block_state(db, client)
        if blocked is not None:
            raise _blocked_exception(blocked)
        captcha_valid = security.verify_captcha(
            client,
            captcha_id=payload.captcha_id,
            answer=payload.captcha_answer,
        )
    except LoginRateLimited as exc:
        raise _rate_limit_exception(exc.retry_after_seconds) from exc
    except LoginSecurityUnavailable as exc:
        raise _security_unavailable_exception() from exc
    if not captcha_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "CAPTCHA_INVALID",
                "message": "Captcha is invalid or expired",
            },
        )

    user = authenticate_user(
        db,
        username=payload.username,
        password=payload.password,
        settings=settings,
    )
    if user is None:
        try:
            decision = security.record_login_failure(
                db,
                client,
                username=payload.username.strip(),
            )
        except LoginSecurityUnavailable as exc:
            raise _security_unavailable_exception() from exc
        if decision is not None and decision.state.is_blocked(utcnow()):
            raise _blocked_exception(decision.state)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "INVALID_CREDENTIALS",
                "message": "Invalid username or password",
            },
        )

    try:
        security.reset_after_success(db, client)
    except LoginSecurityUnavailable as exc:
        raise _security_unavailable_exception() from exc
    token, _ = create_user_session(db, user, settings=settings)
    _set_session_cookie(response, token)
    return LoginResponse(user=to_current_user_out(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Response:
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    revoke_user_session(db, token)
    response.delete_cookie(
        settings.session_cookie_name,
        path="/",
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=CurrentUserOut)
async def get_me(
    current_user: User = Depends(require_current_user),
) -> CurrentUserOut:
    return to_current_user_out(current_user)


@router.get("/setup-status", response_model=SetupStatusOut)
async def get_setup_status(db: Session = Depends(get_db)) -> SetupStatusOut:
    ensure_bootstrap_admin(db)
    has_superuser = has_active_superuser(db)
    return SetupStatusOut(
        needs_setup=not has_superuser,
        has_active_superuser=has_superuser,
    )


@router.post(
    "/setup-admin",
    response_model=LoginResponse,
    status_code=status.HTTP_201_CREATED,
)
def setup_admin(
    payload: SetupAdminRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    security: LoginSecurityService = Depends(get_login_security_service),
) -> LoginResponse:
    client = _resolve_client(request)
    try:
        captcha_valid = security.verify_captcha(
            client,
            captcha_id=payload.captcha_id,
            answer=payload.captcha_answer,
        )
    except LoginRateLimited as exc:
        raise _rate_limit_exception(exc.retry_after_seconds) from exc
    except LoginSecurityUnavailable as exc:
        raise _security_unavailable_exception() from exc
    if not captcha_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "CAPTCHA_INVALID",
                "message": "Captcha is invalid or expired",
            },
        )

    ensure_bootstrap_admin(db)
    if has_active_superuser(db):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Initial administrator already exists",
        )

    user = create_initial_admin(
        db,
        username=payload.username,
        password=payload.password,
        display_name=payload.display_name,
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid administrator setup payload",
        )

    token, _ = create_user_session(db, user, settings=get_settings())
    _set_session_cookie(response, token)
    return LoginResponse(user=to_current_user_out(user))


@router.get("/ip-bans", response_model=list[AuthIpPenaltyOut])
def list_ip_bans(
    active_only: bool = Query(default=True),
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require_superuser),
    db: Session = Depends(get_db),
    security: LoginSecurityService = Depends(get_login_security_service),
) -> list[AuthIpPenaltyOut]:
    return [
        _to_penalty_out(row)
        for row in security.list_penalties(db, active_only=active_only, limit=limit)
    ]


@router.post("/ip-bans/{penalty_id}/release", response_model=AuthIpPenaltyOut)
def release_ip_ban(
    penalty_id: str,
    payload: AuthIpPenaltyReleaseRequest,
    current_user: User = Depends(require_superuser),
    db: Session = Depends(get_db),
    security: LoginSecurityService = Depends(get_login_security_service),
) -> AuthIpPenaltyOut:
    try:
        row = security.unblock_penalty(
            db,
            penalty_id=penalty_id,
            released_by=current_user.id,
            reason=payload.reason.strip(),
        )
    except LoginSecurityUnavailable as exc:
        raise _security_unavailable_exception() from exc
    if row is None:
        raise HTTPException(status_code=404, detail="IP penalty not found")
    return _to_penalty_out(row)


def _resolve_client(request: Request) -> ClientAddress:
    try:
        return resolve_request_client(request, get_settings())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "CLIENT_IP_INVALID",
                "message": "Unable to determine client IP address",
            },
        ) from exc


def _blocked_exception(state: IpSecurityState) -> HTTPException:
    if state.permanent:
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "IP_BLOCKED_PERMANENT",
                "message": "This IP address is permanently blocked",
                "penalty_level": state.level,
                "blocked_until": None,
                "retry_after_seconds": None,
            },
        )
    retry_after = max(
        1,
        ceil((state.blocked_until - utcnow()).total_seconds())
        if state.blocked_until
        else 1,
    )
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(retry_after)},
        detail={
            "code": "IP_BLOCKED_TEMPORARY",
            "message": "Too many failed login attempts from this IP address",
            "penalty_level": state.level,
            "blocked_until": (
                state.blocked_until.isoformat() if state.blocked_until else None
            ),
            "retry_after_seconds": retry_after,
        },
    )


def _rate_limit_exception(retry_after_seconds: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(retry_after_seconds)},
        detail={
            "code": "LOGIN_RATE_LIMITED",
            "message": "Too many authentication requests",
            "retry_after_seconds": retry_after_seconds,
        },
    )


def _security_unavailable_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "LOGIN_SECURITY_UNAVAILABLE",
            "message": "Login security service is temporarily unavailable",
        },
    )


def _to_penalty_out(row: AuthIpPenalty) -> AuthIpPenaltyOut:
    return AuthIpPenaltyOut(
        id=row.id,
        ip_key=row.ip_key,
        last_ip_address=row.last_ip_address,
        level=row.level,
        banned_until=row.banned_until,
        is_permanent=row.is_permanent,
        last_failure_at=row.last_failure_at,
        last_banned_at=row.last_banned_at,
        released_at=row.released_at,
        released_by=row.released_by,
        release_reason=row.release_reason,
        updated_at=row.updated_at,
    )
