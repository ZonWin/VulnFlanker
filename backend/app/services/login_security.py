from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import random
import secrets
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Protocol

from PIL import Image, ImageDraw, ImageFont
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session

from app.core.client_ip import ClientAddress
from app.core.config import Settings, get_settings
from app.db.base import utcnow
from app.db.models import AuthIpPenalty
from app.services.audit import create_audit_log


CAPTCHA_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
BAN_DURATIONS_SECONDS: tuple[int | None, ...] = (
    300,
    900,
    3_600,
    28_800,
    86_400,
    None,
)
_FALLBACK_LOGIN_SECRET = secrets.token_bytes(32)


@dataclass(frozen=True)
class CaptchaChallenge:
    captcha_id: str
    image_base64: str
    expires_in: int


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


@dataclass(frozen=True)
class IpSecurityState:
    level: int = 0
    failures: int = 0
    window_expires_at: datetime | None = None
    blocked_until: datetime | None = None
    permanent: bool = False
    last_banned_at: datetime | None = None

    def is_blocked(self, now: datetime) -> bool:
        return self.permanent or (
            self.blocked_until is not None and self.blocked_until > now
        )


@dataclass(frozen=True)
class FailureDecision:
    state: IpSecurityState
    triggered_ban: bool


class LoginSecurityUnavailable(RuntimeError):
    pass


class LoginRateLimited(RuntimeError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Login security rate limit exceeded")
        self.retry_after_seconds = max(1, retry_after_seconds)


class LoginSecurityStore(Protocol):
    def put_captcha(self, captcha_id: str, payload: str, ttl_seconds: int) -> None: ...

    def consume_captcha(self, captcha_id: str) -> str | None: ...

    def increment_rate(
        self, bucket: str, *, window_seconds: int
    ) -> tuple[int, int]: ...

    def get_ip_state(self, ip_key: str) -> IpSecurityState | None: ...

    def set_ip_state(
        self, ip_key: str, state: IpSecurityState, *, decay_seconds: int
    ) -> None: ...

    def record_password_failure(
        self,
        ip_key: str,
        *,
        now: datetime,
        threshold: int,
        window_seconds: int,
        decay_seconds: int,
    ) -> FailureDecision: ...

    def clear_ip_state(self, ip_key: str) -> None: ...


class RedisLoginSecurityStore:
    _RATE_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('TTL', KEYS[1])}
"""

    _FAILURE_SCRIPT = """
local now = tonumber(ARGV[1])
local threshold = tonumber(ARGV[2])
local window_seconds = tonumber(ARGV[3])
local decay_seconds = tonumber(ARGV[4])
local level = tonumber(redis.call('HGET', KEYS[1], 'level') or '0')
local failures = tonumber(redis.call('HGET', KEYS[1], 'failures') or '0')
local window_expires = tonumber(redis.call('HGET', KEYS[1], 'window_expires') or '0')
local blocked_until = tonumber(redis.call('HGET', KEYS[1], 'blocked_until') or '0')
local permanent = tonumber(redis.call('HGET', KEYS[1], 'permanent') or '0')
local last_banned = tonumber(redis.call('HGET', KEYS[1], 'last_banned') or '0')

if permanent == 1 then
  return {0, level, failures, window_expires, blocked_until, permanent, last_banned}
end
if blocked_until > now then
  return {0, level, failures, window_expires, blocked_until, permanent, last_banned}
end
if blocked_until > 0 and blocked_until <= now then
  blocked_until = 0
  failures = 0
  window_expires = 0
end
if level > 0 and last_banned > 0 and now - last_banned >= decay_seconds then
  level = 0
  last_banned = 0
end
if window_expires <= now then
  failures = 0
  window_expires = now + window_seconds
end

failures = failures + 1
local triggered = 0
if failures >= threshold then
  triggered = 1
  failures = 0
  window_expires = 0
  level = math.min(level + 1, 6)
  last_banned = now
  if level == 6 then
    permanent = 1
    blocked_until = 0
  else
    blocked_until = now + tonumber(ARGV[4 + level])
  end
end

redis.call(
  'HSET', KEYS[1],
  'level', level,
  'failures', failures,
  'window_expires', window_expires,
  'blocked_until', blocked_until,
  'permanent', permanent,
  'last_banned', last_banned
)
if permanent == 1 then
  redis.call('PERSIST', KEYS[1])
else
  redis.call('EXPIRE', KEYS[1], decay_seconds)
end
return {triggered, level, failures, window_expires, blocked_until, permanent, last_banned}
"""

    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client

    def put_captcha(self, captcha_id: str, payload: str, ttl_seconds: int) -> None:
        self.redis.set(self._captcha_key(captcha_id), payload, ex=ttl_seconds)

    def consume_captcha(self, captcha_id: str) -> str | None:
        value = self.redis.getdel(self._captcha_key(captcha_id))
        return str(value) if value is not None else None

    def increment_rate(
        self, bucket: str, *, window_seconds: int
    ) -> tuple[int, int]:
        result = self.redis.eval(
            self._RATE_SCRIPT,
            1,
            f"vulnflanker:auth:rate:{bucket}",
            window_seconds,
        )
        count, ttl = result
        return int(count), max(1, int(ttl))

    def get_ip_state(self, ip_key: str) -> IpSecurityState | None:
        values = self.redis.hgetall(self._ip_state_key(ip_key))
        if not values:
            return None
        return _state_from_mapping(values)

    def set_ip_state(
        self, ip_key: str, state: IpSecurityState, *, decay_seconds: int
    ) -> None:
        key = self._ip_state_key(ip_key)
        self.redis.hset(key, mapping=_state_mapping(state))
        if state.permanent:
            self.redis.persist(key)
        else:
            self.redis.expire(key, decay_seconds)

    def record_password_failure(
        self,
        ip_key: str,
        *,
        now: datetime,
        threshold: int,
        window_seconds: int,
        decay_seconds: int,
    ) -> FailureDecision:
        duration_args = [duration or 0 for duration in BAN_DURATIONS_SECONDS[:-1]]
        result = self.redis.eval(
            self._FAILURE_SCRIPT,
            1,
            self._ip_state_key(ip_key),
            int(now.timestamp()),
            threshold,
            window_seconds,
            decay_seconds,
            *duration_args,
        )
        triggered, level, failures, window_expires, blocked_until, permanent, last_banned = [
            int(value) for value in result
        ]
        return FailureDecision(
            state=IpSecurityState(
                level=level,
                failures=failures,
                window_expires_at=_datetime_from_epoch(window_expires),
                blocked_until=_datetime_from_epoch(blocked_until),
                permanent=bool(permanent),
                last_banned_at=_datetime_from_epoch(last_banned),
            ),
            triggered_ban=bool(triggered),
        )

    def clear_ip_state(self, ip_key: str) -> None:
        self.redis.delete(self._ip_state_key(ip_key))

    @staticmethod
    def _captcha_key(captcha_id: str) -> str:
        return f"vulnflanker:auth:captcha:{captcha_id}"

    @staticmethod
    def _ip_state_key(ip_key: str) -> str:
        digest = hashlib.sha256(ip_key.encode("utf-8")).hexdigest()
        return f"vulnflanker:auth:ip:{digest}"


class InMemoryLoginSecurityStore:
    """Deterministic test store with the same behavior as the Redis state machine."""

    def __init__(self) -> None:
        self.captchas: dict[str, tuple[str, float]] = {}
        self.rates: dict[str, tuple[int, float]] = {}
        self.ip_states: dict[str, IpSecurityState] = {}
        self._lock = threading.RLock()

    def put_captcha(self, captcha_id: str, payload: str, ttl_seconds: int) -> None:
        with self._lock:
            self.captchas[captcha_id] = (payload, time.time() + ttl_seconds)

    def consume_captcha(self, captcha_id: str) -> str | None:
        with self._lock:
            item = self.captchas.pop(captcha_id, None)
            if item is None or item[1] <= time.time():
                return None
            return item[0]

    def increment_rate(
        self, bucket: str, *, window_seconds: int
    ) -> tuple[int, int]:
        with self._lock:
            now = time.time()
            count, expires_at = self.rates.get(bucket, (0, now + window_seconds))
            if expires_at <= now:
                count, expires_at = 0, now + window_seconds
            count += 1
            self.rates[bucket] = (count, expires_at)
            return count, max(1, int(expires_at - now))

    def get_ip_state(self, ip_key: str) -> IpSecurityState | None:
        with self._lock:
            return self.ip_states.get(ip_key)

    def set_ip_state(
        self, ip_key: str, state: IpSecurityState, *, decay_seconds: int
    ) -> None:
        del decay_seconds
        with self._lock:
            self.ip_states[ip_key] = state

    def record_password_failure(
        self,
        ip_key: str,
        *,
        now: datetime,
        threshold: int,
        window_seconds: int,
        decay_seconds: int,
    ) -> FailureDecision:
        with self._lock:
            state = self.ip_states.get(ip_key, IpSecurityState())
            if state.is_blocked(now):
                return FailureDecision(state=state, triggered_ban=False)
            if state.blocked_until is not None and state.blocked_until <= now:
                state = replace(
                    state,
                    failures=0,
                    window_expires_at=None,
                    blocked_until=None,
                )
            if (
                state.level > 0
                and state.last_banned_at is not None
                and now - state.last_banned_at >= timedelta(seconds=decay_seconds)
            ):
                state = replace(state, level=0, last_banned_at=None)
            if state.window_expires_at is None or state.window_expires_at <= now:
                state = replace(
                    state,
                    failures=0,
                    window_expires_at=now + timedelta(seconds=window_seconds),
                )
            failures = state.failures + 1
            triggered = failures >= threshold
            if triggered:
                level = min(state.level + 1, len(BAN_DURATIONS_SECONDS))
                duration = BAN_DURATIONS_SECONDS[level - 1]
                state = replace(
                    state,
                    level=level,
                    failures=0,
                    window_expires_at=None,
                    blocked_until=(
                        now + timedelta(seconds=duration) if duration is not None else None
                    ),
                    permanent=duration is None,
                    last_banned_at=now,
                )
            else:
                state = replace(state, failures=failures)
            self.ip_states[ip_key] = state
            return FailureDecision(state=state, triggered_ban=triggered)

    def clear_ip_state(self, ip_key: str) -> None:
        with self._lock:
            self.ip_states.pop(ip_key, None)


class LoginSecurityService:
    def __init__(self, store: LoginSecurityStore, settings: Settings) -> None:
        self.store = store
        self.settings = settings
        configured_secret = settings.login_security_secret
        self._secret = (
            configured_secret.encode("utf-8")
            if configured_secret
            else _FALLBACK_LOGIN_SECRET
        )

    def create_captcha(self, client: ClientAddress) -> CaptchaChallenge:
        try:
            count, retry_after = self.store.increment_rate(
                f"captcha-issue:{_key_digest(client.ip_key)}",
                window_seconds=self.settings.login_captcha_issue_window_seconds,
            )
            if count > self.settings.login_captcha_issue_limit:
                raise LoginRateLimited(retry_after)

            answer = "".join(
                secrets.choice(CAPTCHA_ALPHABET)
                for _ in range(self.settings.login_captcha_length)
            )
            captcha_id = secrets.token_urlsafe(24)
            payload = json.dumps(
                {
                    "answer_digest": self._captcha_digest(captcha_id, answer),
                    "ip_key": client.ip_key,
                },
                separators=(",", ":"),
            )
            self.store.put_captcha(
                captcha_id,
                payload,
                self.settings.login_captcha_ttl_seconds,
            )
            return CaptchaChallenge(
                captcha_id=captcha_id,
                image_base64=_render_captcha_png(answer),
                expires_in=self.settings.login_captcha_ttl_seconds,
            )
        except LoginRateLimited:
            raise
        except RedisError as exc:
            raise LoginSecurityUnavailable from exc

    def verify_captcha(
        self,
        client: ClientAddress,
        *,
        captcha_id: str | None,
        answer: str | None,
    ) -> bool:
        if not self.settings.login_security_enabled:
            return True
        if not captcha_id or not answer:
            return self._register_captcha_failure(client)
        try:
            payload = self.store.consume_captcha(captcha_id)
            if payload is None:
                return self._register_captcha_failure(client)
            parsed = json.loads(payload)
            expected = self._captcha_digest(captcha_id, answer)
            valid = parsed.get("ip_key") == client.ip_key and hmac.compare_digest(
                str(parsed.get("answer_digest", "")), expected
            )
            return True if valid else self._register_captcha_failure(client)
        except LoginRateLimited:
            raise
        except (RedisError, json.JSONDecodeError, TypeError) as exc:
            if isinstance(exc, RedisError):
                raise LoginSecurityUnavailable from exc
            return self._register_captcha_failure(client)

    def get_block_state(
        self, db: Session, client: ClientAddress
    ) -> IpSecurityState | None:
        if not self.settings.login_security_enabled or client.is_ban_exempt:
            return None
        try:
            state = self._ensure_ip_state(db, client.ip_key)
        except RedisError as exc:
            raise LoginSecurityUnavailable from exc
        if state is not None and state.is_blocked(utcnow()):
            return state
        return None

    def record_login_failure(
        self,
        db: Session,
        client: ClientAddress,
        *,
        username: str,
    ) -> FailureDecision | None:
        now = utcnow()
        decision: FailureDecision | None = None
        try:
            if self.settings.login_security_enabled and not client.is_ban_exempt:
                self._ensure_ip_state(db, client.ip_key)
                decision = self.store.record_password_failure(
                    client.ip_key,
                    now=now,
                    threshold=self.settings.login_failure_threshold,
                    window_seconds=self.settings.login_failure_window_seconds,
                    decay_seconds=self.settings.login_penalty_decay_seconds,
                )
                self.store.increment_rate(
                    f"account-failure:{self._account_digest(username)}",
                    window_seconds=self.settings.login_failure_window_seconds,
                )
        except RedisError as exc:
            raise LoginSecurityUnavailable from exc

        details: dict[str, object] = {
            "username": username,
            "reason": "invalid_credentials",
            "ip_address": client.address,
            "ip_key": client.ip_key,
        }
        if decision is not None:
            details.update(
                {
                    "failure_count": decision.state.failures,
                    "penalty_level": decision.state.level,
                }
            )
        create_audit_log(
            db,
            action="auth.login_failed",
            resource_type="user",
            actor_type="anonymous",
            outcome="failed",
            summary="User login failed.",
            details=details,
        )

        if decision is not None and decision.triggered_ban:
            row = self._persist_ban(db, client, decision.state, now=now)
            create_audit_log(
                db,
                action="auth.ip_banned",
                resource_type="auth_ip_penalty",
                resource_id=row.id,
                actor_type="system",
                summary="Login source IP entered a progressive ban stage.",
                details={
                    "ip_address": client.address,
                    "ip_key": client.ip_key,
                    "penalty_level": decision.state.level,
                    "is_permanent": decision.state.permanent,
                    "banned_until": (
                        decision.state.blocked_until.isoformat()
                        if decision.state.blocked_until
                        else None
                    ),
                },
            )
        db.commit()
        return decision

    def reset_after_success(self, db: Session, client: ClientAddress) -> None:
        if not self.settings.login_security_enabled or client.is_ban_exempt:
            return
        try:
            self.store.clear_ip_state(client.ip_key)
        except RedisError as exc:
            raise LoginSecurityUnavailable from exc
        row = db.scalar(select(AuthIpPenalty).where(AuthIpPenalty.ip_key == client.ip_key))
        if row is None or row.is_permanent or row.level == 0:
            return
        row.level = 0
        row.banned_until = None
        row.last_failure_at = utcnow()
        row.released_at = utcnow()
        row.released_by = "successful_login"
        row.release_reason = "Penalty reset after successful login."
        db.add(row)

    def list_penalties(
        self, db: Session, *, active_only: bool, limit: int
    ) -> list[AuthIpPenalty]:
        statement = select(AuthIpPenalty).order_by(desc(AuthIpPenalty.updated_at))
        if active_only:
            now = utcnow()
            statement = statement.where(
                or_(
                    AuthIpPenalty.is_permanent.is_(True),
                    AuthIpPenalty.banned_until > now,
                )
            )
        return list(db.scalars(statement.limit(limit)).all())

    def unblock_penalty(
        self,
        db: Session,
        *,
        penalty_id: str,
        released_by: str,
        reason: str,
    ) -> AuthIpPenalty | None:
        row = db.scalar(
            select(AuthIpPenalty)
            .where(AuthIpPenalty.id == penalty_id)
            .with_for_update()
        )
        if row is None:
            return None
        try:
            self.store.clear_ip_state(row.ip_key)
        except RedisError as exc:
            raise LoginSecurityUnavailable from exc
        row.level = 0
        row.banned_until = None
        row.is_permanent = False
        row.released_at = utcnow()
        row.released_by = released_by
        row.release_reason = reason
        db.add(row)
        create_audit_log(
            db,
            action="auth.ip_unbanned",
            resource_type="auth_ip_penalty",
            resource_id=row.id,
            actor_type="user" if released_by != "cli" else "system",
            actor_id=None if released_by == "cli" else released_by,
            summary="Login source IP penalty was manually cleared.",
            details={"ip_key": row.ip_key, "reason": reason, "released_by": released_by},
        )
        db.commit()
        db.refresh(row)
        return row

    def _ensure_ip_state(
        self, db: Session, ip_key: str
    ) -> IpSecurityState | None:
        state = self.store.get_ip_state(ip_key)
        if state is not None:
            return state
        row = db.scalar(select(AuthIpPenalty).where(AuthIpPenalty.ip_key == ip_key))
        if row is None or row.level <= 0:
            return None
        now = utcnow()
        banned_until = (
            _ensure_aware(row.banned_until) if row.banned_until is not None else None
        )
        if (
            not row.is_permanent
            and (banned_until is None or banned_until <= now)
            and row.last_banned_at is not None
            and _ensure_aware(row.last_banned_at)
            <= now - timedelta(seconds=self.settings.login_penalty_decay_seconds)
        ):
            row.level = 0
            row.banned_until = None
            row.released_at = now
            row.released_by = "automatic_decay"
            row.release_reason = "Penalty decayed after the configured quiet period."
            db.add(row)
            db.commit()
            return None
        state = IpSecurityState(
            level=row.level,
            blocked_until=banned_until,
            permanent=row.is_permanent,
            last_banned_at=(
                _ensure_aware(row.last_banned_at) if row.last_banned_at else None
            ),
        )
        self.store.set_ip_state(
            ip_key,
            state,
            decay_seconds=self.settings.login_penalty_decay_seconds,
        )
        return state

    def _persist_ban(
        self,
        db: Session,
        client: ClientAddress,
        state: IpSecurityState,
        *,
        now: datetime,
    ) -> AuthIpPenalty:
        row = db.scalar(
            select(AuthIpPenalty)
            .where(AuthIpPenalty.ip_key == client.ip_key)
            .with_for_update()
        )
        if row is None:
            row = AuthIpPenalty(
                ip_key=client.ip_key,
                last_ip_address=client.address,
            )
        row.last_ip_address = client.address
        row.level = state.level
        row.banned_until = state.blocked_until
        row.is_permanent = state.permanent
        row.last_failure_at = now
        row.last_banned_at = state.last_banned_at or now
        row.released_at = None
        row.released_by = None
        row.release_reason = None
        db.add(row)
        db.flush()
        return row

    def _register_captcha_failure(self, client: ClientAddress) -> bool:
        try:
            count, retry_after = self.store.increment_rate(
                f"captcha-failure:{_key_digest(client.ip_key)}",
                window_seconds=self.settings.login_captcha_failure_window_seconds,
            )
        except RedisError as exc:
            raise LoginSecurityUnavailable from exc
        if count > self.settings.login_captcha_failure_limit:
            raise LoginRateLimited(retry_after)
        return False

    def _captcha_digest(self, captcha_id: str, answer: str) -> str:
        normalized = answer.strip().upper()
        return hmac.new(
            self._secret,
            f"{captcha_id}:{normalized}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _account_digest(self, username: str) -> str:
        return hmac.new(
            self._secret,
            username.strip().casefold().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


@lru_cache
def get_login_security_store() -> RedisLoginSecurityStore:
    settings = get_settings()
    client = Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        health_check_interval=30,
    )
    return RedisLoginSecurityStore(client)


@lru_cache
def get_login_security_service() -> LoginSecurityService:
    return LoginSecurityService(get_login_security_store(), get_settings())


def _render_captcha_png(answer: str) -> str:
    rng = random.SystemRandom()
    width = max(160, 28 * len(answer) + 24)
    height = 60
    image = Image.new(
        "RGB",
        (width, height),
        (rng.randint(232, 250), rng.randint(232, 250), rng.randint(232, 250)),
    )
    draw = ImageDraw.Draw(image)
    for _ in range(7):
        draw.line(
            (
                rng.randint(0, width),
                rng.randint(0, height),
                rng.randint(0, width),
                rng.randint(0, height),
            ),
            fill=(rng.randint(90, 190), rng.randint(90, 190), rng.randint(90, 190)),
            width=rng.randint(1, 2),
        )
    for _ in range(90):
        draw.point(
            (rng.randint(0, width - 1), rng.randint(0, height - 1)),
            fill=(rng.randint(70, 210), rng.randint(70, 210), rng.randint(70, 210)),
        )

    font = _captcha_font(36)
    x = 12
    for character in answer:
        glyph = Image.new("RGBA", (40, 52), (255, 255, 255, 0))
        glyph_draw = ImageDraw.Draw(glyph)
        glyph_draw.text(
            (5, 3),
            character,
            font=font,
            fill=(rng.randint(20, 80), rng.randint(30, 90), rng.randint(50, 120), 255),
        )
        glyph = glyph.rotate(rng.randint(-18, 18), resample=Image.Resampling.BICUBIC)
        image.paste(glyph, (x, rng.randint(3, 8)), glyph)
        x += rng.randint(25, 29)

    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return base64.b64encode(output.getvalue()).decode("ascii")


def _captcha_font(size: int):
    candidates = (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        "C:/Windows/Fonts/arialbd.ttf",
        "DejaVuSans-Bold.ttf",
    )
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


def _key_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _state_mapping(state: IpSecurityState) -> dict[str, int]:
    return {
        "level": state.level,
        "failures": state.failures,
        "window_expires": _epoch(state.window_expires_at),
        "blocked_until": _epoch(state.blocked_until),
        "permanent": int(state.permanent),
        "last_banned": _epoch(state.last_banned_at),
    }


def _state_from_mapping(values: dict) -> IpSecurityState:
    def integer(name: str) -> int:
        value = values.get(name, 0)
        return int(value) if value else 0

    return IpSecurityState(
        level=integer("level"),
        failures=integer("failures"),
        window_expires_at=_datetime_from_epoch(integer("window_expires")),
        blocked_until=_datetime_from_epoch(integer("blocked_until")),
        permanent=bool(integer("permanent")),
        last_banned_at=_datetime_from_epoch(integer("last_banned")),
    )


def _epoch(value: datetime | None) -> int:
    return int(value.timestamp()) if value else 0


def _datetime_from_epoch(value: int) -> datetime | None:
    return datetime.fromtimestamp(value, tz=UTC) if value > 0 else None


def _ensure_aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
