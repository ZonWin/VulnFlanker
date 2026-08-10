from __future__ import annotations

import base64
import io
import json
from datetime import UTC, datetime, timedelta

from PIL import Image
from sqlalchemy import select

from app.core.client_ip import ClientAddress
from app.core.config import Settings
from app.db.models import AuthIpPenalty
from app.services.login_security import (
    BAN_DURATIONS_SECONDS,
    InMemoryLoginSecurityStore,
    LoginSecurityService,
)


def _settings(**overrides) -> Settings:
    return Settings(
        _env_file=None,
        login_security_secret="test-login-security-secret",
        **overrides,
    )


def _client(
    address: str = "198.51.100.7",
    ip_key: str = "198.51.100.7/32",
) -> ClientAddress:
    return ClientAddress(
        address=address,
        ip_key=ip_key,
        peer_address="10.0.0.5",
        is_ban_exempt=False,
    )


def _put_known_captcha(
    service: LoginSecurityService,
    store: InMemoryLoginSecurityStore,
    client: ClientAddress,
    *,
    captcha_id: str = "known-captcha",
    answer: str = "AB234",
) -> None:
    payload = json.dumps(
        {
            "answer_digest": service._captcha_digest(captcha_id, answer),
            "ip_key": client.ip_key,
        }
    )
    store.put_captcha(captcha_id, payload, 120)


def test_captcha_is_png_scoped_and_single_use() -> None:
    store = InMemoryLoginSecurityStore()
    service = LoginSecurityService(store, _settings())
    client = _client()

    challenge = service.create_captcha(client)
    image = Image.open(io.BytesIO(base64.b64decode(challenge.image_base64)))

    assert image.format == "PNG"
    assert image.width >= 160
    assert challenge.expires_in == 120

    _put_known_captcha(service, store, client)
    assert service.verify_captcha(
        client, captcha_id="known-captcha", answer="ab234"
    )
    assert not service.verify_captcha(
        client, captcha_id="known-captcha", answer="AB234"
    )


def test_captcha_cannot_be_used_from_another_ip_scope() -> None:
    store = InMemoryLoginSecurityStore()
    service = LoginSecurityService(store, _settings())
    client = _client()
    _put_known_captcha(service, store, client)

    assert not service.verify_captcha(
        _client("203.0.113.9", "203.0.113.9/32"),
        captcha_id="known-captcha",
        answer="AB234",
    )


def test_progressive_ban_ladder_advances_one_stage_per_failure_cycle() -> None:
    store = InMemoryLoginSecurityStore()
    now = datetime(2026, 8, 7, tzinfo=UTC)

    for expected_level, duration in enumerate(BAN_DURATIONS_SECONDS, start=1):
        for _ in range(4):
            decision = store.record_password_failure(
                "198.51.100.7/32",
                now=now,
                threshold=5,
                window_seconds=600,
                decay_seconds=2_592_000,
            )
            assert decision.triggered_ban is False
        decision = store.record_password_failure(
            "198.51.100.7/32",
            now=now,
            threshold=5,
            window_seconds=600,
            decay_seconds=2_592_000,
        )
        assert decision.triggered_ban is True
        assert decision.state.level == expected_level
        assert decision.state.failures == 0
        assert decision.state.permanent is (duration is None)
        if duration is None:
            assert decision.state.blocked_until is None
            break

        assert decision.state.blocked_until == now + timedelta(seconds=duration)
        blocked_attempt = store.record_password_failure(
            "198.51.100.7/32",
            now=now + timedelta(seconds=1),
            threshold=5,
            window_seconds=600,
            decay_seconds=2_592_000,
        )
        assert blocked_attempt.triggered_ban is False
        assert blocked_attempt.state.failures == 0
        now = now + timedelta(seconds=duration + 1)


def test_triggered_ban_is_persisted_and_success_resets_non_permanent_penalty(
    db_session,
) -> None:
    store = InMemoryLoginSecurityStore()
    service = LoginSecurityService(
        store,
        _settings(login_failure_threshold=2),
    )
    client = _client()

    service.record_login_failure(db_session, client, username="admin")
    decision = service.record_login_failure(db_session, client, username="admin")
    assert decision is not None and decision.triggered_ban is True

    row = db_session.scalar(
        select(AuthIpPenalty).where(AuthIpPenalty.ip_key == client.ip_key)
    )
    assert row is not None
    assert row.level == 1
    assert row.banned_until is not None

    service.reset_after_success(db_session, client)
    db_session.commit()
    db_session.refresh(row)

    assert row.level == 0
    assert row.banned_until is None
    assert store.get_ip_state(client.ip_key) is None

