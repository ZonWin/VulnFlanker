from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from redis import Redis

from app.services.login_security import RedisLoginSecurityStore


@pytest.mark.skipif(
    not os.getenv("VULNFLANKER_TEST_REDIS_URL"),
    reason="VULNFLANKER_TEST_REDIS_URL is not configured",
)
def test_redis_store_consumes_captcha_and_triggers_first_ban() -> None:
    client = Redis.from_url(
        os.environ["VULNFLANKER_TEST_REDIS_URL"],
        decode_responses=True,
    )
    client.flushdb()
    store = RedisLoginSecurityStore(client)
    try:
        store.put_captcha("captcha-1", "payload", 120)
        assert store.consume_captcha("captcha-1") == "payload"
        assert store.consume_captcha("captcha-1") is None

        now = datetime(2026, 8, 7, tzinfo=UTC)
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
        assert decision.state.level == 1
        assert decision.state.blocked_until is not None
    finally:
        client.flushdb()
        client.close()

