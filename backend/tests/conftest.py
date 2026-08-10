from __future__ import annotations

from collections.abc import Generator
from collections.abc import Callable
import json
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db, require_current_user
from app.db.base import Base
from app.db.models import User
from app.main import app
from app.services.auth import hash_password
from app.services.login_security import (
    InMemoryLoginSecurityStore,
    LoginSecurityService,
    get_login_security_service,
)
from app.core.config import Settings


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    Base.metadata.create_all(bind=engine)
    try:
        with TestingSessionLocal() as session:
            yield session
    finally:
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def authenticated_user(db_session: Session) -> User:
    user = User(
        id="test-admin-user",
        username="test-admin",
        display_name="Test Admin",
        password_hash=hash_password("test-password"),
        is_superuser=True,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def login_security_service() -> LoginSecurityService:
    return LoginSecurityService(
        InMemoryLoginSecurityStore(),
        Settings(
            _env_file=None,
            login_security_secret="test-login-security-secret",
        ),
    )


@pytest.fixture
def captcha_payload(
    login_security_service: LoginSecurityService,
) -> Callable[[], dict[str, str]]:
    def create() -> dict[str, str]:
        captcha_id = secrets.token_urlsafe(12)
        answer = "AB234"
        payload = json.dumps(
            {
                "answer_digest": login_security_service._captcha_digest(
                    captcha_id, answer
                ),
                "ip_key": "127.0.0.1/32",
            }
        )
        login_security_service.store.put_captcha(captcha_id, payload, 120)
        return {"captcha_id": captcha_id, "captcha_answer": answer}

    return create


@pytest.fixture
def anonymous_client(
    db_session: Session,
    login_security_service: LoginSecurityService,
) -> Generator[TestClient, None, None]:
    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_login_security_service] = (
        lambda: login_security_service
    )
    try:
        yield TestClient(app, client=("127.0.0.1", 50000))
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def client(
    db_session: Session,
    authenticated_user: User,
    login_security_service: LoginSecurityService,
) -> Generator[TestClient, None, None]:
    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    def override_require_current_user() -> User:
        return authenticated_user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_current_user] = override_require_current_user
    app.dependency_overrides[get_login_security_service] = (
        lambda: login_security_service
    )
    try:
        yield TestClient(app, client=("127.0.0.1", 50000))
    finally:
        app.dependency_overrides.clear()
