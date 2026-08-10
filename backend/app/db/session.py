from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.deployment import deployment_profile

settings = get_settings()
profile = deployment_profile(settings)

engine = create_engine(
    settings.database_url,
    future=True,
    pool_pre_ping=True,
    pool_size=profile.db_pool_size,
    max_overflow=profile.db_max_overflow,
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)
