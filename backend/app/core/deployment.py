from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings


@dataclass(frozen=True)
class DeploymentProfile:
    name: str
    console_api_workers: int
    agent_api_workers: int
    db_pool_size: int
    db_max_overflow: int
    matching_batch_size: int


STANDARD_PROFILE = DeploymentProfile(
    name="standard",
    console_api_workers=1,
    agent_api_workers=1,
    db_pool_size=5,
    db_max_overflow=5,
    matching_batch_size=100,
)

LARGE_SCALE_PROFILE = DeploymentProfile(
    name="large_scale",
    console_api_workers=2,
    agent_api_workers=2,
    db_pool_size=STANDARD_PROFILE.db_pool_size,
    db_max_overflow=STANDARD_PROFILE.db_max_overflow,
    matching_batch_size=STANDARD_PROFILE.matching_batch_size,
)


def deployment_profile(settings: Settings) -> DeploymentProfile:
    return LARGE_SCALE_PROFILE if settings.large_scale_mode else STANDARD_PROFILE
