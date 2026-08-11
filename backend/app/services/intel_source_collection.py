from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.connectors.base import VulnerabilitySourceConnector
from app.db.models import IntelCollectionRun
from app.services.intel_enrichment import (
    EnrichmentMapper,
    EnrichmentMapperRegistry,
    materialize_enrichment_generation,
    normalize_enrichment_page,
)
from app.services.intel_generations import (
    collect_generation,
    get_or_create_source_config,
)


def build_builtin_mapper_registry() -> EnrichmentMapperRegistry:
    from app.services.cve_list_normalization import CveListV5Mapper
    from app.services.canonical_ubuntu_normalization import CanonicalUbuntuMapper
    from app.services.nvd_normalization import NvdCveMapper

    registry = EnrichmentMapperRegistry()
    registry.register(CveListV5Mapper())
    registry.register(NvdCveMapper())
    registry.register(CanonicalUbuntuMapper())
    return registry


def collect_enrichment_source(
    db: Session,
    *,
    connector: VulnerabilitySourceConnector,
    mapper: EnrichmentMapper,
    trigger_type: str = "manual",
    parameters: dict[str, Any] | None = None,
    **fetch_kwargs: Any,
) -> IntelCollectionRun:
    metadata = connector.metadata
    if mapper.source_name != metadata.source_name:
        raise ValueError("connector and mapper source names do not match")
    config = get_or_create_source_config(
        db,
        source_name=metadata.source_name,
        update_mode=metadata.update_mode.value,
        schedule_seconds=metadata.default_schedule_seconds,
    )
    db.commit()
    fetch_kwargs.setdefault("cursor", dict(config.cursor_json or {}))
    return collect_generation(
        db,
        connector,
        trigger_type=trigger_type,
        parameters=parameters,
        normalize_page=lambda session, run, page: normalize_enrichment_page(
            session,
            run,
            page,
            mapper=mapper,
        ),
        after_activate=materialize_enrichment_generation,
        **fetch_kwargs,
    )
