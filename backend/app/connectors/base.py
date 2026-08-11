from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Iterator


class CollectorUpdateMode(StrEnum):
    SNAPSHOT = "snapshot"
    DELTA = "delta"
    MODIFIED_WINDOW = "modified_window"


@dataclass(frozen=True, slots=True)
class CollectorMetadata:
    source_name: str
    display_name: str
    update_mode: CollectorUpdateMode = CollectorUpdateMode.SNAPSHOT
    default_schedule_seconds: int = 86_400
    parser_version: str = "1"
    supports_cursor: bool = False
    supports_deletions: bool = False
    authority_fields: frozenset[str] = frozenset()


@dataclass(slots=True)
class RawIntelRecord:
    source_name: str
    external_id: str
    title: str
    payload: dict
    fetched_at: datetime
    references: list[str] = field(default_factory=list)
    event_type: str = "vulnerability"
    source_url: str | None = None


@dataclass(slots=True)
class CollectorPage:
    """One durable unit emitted by an independent source collector."""

    records: list[RawIntelRecord]
    page_key: str
    next_cursor: dict[str, Any] | None = None
    complete: bool = False
    artifact_uri: str | None = None
    artifact_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class VulnerabilitySourceConnector(ABC):
    source_name: str

    @property
    def metadata(self) -> CollectorMetadata:
        """Describe the collector without changing legacy implementations."""
        return CollectorMetadata(
            source_name=self.source_name,
            display_name=self.source_name,
        )

    @abstractmethod
    def fetch(self, **kwargs) -> list[RawIntelRecord]:
        """Fetch raw vulnerability records from a single source."""

    def fetch_pages(self, **kwargs) -> Iterator[CollectorPage]:
        """Adapt legacy list collectors to the generation-aware page protocol."""
        records = self.fetch(**kwargs)
        yield CollectorPage(
            records=records,
            page_key="legacy:1",
            complete=True,
            metadata={"adapter": "legacy-list"},
        )
