from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any, BinaryIO

from app.connectors.base import (
    CollectorMetadata,
    CollectorPage,
    CollectorUpdateMode,
    RawIntelRecord,
    VulnerabilitySourceConnector,
)
from app.connectors.http_client import SecureSourceHttpClient, SourceDownloadError
from app.core.config import get_settings
from app.db.base import utcnow


class DebianSecurityTrackerConnector(VulnerabilitySourceConnector):
    source_name = "debian-security-tracker"

    def __init__(
        self,
        *,
        feed_url: str | None = None,
        page_size: int | None = None,
        timeout: int | None = None,
        download_artifact: Callable[[str], tuple[BinaryIO, str]] | None = None,
    ) -> None:
        settings = get_settings()
        self.feed_url = feed_url or settings.debian_tracker_json_url
        self.page_size = page_size or settings.debian_tracker_page_size
        client = SecureSourceHttpClient(
            allowed_hosts={"security-tracker.debian.org"},
            timeout=timeout or settings.debian_tracker_timeout_seconds,
            max_artifact_bytes=256 * 1024 * 1024,
        )
        self.download_artifact = download_artifact or client.download

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            source_name=self.source_name,
            display_name="Debian Security Tracker",
            update_mode=CollectorUpdateMode.SNAPSHOT,
            default_schedule_seconds=21_600,
            parser_version="debian-security-tracker-json-v1",
            authority_fields=frozenset({"debian_scopes"}),
        )

    def fetch(self, **kwargs) -> list[RawIntelRecord]:
        return [record for page in self.fetch_pages(**kwargs) for record in page.records]

    def fetch_pages(
        self,
        *,
        cursor: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> Iterator[CollectorPage]:
        del cursor
        artifact, artifact_hash = self.download_artifact(self.feed_url)
        fetched_at = utcnow()
        emitted = 0
        page_number = 0
        records: list[RawIntelRecord] = []
        truncated = False
        try:
            for record in iter_debian_tracker_records(
                artifact,
                fetched_at=fetched_at,
                source_url=self.feed_url,
            ):
                if limit is not None and emitted >= limit:
                    truncated = True
                    break
                records.append(record)
                emitted += 1
                if len(records) >= self.page_size:
                    page_number += 1
                    yield CollectorPage(
                        records=records,
                        page_key=f"debian:{page_number}",
                        artifact_uri=self.feed_url if page_number == 1 else None,
                        artifact_hash=artifact_hash if page_number == 1 else None,
                        metadata={"mode": "snapshot"},
                    )
                    records = []
        finally:
            artifact.close()

        if records:
            page_number += 1
            yield CollectorPage(
                records=records,
                page_key=f"debian:{page_number}",
                artifact_uri=self.feed_url if page_number == 1 else None,
                artifact_hash=artifact_hash if page_number == 1 else None,
                metadata={"mode": "snapshot"},
            )
        yield CollectorPage(
            records=[],
            page_key=f"debian:{page_number + 1}:complete",
            next_cursor={
                "collected_at": fetched_at.isoformat(),
                "artifact_hash": artifact_hash,
            },
            complete=not truncated,
            metadata={
                "mode": "snapshot",
                "record_count": emitted,
                "truncated": truncated,
            },
        )


def iter_debian_tracker_records(
    artifact: BinaryIO,
    *,
    fetched_at: datetime,
    source_url: str,
) -> Iterator[RawIntelRecord]:
    try:
        payload = json.load(artifact)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceDownloadError("Debian tracker returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise SourceDownloadError("Debian tracker root must be an object")

    for source_package in sorted(payload):
        issues = payload[source_package]
        if not isinstance(source_package, str) or not isinstance(issues, dict):
            continue
        for cve_id in sorted(issues):
            issue = issues[cve_id]
            if not _valid_cve_id(cve_id) or not isinstance(issue, dict):
                continue
            yield RawIntelRecord(
                source_name="debian-security-tracker",
                external_id=f"{cve_id}:{source_package}",
                title=cve_id,
                payload={
                    "cve_id": cve_id,
                    "source_package": source_package,
                    "tracker": issue,
                },
                fetched_at=fetched_at,
                event_type="debian-package-status",
                source_url=f"https://security-tracker.debian.org/tracker/{cve_id}",
                references=[source_url],
            )


def _valid_cve_id(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("CVE-"):
        return False
    parts = value.split("-")
    return len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit()
