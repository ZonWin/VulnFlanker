from __future__ import annotations

import csv
import io
import json
import re
import tarfile
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import urljoin

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


_ARCHIVE_RE = re.compile(r"^csaf_vex_(\d{4}-\d{2}-\d{2})\.tar\.zst$")
_VEX_PATH_RE = re.compile(r"((?:19|20)\d{2}/cve-\d{4}-\d{4,}\.json)$", re.I)


class RedHatCsafConnector(VulnerabilitySourceConnector):
    source_name = "redhat-csaf"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        page_size: int | None = None,
        timeout: int | None = None,
        download_artifact: Callable[[str], tuple[BinaryIO, str]] | None = None,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.redhat_csaf_vex_base_url).rstrip("/") + "/"
        self.page_size = page_size or settings.redhat_csaf_page_size
        client = SecureSourceHttpClient(
            allowed_hosts={"security.access.redhat.com", "access.redhat.com"},
            timeout=timeout or settings.redhat_csaf_timeout_seconds,
            max_artifact_bytes=2 * 1024 * 1024 * 1024,
        )
        self.download_artifact = download_artifact or client.download

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            source_name=self.source_name,
            display_name="Red Hat CSAF VEX",
            update_mode=CollectorUpdateMode.DELTA,
            default_schedule_seconds=21_600,
            parser_version="redhat-csaf-vex-2.0-v1",
            supports_cursor=True,
            supports_deletions=True,
            authority_fields=frozenset({"redhat_scopes"}),
        )

    def fetch(self, **kwargs) -> list[RawIntelRecord]:
        return [record for page in self.fetch_pages(**kwargs) for record in page.records]

    def fetch_pages(
        self,
        *,
        cursor: dict[str, Any] | None = None,
        force_baseline: bool = False,
        limit: int | None = None,
    ) -> Iterator[CollectorPage]:
        if cursor and cursor.get("feed_timestamp") and not force_baseline:
            yield from self._fetch_delta(cursor, limit=limit)
            return
        yield from self._fetch_baseline(limit=limit)

    def _fetch_baseline(self, *, limit: int | None) -> Iterator[CollectorPage]:
        pointer_url = urljoin(self.base_url, "archive_latest.txt")
        pointer, _pointer_hash = self.download_artifact(pointer_url)
        try:
            archive_name = _read_archive_pointer(pointer)
        finally:
            pointer.close()
        archive_url = urljoin(self.base_url, archive_name)
        archive, archive_hash = self.download_artifact(archive_url)
        fetched_at = utcnow()
        emitted = 0
        page_number = 0
        records: list[RawIntelRecord] = []
        truncated = False
        try:
            for record in iter_redhat_archive_records(
                archive,
                fetched_at=fetched_at,
                base_url=self.base_url,
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
                        page_key=f"redhat:baseline:{page_number}",
                        artifact_uri=archive_url if page_number == 1 else None,
                        artifact_hash=archive_hash if page_number == 1 else None,
                        metadata={"mode": "baseline", "archive_name": archive_name},
                    )
                    records = []
        finally:
            archive.close()
        if records:
            page_number += 1
            yield CollectorPage(
                records=records,
                page_key=f"redhat:baseline:{page_number}",
                artifact_uri=archive_url if page_number == 1 else None,
                artifact_hash=archive_hash if page_number == 1 else None,
                metadata={"mode": "baseline", "archive_name": archive_name},
            )
        archive_date = _ARCHIVE_RE.fullmatch(archive_name).group(1)
        yield CollectorPage(
            records=[],
            page_key=f"redhat:baseline:{page_number + 1}:complete",
            next_cursor={
                "archive_name": archive_name,
                "feed_timestamp": f"{archive_date}T00:00:00+00:00",
            },
            complete=not truncated,
            metadata={
                "mode": "baseline",
                "record_count": emitted,
                "truncated": truncated,
            },
        )

    def _fetch_delta(
        self,
        cursor: dict[str, Any],
        *,
        limit: int | None,
    ) -> Iterator[CollectorPage]:
        since = _parse_timestamp(str(cursor["feed_timestamp"]))
        change_url = urljoin(self.base_url, "changes.csv")
        deletion_url = urljoin(self.base_url, "deletions.csv")
        change_file, change_hash = self.download_artifact(change_url)
        deletion_file, deletion_hash = self.download_artifact(deletion_url)
        try:
            actions, latest = select_redhat_delta_actions(
                change_file,
                deletion_file,
                since=since,
            )
        finally:
            change_file.close()
            deletion_file.close()

        total_actions = len(actions)
        if limit is not None:
            actions = actions[:limit]
        fetched_at = utcnow()
        records: list[RawIntelRecord] = []
        page_number = 0
        for action in actions:
            path = action["path"]
            source_url = urljoin(self.base_url, path)
            if action["action"] == "delete":
                payload = {
                    "deleted": True,
                    "cve_id": cve_id_from_redhat_path(path),
                    "deleted_at": action["timestamp"],
                    "path": path,
                }
            else:
                document, _document_hash = self.download_artifact(source_url)
                try:
                    payload = _load_json_document(document, source_url)
                finally:
                    document.close()
            records.append(
                redhat_payload_to_raw_record(
                    payload,
                    fetched_at=fetched_at,
                    source_url=source_url,
                )
            )
            if len(records) >= self.page_size:
                page_number += 1
                yield CollectorPage(
                    records=records,
                    page_key=f"redhat:delta:{page_number}",
                    artifact_uri=change_url if page_number == 1 else None,
                    artifact_hash=change_hash if page_number == 1 else None,
                    metadata={"mode": "delta", "deletions_hash": deletion_hash},
                )
                records = []
        if records:
            page_number += 1
            yield CollectorPage(
                records=records,
                page_key=f"redhat:delta:{page_number}",
                artifact_uri=change_url if page_number == 1 else None,
                artifact_hash=change_hash if page_number == 1 else None,
                metadata={"mode": "delta", "deletions_hash": deletion_hash},
            )
        complete = len(actions) == total_actions
        yield CollectorPage(
            records=[],
            page_key=f"redhat:delta:{page_number + 1}:complete",
            next_cursor={
                **cursor,
                "feed_timestamp": (
                    max(since, latest).isoformat()
                    if complete and latest is not None
                    else since.isoformat()
                ),
            },
            complete=complete,
            metadata={
                "mode": "delta",
                "record_count": len(actions),
                "deletion_count": sum(
                    action["action"] == "delete" for action in actions
                ),
                "truncated": not complete,
            },
        )


def iter_redhat_archive_records(
    artifact: BinaryIO,
    *,
    fetched_at: datetime,
    base_url: str,
) -> Iterator[RawIntelRecord]:
    try:
        import zstandard
    except ImportError as exc:  # pragma: no cover - packaging guard
        raise SourceDownloadError("zstandard is required for Red Hat CSAF archives") from exc

    total_size = 0
    member_count = 0
    decompressor = zstandard.ZstdDecompressor(max_window_size=2**31)
    with decompressor.stream_reader(artifact) as stream:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                member_count += 1
                if member_count > 100_000:
                    raise SourceDownloadError("Red Hat archive has too many members")
                path = _safe_redhat_member_path(member)
                if path is None:
                    continue
                total_size += member.size
                if member.size > 64 * 1024 * 1024 or total_size > 16 * 1024**3:
                    raise SourceDownloadError("Red Hat archive exceeds decompressed size limits")
                source = archive.extractfile(member)
                if source is None:
                    raise SourceDownloadError("Red Hat archive member cannot be read")
                payload = _load_json_document(source, path)
                yield redhat_payload_to_raw_record(
                    payload,
                    fetched_at=fetched_at,
                    source_url=urljoin(base_url, path),
                )


def select_redhat_delta_actions(
    changes: BinaryIO,
    deletions: BinaryIO,
    *,
    since: datetime,
) -> tuple[list[dict[str, str]], datetime | None]:
    candidates: dict[str, tuple[datetime, str]] = {}
    latest: datetime | None = None
    for stream, action in ((changes, "update"), (deletions, "delete")):
        try:
            text = stream.read().decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise SourceDownloadError("Red Hat change metadata is not UTF-8") from exc
        for row in csv.reader(io.StringIO(text)):
            if len(row) < 2:
                continue
            path = normalize_redhat_path(row[0])
            if path is None:
                continue
            timestamp = _parse_timestamp(row[1])
            latest = timestamp if latest is None or timestamp > latest else latest
            if timestamp <= since:
                continue
            previous = candidates.get(path)
            if previous is None or (timestamp, action == "delete") > (
                previous[0],
                previous[1] == "delete",
            ):
                candidates[path] = (timestamp, action)
    actions = [
        {"path": path, "timestamp": timestamp.isoformat(), "action": action}
        for path, (timestamp, action) in candidates.items()
    ]
    actions.sort(key=lambda item: (item["timestamp"], item["path"]))
    return actions, latest


def redhat_payload_to_raw_record(
    payload: Any,
    *,
    fetched_at: datetime,
    source_url: str,
) -> RawIntelRecord:
    if not isinstance(payload, dict):
        raise SourceDownloadError("Red Hat CSAF document must be an object")
    if payload.get("deleted") is True:
        cve_id = payload.get("cve_id")
    else:
        vulnerabilities = payload.get("vulnerabilities")
        cve_id = next(
            (
                item.get("cve")
                for item in vulnerabilities or []
                if isinstance(item, dict) and _valid_cve_id(item.get("cve"))
            ),
            None,
        )
    if not _valid_cve_id(cve_id):
        raise SourceDownloadError("Red Hat CSAF document has no valid CVE id")
    return RawIntelRecord(
        source_name="redhat-csaf",
        external_id=str(cve_id).upper(),
        title=str(cve_id).upper(),
        payload=payload,
        fetched_at=fetched_at,
        event_type=("redhat-csaf-deletion" if payload.get("deleted") else "csaf-vex"),
        source_url=source_url,
        references=["https://access.redhat.com/security/data"],
    )


def normalize_redhat_path(value: object) -> str | None:
    text = str(value or "").strip().replace("\\", "/")
    match = _VEX_PATH_RE.search(text)
    return match.group(1).lower() if match else None


def cve_id_from_redhat_path(path: str) -> str:
    normalized = normalize_redhat_path(path)
    if normalized is None:
        raise SourceDownloadError("invalid Red Hat VEX path")
    return PurePosixPath(normalized).stem.upper()


def _read_archive_pointer(stream: BinaryIO) -> str:
    raw = stream.read(1025)
    if len(raw) > 1024:
        raise SourceDownloadError("Red Hat archive pointer is too large")
    try:
        archive_name = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise SourceDownloadError("Red Hat archive pointer is not UTF-8") from exc
    if _ARCHIVE_RE.fullmatch(archive_name) is None:
        raise SourceDownloadError("Red Hat archive pointer is invalid")
    return archive_name


def _safe_redhat_member_path(member: tarfile.TarInfo) -> str | None:
    raw = member.name.replace("\\", "/")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
        raise SourceDownloadError("Red Hat archive contains an unsafe member")
    if not member.isfile():
        return None
    normalized = normalize_redhat_path(raw)
    return normalized


def _load_json_document(stream: BinaryIO, source: str) -> dict[str, Any]:
    try:
        payload = json.load(stream)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceDownloadError(f"Red Hat CSAF document is invalid: {source}") from exc
    if not isinstance(payload, dict):
        raise SourceDownloadError(f"Red Hat CSAF document is not an object: {source}")
    return payload


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceDownloadError(f"invalid Red Hat feed timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _valid_cve_id(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.I)
    )
