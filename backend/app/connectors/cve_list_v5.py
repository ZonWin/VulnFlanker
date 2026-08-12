from __future__ import annotations

import json
import re
import zipfile
from collections.abc import Callable, Iterator
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, BinaryIO
from urllib.parse import urljoin, urlparse

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


class CveDeltaCursorExpired(SourceDownloadError):
    pass


class CveListV5Connector(VulnerabilitySourceConnector):
    source_name = "cve-list-v5"

    def __init__(
        self,
        *,
        release_api_url: str | None = None,
        release_page_url: str | None = None,
        github_token: str | None = None,
        delta_log_url: str | None = None,
        page_size: int | None = None,
        timeout: int | None = None,
        get_json: Callable[..., Any] | None = None,
        get_text: Callable[..., str] | None = None,
        download_artifact: Callable[[str], tuple[BinaryIO, str]] | None = None,
    ) -> None:
        settings = get_settings()
        self.release_api_url = release_api_url or settings.cve_list_release_api_url
        self.release_page_url = (
            release_page_url or settings.cve_list_release_page_url
        )
        self.github_token = (
            github_token if github_token is not None else settings.cve_list_github_token
        )
        self.delta_log_url = delta_log_url or settings.cve_list_delta_log_url
        self.page_size = page_size or settings.cve_list_page_size
        client = SecureSourceHttpClient(
            allowed_hosts={
                "api.github.com",
                "github.com",
                "raw.githubusercontent.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
            },
            timeout=timeout or settings.cve_list_timeout_seconds,
        )
        self.get_json = get_json or client.get_json
        self.get_text = get_text or client.get_text
        self.download_artifact = download_artifact or client.download

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            source_name=self.source_name,
            display_name="CVE List V5",
            update_mode=CollectorUpdateMode.DELTA,
            default_schedule_seconds=3_600,
            parser_version="cve-json-5.2-compatible-v1",
            supports_cursor=True,
            authority_fields=frozenset(
                {
                    "canonical_id",
                    "cve_state",
                    "title",
                    "description",
                    "products",
                    "upstream_scopes",
                    "references",
                    "cna_metrics",
                }
            ),
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
        if cursor and cursor.get("fetch_time") and not force_baseline:
            try:
                yield from self._fetch_delta(cursor, limit=limit)
                return
            except CveDeltaCursorExpired:
                pass
        yield from self._fetch_baseline(limit=limit)

    def _fetch_baseline(self, *, limit: int | None) -> Iterator[CollectorPage]:
        artifact_url, artifact_name = self._discover_baseline_asset()
        artifact, artifact_hash = self.download_artifact(artifact_url)
        fetched_at = utcnow()
        emitted = 0
        page_number = 0
        records: list[RawIntelRecord] = []
        try:
            with zipfile.ZipFile(artifact) as archive:
                members = safe_cve_zip_members(archive)
                for member in members:
                    if limit is not None and emitted >= limit:
                        break
                    with archive.open(member) as stream:
                        payload = json.load(stream)
                    record = cve_payload_to_raw_record(payload, fetched_at=fetched_at)
                    records.append(record)
                    emitted += 1
                    if len(records) >= self.page_size:
                        page_number += 1
                        yield CollectorPage(
                            records=records,
                            page_key=f"baseline:{page_number}",
                            artifact_uri=artifact_url if page_number == 1 else None,
                            artifact_hash=artifact_hash if page_number == 1 else None,
                            metadata={"artifact_name": artifact_name, "mode": "baseline"},
                        )
                        records = []
        finally:
            artifact.close()
        truncated = limit is not None and emitted < len(members)
        if records:
            page_number += 1
            yield CollectorPage(
                records=records,
                page_key=f"baseline:{page_number}",
                artifact_uri=artifact_url if page_number == 1 else None,
                artifact_hash=artifact_hash if page_number == 1 else None,
                metadata={"artifact_name": artifact_name, "mode": "baseline"},
            )
        yield CollectorPage(
            records=[],
            page_key=f"baseline:{page_number + 1}:complete",
            next_cursor={"baseline": artifact_name, "fetch_time": fetched_at.isoformat()},
            complete=not truncated,
            metadata={
                "artifact_name": artifact_name,
                "mode": "baseline",
                "record_count": emitted,
                "truncated": truncated,
            },
        )

    def _discover_baseline_asset(self) -> tuple[str, str]:
        headers = {"Authorization": f"Bearer {self.github_token}"} if self.github_token else None
        try:
            release = self.get_json(self.release_api_url, headers=headers)
            return select_cve_baseline_asset(release)
        except SourceDownloadError:
            try:
                return discover_cve_baseline_from_release_page(
                    self.release_page_url,
                    get_text=self.get_text,
                )
            except SourceDownloadError as page_error:
                raise SourceDownloadError(
                    "CVE baseline discovery failed via GitHub API and release page"
                ) from page_error

    def _fetch_delta(
        self,
        cursor: dict[str, Any],
        *,
        limit: int | None,
    ) -> Iterator[CollectorPage]:
        payload = self.get_json(self.delta_log_url)
        changes, latest_fetch_time = select_cve_delta_changes(
            payload,
            since=str(cursor["fetch_time"]),
        )
        total_changes = len(changes)
        if limit is not None:
            changes = changes[:limit]
        fetched_at = utcnow()
        page_number = 0
        records: list[RawIntelRecord] = []
        for change in changes:
            record_payload = self.get_json(change["githubLink"])
            records.append(
                cve_payload_to_raw_record(record_payload, fetched_at=fetched_at)
            )
            if len(records) >= self.page_size:
                page_number += 1
                yield CollectorPage(
                    records=records,
                    page_key=f"delta:{page_number}",
                    metadata={"mode": "delta"},
                )
                records = []
        if records:
            page_number += 1
            yield CollectorPage(
                records=records,
                page_key=f"delta:{page_number}",
                metadata={"mode": "delta"},
            )
        yield CollectorPage(
            records=[],
            page_key=f"delta:{page_number + 1}:complete",
            next_cursor={
                **cursor,
                "fetch_time": latest_fetch_time,
            },
            complete=len(changes) == total_changes,
            metadata={
                "mode": "delta",
                "record_count": len(changes),
                "truncated": len(changes) != total_changes,
            },
        )


def select_cve_baseline_asset(release: Any) -> tuple[str, str]:
    if not isinstance(release, dict) or not isinstance(release.get("assets"), list):
        raise SourceDownloadError("CVE release response has no assets")
    candidates = []
    for asset in release["assets"]:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if re.search(r"_all_CVEs_at_midnight\.zip(?:\.zip)?$", name) and url:
            candidates.append((name, url))
    if not candidates:
        raise SourceDownloadError("CVE release has no daily baseline asset")
    name, url = sorted(candidates)[-1]
    return url, name


def discover_cve_baseline_from_release_page(
    release_page_url: str,
    *,
    get_text: Callable[..., str],
) -> tuple[str, str]:
    release_html = get_text(release_page_url)
    release_links = _html_links(release_html)
    expanded_path = next(
        (
            link
            for link in release_links
            if link.startswith("/CVEProject/cvelistV5/releases/expanded_assets/")
        ),
        None,
    )
    if not expanded_path:
        raise SourceDownloadError("CVE release page has no expanded asset list")
    expanded_url = urljoin(release_page_url, expanded_path)
    expanded_html = get_text(expanded_url)
    candidates: list[tuple[str, str]] = []
    for link in _html_links(expanded_html):
        name = link.rstrip("/").split("/")[-1]
        if not re.search(r"_all_CVEs_at_midnight\.zip(?:\.zip)?$", name):
            continue
        artifact_url = urljoin(expanded_url, link)
        parsed = urlparse(artifact_url)
        if parsed.scheme == "https" and parsed.hostname == "github.com":
            candidates.append((name, artifact_url))
    if not candidates:
        raise SourceDownloadError("CVE release page has no daily baseline asset")
    name, url = sorted(candidates)[-1]
    return url, name


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.links.append(href)


def _html_links(payload: str) -> list[str]:
    parser = _LinkParser()
    parser.feed(payload)
    return parser.links


def safe_cve_zip_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members: list[zipfile.ZipInfo] = []
    total_size = 0
    for member in archive.infolist():
        normalized = member.filename.replace("\\", "/")
        parts = normalized.split("/")
        if normalized.startswith("/") or ".." in parts:
            raise SourceDownloadError("CVE baseline contains an unsafe archive path")
        total_size += member.file_size
        if total_size > 8 * 1024 * 1024 * 1024:
            raise SourceDownloadError("CVE baseline exceeds decompressed size limit")
        filename = parts[-1]
        if (
            not member.is_dir()
            and filename.endswith(".json")
            and filename not in {"delta.json", "deltaLog.json"}
        ):
            members.append(member)
    return sorted(members, key=lambda member: member.filename)


def cve_payload_to_raw_record(
    payload: Any,
    *,
    fetched_at: datetime,
) -> RawIntelRecord:
    if not isinstance(payload, dict):
        raise SourceDownloadError("CVE record must be a JSON object")
    metadata = payload.get("cveMetadata")
    cve_id = metadata.get("cveId") if isinstance(metadata, dict) else None
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        raise SourceDownloadError("CVE record has no valid cveMetadata.cveId")
    return RawIntelRecord(
        source_name="cve-list-v5",
        external_id=cve_id,
        title=cve_id,
        payload=payload,
        fetched_at=fetched_at,
        event_type="cve-record-v5",
        source_url=f"https://www.cve.org/CVERecord?id={cve_id}",
    )


def select_cve_delta_changes(
    payload: Any,
    *,
    since: str,
) -> tuple[list[dict[str, str]], str]:
    if not isinstance(payload, list) or not payload:
        raise SourceDownloadError("CVE delta log is empty or invalid")
    entries = [entry for entry in payload if isinstance(entry, dict)]
    fetch_times = sorted(
        str(entry["fetchTime"])
        for entry in entries
        if isinstance(entry.get("fetchTime"), str)
    )
    if not fetch_times:
        raise SourceDownloadError("CVE delta log has no fetchTime values")
    if _parse_iso_time(since) < _parse_iso_time(fetch_times[0]):
        raise CveDeltaCursorExpired("CVE delta cursor predates the retained log")

    by_cve: dict[str, dict[str, str]] = {}
    for entry in entries:
        fetch_time = entry.get("fetchTime")
        if not isinstance(fetch_time, str) or _parse_iso_time(fetch_time) < _parse_iso_time(since):
            continue
        for group in ("new", "updated"):
            changes = entry.get(group)
            if not isinstance(changes, list):
                continue
            for change in changes:
                if not isinstance(change, dict):
                    continue
                cve_id = change.get("cveId")
                github_link = change.get("githubLink")
                if not isinstance(cve_id, str) or not isinstance(github_link, str):
                    continue
                candidate = {
                    "cveId": cve_id,
                    "githubLink": github_link,
                    "dateUpdated": str(change.get("dateUpdated") or fetch_time),
                }
                previous = by_cve.get(cve_id)
                if previous is None or candidate["dateUpdated"] > previous["dateUpdated"]:
                    by_cve[cve_id] = candidate
    return sorted(by_cve.values(), key=lambda item: item["cveId"]), fetch_times[-1]


def _parse_iso_time(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SourceDownloadError(f"invalid CVE delta timestamp: {value}") from exc
