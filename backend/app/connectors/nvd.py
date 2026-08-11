from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

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


class NvdCveConnector(VulnerabilitySourceConnector):
    source_name = "nvd"

    def __init__(
        self,
        *,
        api_url: str | None = None,
        api_key: str | None = None,
        page_size: int | None = None,
        timeout: int | None = None,
        overlap_seconds: int | None = None,
        get_json: Callable[..., Any] | None = None,
    ) -> None:
        settings = get_settings()
        self.api_url = api_url or settings.nvd_cve_api_url
        self.api_key = api_key if api_key is not None else settings.nvd_api_key
        self.page_size = page_size or settings.nvd_page_size
        if not 1 <= self.page_size <= 2_000:
            raise ValueError("NVD page_size must be between 1 and 2000")
        self.overlap_seconds = overlap_seconds or settings.nvd_overlap_seconds
        client = SecureSourceHttpClient(
            allowed_hosts={"services.nvd.nist.gov"},
            timeout=timeout or settings.nvd_timeout_seconds,
        )
        self.get_json = get_json or client.get_json

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            source_name=self.source_name,
            display_name="NVD",
            update_mode=CollectorUpdateMode.MODIFIED_WINDOW,
            default_schedule_seconds=7_200,
            parser_version="nvd-cve-api-2.0-v1",
            supports_cursor=True,
            authority_fields=frozenset(
                {
                    "nvd_metrics",
                    "weaknesses",
                    "cpe_configurations",
                    "references",
                    "description",
                }
            ),
        )

    def fetch(self, **kwargs) -> list[RawIntelRecord]:
        return [record for page in self.fetch_pages(**kwargs) for record in page.records]

    def fetch_pages(
        self,
        *,
        cursor: dict[str, Any] | None = None,
        start: datetime | str | None = None,
        end: datetime | str | None = None,
        limit: int | None = None,
    ) -> Iterator[CollectorPage]:
        window_start, window_end = nvd_modified_window(
            cursor=cursor,
            start=start,
            end=end,
            overlap_seconds=self.overlap_seconds,
        )
        start_index = 0
        emitted = 0
        page_number = 0
        headers = {"apiKey": self.api_key} if self.api_key else None
        while True:
            request_size = self.page_size
            if limit is not None:
                request_size = min(request_size, max(1, limit - emitted))
            payload = self.get_json(
                self.api_url,
                params={
                    "lastModStartDate": _nvd_datetime(window_start),
                    "lastModEndDate": _nvd_datetime(window_end),
                    "resultsPerPage": request_size,
                    "startIndex": start_index,
                },
                headers=headers,
            )
            records, response_start, response_page_size, total_results = parse_nvd_page(
                payload,
                fetched_at=utcnow(),
            )
            if response_start != start_index:
                raise SourceDownloadError("NVD response startIndex does not match request")
            if limit is not None and emitted + len(records) > limit:
                records = records[: limit - emitted]
            emitted += len(records)
            page_number += 1
            next_index = start_index + response_page_size
            natural_terminal = next_index >= total_results
            limit_reached = limit is not None and emitted >= limit
            terminal = natural_terminal
            yield CollectorPage(
                records=records,
                page_key=f"window:{page_number}:{start_index}",
                next_cursor=(
                    {"last_modified": window_end.isoformat()} if terminal else None
                ),
                complete=terminal,
                metadata={
                    "mode": "modified_window",
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                    "total_results": total_results,
                    "truncated": limit_reached and not natural_terminal,
                },
            )
            if terminal:
                break
            if limit_reached:
                break
            if response_page_size <= 0:
                raise SourceDownloadError("NVD pagination made no progress")
            start_index = next_index


def nvd_modified_window(
    *,
    cursor: dict[str, Any] | None,
    start: datetime | str | None,
    end: datetime | str | None,
    overlap_seconds: int,
) -> tuple[datetime, datetime]:
    window_end = _as_utc_datetime(end) if end is not None else utcnow()
    if start is not None:
        window_start = _as_utc_datetime(start)
    elif cursor and cursor.get("last_modified"):
        window_start = _as_utc_datetime(str(cursor["last_modified"])) - timedelta(
            seconds=overlap_seconds
        )
    else:
        window_start = window_end - timedelta(days=1)
    if window_start >= window_end:
        raise ValueError("NVD modified window start must be before end")
    if window_end - window_start > timedelta(days=120):
        raise ValueError("NVD modified window must not exceed 120 days")
    return window_start, window_end


def parse_nvd_page(
    payload: Any,
    *,
    fetched_at: datetime,
) -> tuple[list[RawIntelRecord], int, int, int]:
    if not isinstance(payload, dict):
        raise SourceDownloadError("NVD response must be a JSON object")
    try:
        start_index = int(payload["startIndex"])
        results_per_page = int(payload["resultsPerPage"])
        total_results = int(payload["totalResults"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SourceDownloadError("NVD response has invalid pagination metadata") from exc
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise SourceDownloadError("NVD response has no vulnerabilities array")
    records: list[RawIntelRecord] = []
    for item in vulnerabilities:
        cve = item.get("cve") if isinstance(item, dict) else None
        cve_id = cve.get("id") if isinstance(cve, dict) else None
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            raise SourceDownloadError("NVD response contains a CVE without an id")
        records.append(
            RawIntelRecord(
                source_name="nvd",
                external_id=cve_id,
                title=cve_id,
                payload=cve,
                fetched_at=fetched_at,
                event_type="nvd-cve-2.0",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )
    if len(records) > results_per_page:
        raise SourceDownloadError("NVD response exceeds resultsPerPage")
    return records, start_index, results_per_page, total_results


def _as_utc_datetime(value: datetime | str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _nvd_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
