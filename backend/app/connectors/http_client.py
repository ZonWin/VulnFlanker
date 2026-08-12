from __future__ import annotations

import json
import random
import tempfile
import time
from collections.abc import Callable
from hashlib import sha256
from typing import Any, BinaryIO
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


class SourceDownloadError(RuntimeError):
    pass


class SecureSourceHttpClient:
    """Small bounded HTTP client for official feed collectors."""

    def __init__(
        self,
        *,
        allowed_hosts: set[str],
        timeout: int = 60,
        max_json_bytes: int = 64 * 1024 * 1024,
        max_artifact_bytes: int = 2 * 1024 * 1024 * 1024,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.allowed_hosts = {host.lower() for host in allowed_hosts}
        self.timeout = timeout
        self.max_json_bytes = max_json_bytes
        self.max_artifact_bytes = max_artifact_bytes
        self.retries = retries
        self.sleep = sleep

    def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        response = self._open(url, params=params, headers=headers)
        with response:
            payload = _read_bounded(response, self.max_json_bytes)
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceDownloadError(f"source returned invalid JSON: {url}") from exc

    def get_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int = 8 * 1024 * 1024,
    ) -> str:
        response = self._open(url, headers=headers)
        with response:
            payload = _read_bounded(response, max_bytes)
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SourceDownloadError(f"source returned invalid UTF-8: {url}") from exc

    def download(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[BinaryIO, str]:
        response = self._open(url, headers=headers)
        output = tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024, mode="w+b")
        digest = sha256()
        total = 0
        with response:
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > self.max_artifact_bytes:
                    raise SourceDownloadError(
                        f"source artifact exceeds {self.max_artifact_bytes} bytes"
                    )
                digest.update(chunk)
                output.write(chunk)
        output.seek(0)
        return output, digest.hexdigest()

    def _open(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ):
        request_url = _with_query(url, params)
        self._validate_url(request_url)
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "VulnFlanker/0.9",
            **(headers or {}),
        }
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                response = urlopen(
                    Request(request_url, headers=request_headers),
                    timeout=self.timeout,
                )
                self._validate_url(response.geturl())
                return response
            except HTTPError as exc:
                last_error = exc
                if exc.code != 429 and exc.code < 500:
                    break
                if attempt >= self.retries:
                    break
                retry_after = _retry_after_seconds(exc.headers.get("Retry-After"))
                self.sleep(retry_after or _backoff_seconds(attempt))
            except OSError as exc:
                last_error = exc
                if attempt >= self.retries:
                    break
                self.sleep(_backoff_seconds(attempt))
        raise SourceDownloadError(f"source request failed: {request_url}") from last_error

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise SourceDownloadError("source URL must use HTTPS")
        if parsed.hostname.lower() not in self.allowed_hosts:
            raise SourceDownloadError(f"source host is not allowed: {parsed.hostname}")


def _read_bounded(response: Any, maximum: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise SourceDownloadError("source returned an invalid Content-Length") from exc
        if declared_length > maximum:
            raise SourceDownloadError(f"source response exceeds {maximum} bytes")
    payload = response.read(maximum + 1)
    if len(payload) > maximum:
        raise SourceDownloadError(f"source response exceeds {maximum} bytes")
    return payload


def _with_query(url: str, params: dict[str, Any] | None) -> str:
    if not params:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(params)}"


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return min(60.0, max(0.0, float(value)))
    except ValueError:
        return None


def _backoff_seconds(attempt: int) -> float:
    return min(30.0, (2**attempt) + random.random())
