from __future__ import annotations

import bz2
import json
import re
import tarfile
import tempfile
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any, BinaryIO
from urllib.parse import quote
from xml.etree import ElementTree as ET

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


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


class CanonicalUbuntuConnector(VulnerabilitySourceConnector):
    source_name = "canonical-ubuntu"

    def __init__(
        self,
        *,
        vex_url: str | None = None,
        oval_url_template: str | None = None,
        releases: list[str] | tuple[str, ...] | None = None,
        page_size: int | None = None,
        timeout: int | None = None,
        download_artifact: Callable[[str], tuple[BinaryIO, str]] | None = None,
    ) -> None:
        settings = get_settings()
        self.vex_url = vex_url or settings.canonical_vex_url
        self.oval_url_template = oval_url_template or settings.canonical_oval_url_template
        configured_releases = releases or tuple(
            item.strip()
            for item in settings.canonical_oval_releases.split(",")
            if item.strip()
        )
        self.releases = tuple(dict.fromkeys(configured_releases))
        if not self.releases:
            raise ValueError("at least one Canonical OVAL release is required")
        self.page_size = page_size or settings.canonical_page_size
        client = SecureSourceHttpClient(
            allowed_hosts={"security-metadata.canonical.com"},
            timeout=timeout or settings.canonical_timeout_seconds,
            max_artifact_bytes=2 * 1024 * 1024 * 1024,
        )
        self.download_artifact = download_artifact or client.download

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            source_name=self.source_name,
            display_name="Canonical Ubuntu Security",
            update_mode=CollectorUpdateMode.SNAPSHOT,
            default_schedule_seconds=21_600,
            parser_version="canonical-openvex-0.2-oval-v1",
            authority_fields=frozenset({"ubuntu_vex", "ubuntu_oval"}),
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
        fetched_at = utcnow()
        artifacts: dict[str, str] = {}
        records: list[RawIntelRecord] = []
        page_number = 0
        emitted = 0
        truncated = False

        def emit(record: RawIntelRecord) -> CollectorPage | None:
            nonlocal page_number, emitted, records
            records.append(record)
            emitted += 1
            if len(records) < self.page_size:
                return None
            page_number += 1
            page = CollectorPage(
                records=records,
                page_key=f"canonical:{page_number}",
                metadata={"mode": "snapshot"},
            )
            records = []
            return page

        vex_file, vex_hash = self.download_artifact(self.vex_url)
        artifacts["openvex"] = vex_hash
        try:
            for record in iter_canonical_vex_records(
                vex_file,
                fetched_at=fetched_at,
                source_url=self.vex_url,
            ):
                if limit is not None and emitted >= limit:
                    truncated = True
                    break
                if page := emit(record):
                    if page_number == 1:
                        page.artifact_uri = self.vex_url
                        page.artifact_hash = vex_hash
                    yield page
        finally:
            vex_file.close()

        if not truncated:
            for artifact_release in self.releases:
                oval_url = self.oval_url_template.format(
                    artifact_release=quote(artifact_release.replace("/", "_"), safe="-_")
                )
                oval_file, oval_hash = self.download_artifact(oval_url)
                artifacts[f"oval:{artifact_release}"] = oval_hash
                try:
                    xml_file = decompress_bz2_bounded(oval_file)
                    try:
                        for record in iter_canonical_oval_records(
                            xml_file,
                            artifact_release=artifact_release,
                            fetched_at=fetched_at,
                            source_url=oval_url,
                        ):
                            if limit is not None and emitted >= limit:
                                truncated = True
                                break
                            if page := emit(record):
                                yield page
                    finally:
                        xml_file.close()
                finally:
                    oval_file.close()
                if truncated:
                    break

        if records:
            page_number += 1
            yield CollectorPage(
                records=records,
                page_key=f"canonical:{page_number}",
                metadata={"mode": "snapshot"},
            )
        yield CollectorPage(
            records=[],
            page_key=f"canonical:{page_number + 1}:complete",
            next_cursor={
                "collected_at": fetched_at.isoformat(),
                "artifacts": artifacts,
                "releases": list(self.releases),
            },
            complete=not truncated,
            metadata={
                "mode": "snapshot",
                "record_count": emitted,
                "artifact_count": len(artifacts),
                "truncated": truncated,
            },
        )


def iter_canonical_vex_records(
    artifact: BinaryIO,
    *,
    fetched_at: datetime,
    source_url: str,
) -> Iterator[RawIntelRecord]:
    total_size = 0
    member_count = 0
    with tarfile.open(fileobj=artifact, mode="r:xz") as archive:
        for member in archive:
            member_count += 1
            if member_count > 1_000_000:
                raise SourceDownloadError("Canonical VEX archive has too many members")
            normalized = member.name.replace("\\", "/")
            if normalized.startswith("/") or ".." in normalized.split("/"):
                raise SourceDownloadError("Canonical VEX archive has an unsafe path")
            if member.issym() or member.islnk():
                raise SourceDownloadError("Canonical VEX archive contains a link")
            total_size += member.size
            if total_size > 8 * 1024 * 1024 * 1024:
                raise SourceDownloadError("Canonical VEX archive exceeds size limit")
            if (
                not member.isfile()
                or "/vex/cve/" not in f"/{normalized}"
                or not normalized.endswith(".json")
            ):
                continue
            if member.size > 32 * 1024 * 1024:
                raise SourceDownloadError("Canonical VEX member exceeds size limit")
            stream = archive.extractfile(member)
            if stream is None:
                raise SourceDownloadError("Canonical VEX member cannot be read")
            with stream:
                document = json.load(stream)
            cve_id = canonical_vex_cve_id(document)
            yield RawIntelRecord(
                source_name="canonical-ubuntu",
                external_id=f"vex:{cve_id}",
                title=cve_id,
                payload={
                    "artifact_type": "openvex",
                    "artifact_member": normalized,
                    "document": document,
                },
                fetched_at=fetched_at,
                event_type="canonical-openvex-cve",
                source_url=f"https://ubuntu.com/security/{cve_id}",
            )


def canonical_vex_cve_id(document: Any) -> str:
    if not isinstance(document, dict) or not isinstance(document.get("statements"), list):
        raise SourceDownloadError("Canonical VEX document has no statements")
    cve_ids: set[str] = set()
    for statement in document["statements"]:
        vulnerability = statement.get("vulnerability") if isinstance(statement, dict) else None
        name = vulnerability.get("name") if isinstance(vulnerability, dict) else None
        if isinstance(name, str) and _CVE_RE.fullmatch(name.upper()):
            cve_ids.add(name.upper())
    if len(cve_ids) != 1:
        raise SourceDownloadError("Canonical VEX document must describe exactly one CVE")
    return next(iter(cve_ids))


def decompress_bz2_bounded(
    artifact: BinaryIO,
    *,
    maximum: int = 2 * 1024 * 1024 * 1024,
) -> BinaryIO:
    output = tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024, mode="w+b")
    decompressor = bz2.BZ2Decompressor()
    total = 0
    scan_tail = b""
    try:
        while chunk := artifact.read(1024 * 1024):
            data = decompressor.decompress(chunk)
            total += len(data)
            if total > maximum:
                raise SourceDownloadError("Canonical OVAL XML exceeds size limit")
            scan = (scan_tail + data).upper()
            if b"<!DOCTYPE" in scan or b"<!ENTITY" in scan:
                raise SourceDownloadError("Canonical OVAL XML contains a forbidden declaration")
            scan_tail = scan[-16:]
            output.write(data)
        if not decompressor.eof:
            raise SourceDownloadError("Canonical OVAL bz2 stream is incomplete")
        output.seek(0)
        return output
    except Exception:
        output.close()
        raise


def iter_canonical_oval_records(
    xml_file: BinaryIO,
    *,
    artifact_release: str,
    fetched_at: datetime,
    source_url: str,
) -> Iterator[RawIntelRecord]:
    definitions: list[dict[str, Any]] = []
    tests: dict[str, dict[str, Any]] = {}
    objects: dict[str, dict[str, Any]] = {}
    states: dict[str, dict[str, Any]] = {}
    variables: dict[str, list[str]] = {}

    for _event, element in ET.iterparse(xml_file, events=("end",)):
        local = _local_name(element.tag)
        element_id = element.attrib.get("id")
        if local == "definition":
            cve_ids = {
                reference.attrib.get("ref_id", "").upper()
                for reference in element.iter()
                if _local_name(reference.tag) == "reference"
                and reference.attrib.get("source") == "CVE"
            }
            cve_ids = {cve_id for cve_id in cve_ids if _CVE_RE.fullmatch(cve_id)}
            if cve_ids:
                criteria = []
                for criterion in element.iter():
                    if _local_name(criterion.tag) != "criterion":
                        continue
                    test_ref = criterion.attrib.get("test_ref")
                    if test_ref:
                        criteria.append(
                            {
                                "test_ref": test_ref,
                                "comment": criterion.attrib.get("comment"),
                            }
                        )
                definitions.append(
                    {
                        "definition_id": element_id,
                        "cve_ids": sorted(cve_ids),
                        "criteria": criteria,
                        "title": _first_descendant_text(element, "title"),
                        "description": _first_descendant_text(element, "description"),
                    }
                )
            element.clear()
        elif local == "dpkginfo_test" and element_id:
            tests[element_id] = {
                "comment": element.attrib.get("comment"),
                "object_ref": _first_descendant_attribute(element, "object_ref"),
                "state_ref": _first_descendant_attribute(element, "state_ref"),
            }
            element.clear()
        elif local == "dpkginfo_object" and element_id:
            name = next(
                (child for child in element.iter() if _local_name(child.tag) == "name"),
                None,
            )
            objects[element_id] = {
                "name": _text(name.text) if name is not None else None,
                "var_ref": name.attrib.get("var_ref") if name is not None else None,
            }
            element.clear()
        elif local == "dpkginfo_state" and element_id:
            evr = next(
                (child for child in element.iter() if _local_name(child.tag) == "evr"),
                None,
            )
            states[element_id] = {
                "evr": _text(evr.text) if evr is not None else None,
                "operation": evr.attrib.get("operation") if evr is not None else None,
                "datatype": evr.attrib.get("datatype") if evr is not None else None,
            }
            element.clear()
        elif local == "constant_variable" and element_id:
            variables[element_id] = [
                value
                for child in element.iter()
                if _local_name(child.tag) == "value" and (value := _text(child.text))
            ]
            element.clear()

    release, flavor = canonical_artifact_identity(artifact_release)
    facts_by_cve: dict[str, list[dict[str, Any]]] = {}
    metadata_by_cve: dict[str, dict[str, Any]] = {}
    for definition in definitions:
        seen_tests: set[str] = set()
        definition_facts: list[dict[str, Any]] = []
        for criterion in definition["criteria"]:
            test_ref = criterion["test_ref"]
            if test_ref in seen_tests or test_ref not in tests:
                continue
            seen_tests.add(test_ref)
            test = tests[test_ref]
            object_data = objects.get(test.get("object_ref"), {})
            package_names = []
            if object_data.get("name"):
                package_names.append(object_data["name"])
            package_names.extend(variables.get(object_data.get("var_ref"), []))
            package_names = list(dict.fromkeys(package_names))
            if not package_names:
                continue
            state = states.get(test.get("state_ref"), {})
            status, default_status = canonical_oval_status(
                criterion.get("comment") or test.get("comment"),
                state,
            )
            fixed_version = _normalize_oval_evr(state.get("evr")) if status == "fixed" else None
            source_package = _source_package_from_comment(
                criterion.get("comment") or test.get("comment")
            ) or package_names[0]
            for package_name in package_names:
                definition_facts.append(
                    {
                        "test_ref": test_ref,
                        "definition_id": definition["definition_id"],
                        "source_package": source_package,
                        "binary_package": package_name,
                        "release": release,
                        "flavor": flavor,
                        "status": status,
                        "default_status": default_status,
                        "fixed_version": fixed_version,
                        "operation": state.get("operation"),
                        "datatype": state.get("datatype"),
                        "comment": criterion.get("comment") or test.get("comment"),
                    }
                )
        for cve_id in definition["cve_ids"]:
            facts_by_cve.setdefault(cve_id, []).extend(definition_facts)
            metadata_by_cve[cve_id] = {
                "title": definition.get("title"),
                "description": definition.get("description"),
            }

    for cve_id in sorted(facts_by_cve):
        facts = _dedupe_oval_facts(facts_by_cve[cve_id])
        metadata = metadata_by_cve[cve_id]
        yield RawIntelRecord(
            source_name="canonical-ubuntu",
            external_id=f"oval:{artifact_release}:{cve_id}",
            title=metadata.get("title") or cve_id,
            payload={
                "artifact_type": "oval",
                "artifact_release": artifact_release,
                "release": release,
                "flavor": flavor,
                "cve_id": cve_id,
                "title": metadata.get("title"),
                "description": metadata.get("description"),
                "facts": facts,
            },
            fetched_at=fetched_at,
            event_type="canonical-ubuntu-cve-oval",
            source_url=source_url,
        )


def canonical_artifact_identity(artifact_release: str) -> tuple[str, str | None]:
    if "/" not in artifact_release:
        return artifact_release.lower(), None
    flavor, release = artifact_release.rsplit("/", 1)
    return release.lower(), flavor.lower()


def canonical_oval_status(
    comment: str | None,
    state: dict[str, Any],
) -> tuple[str, str]:
    normalized = (comment or "").lower()
    if "not affected" in normalized:
        return "not_affected", "not-affected"
    if state.get("evr") and str(state.get("operation") or "").lower() == "less than":
        return "fixed", "released"
    if "was vulnerable but has been fixed" in normalized:
        return "fixed", "released"
    if "decision has been made to ignore" in normalized or "ignored" in normalized:
        return "affected", "ignored"
    if "needs evaluation" in normalized or "needs-triage" in normalized:
        return "under_investigation", "needs-triage"
    if "deferred" in normalized:
        return "under_investigation", "deferred"
    if "vulnerable" in normalized or "needs fixing" in normalized:
        return "affected", "needed"
    return "under_investigation", "unknown"


def _dedupe_oval_facts(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for fact in facts:
        key = json.dumps(fact, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        deduped[key] = fact
    return list(deduped.values())


def _normalize_oval_evr(value: Any) -> str | None:
    text = _text(value)
    return text[2:] if text and text.startswith("0:") else text


def _source_package_from_comment(comment: Any) -> str | None:
    text = _text(comment)
    if not text:
        return None
    if ":" in text:
        candidate = text.split(":", 1)[0].strip()
        if candidate and " " not in candidate:
            return candidate
    match = re.search(r"(?:the\s+)?'([^']+)'\s+package", text, re.IGNORECASE)
    return match.group(1) if match else None


def _first_descendant_text(element: ET.Element, name: str) -> str | None:
    return next(
        (
            text
            for child in element.iter()
            if _local_name(child.tag) == name and (text := _text(child.text))
        ),
        None,
    )


def _first_descendant_attribute(element: ET.Element, name: str) -> str | None:
    return next(
        (
            value
            for child in element.iter()
            if (value := child.attrib.get(name)) is not None
        ),
        None,
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
