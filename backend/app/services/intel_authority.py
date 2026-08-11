from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


SOURCE_FIELD_AUTHORITY: dict[str, dict[str, int]] = {
    "cisa-kev": {
        "known_exploited": 100,
        "kev_date_added": 100,
        "kev_due_date": 100,
        "required_action": 100,
        "known_ransomware_use": 100,
    },
    "cve-list-v5": {
        "canonical_id": 100,
        "cve_state": 100,
        "title": 90,
        "description": 90,
        "products": 90,
        "upstream_scopes": 90,
        "references": 90,
        "cna_metrics": 100,
    },
    "nvd": {
        "nvd_metrics": 100,
        "weaknesses": 100,
        "cpe_configurations": 100,
        "references": 70,
        "description": 60,
    },
    "canonical-ubuntu": {"ubuntu_scopes": 100},
    "debian-security-tracker": {"debian_scopes": 100},
    "redhat-csaf": {"redhat_scopes": 100},
    # Existing community/commercial feeds remain useful supplements during
    # migration, but cannot override source-specific official facts above.
    "aliyun-avd": {
        "title": 50,
        "description": 50,
        "references": 50,
        "products": 40,
        "upstream_scopes": 40,
        "severity": 50,
    },
    "watchvuln": {
        "title": 40,
        "description": 40,
        "references": 40,
        "products": 30,
        "upstream_scopes": 30,
        "severity": 40,
    },
}


@dataclass(frozen=True, slots=True)
class FieldCandidate:
    source_name: str
    generation_id: str
    external_key: str
    value: Any
    priority: int
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MergedField:
    value: Any
    source_name: str
    priority: int
    candidates: tuple[FieldCandidate, ...]
    has_conflict: bool


def authority_for(source_name: str, field_name: str) -> int | None:
    profile = SOURCE_FIELD_AUTHORITY.get(source_name)
    if profile is None and source_name.startswith("watchvuln:"):
        profile = SOURCE_FIELD_AUTHORITY["watchvuln"]
    return profile.get(field_name) if profile is not None else None


def merge_contribution_documents(
    contributions: Iterable[object],
) -> dict[str, MergedField]:
    """Merge active source contributions without losing alternate values."""
    candidates_by_field: dict[str, list[FieldCandidate]] = {}
    for contribution in contributions:
        if not getattr(contribution, "is_active", True):
            continue
        document = getattr(contribution, "contribution_json", None)
        if not isinstance(document, dict):
            continue
        source_name = str(getattr(contribution, "source_name"))
        for field_name, value in document.items():
            priority = authority_for(source_name, field_name)
            if priority is None or value is None:
                continue
            candidates_by_field.setdefault(field_name, []).append(
                FieldCandidate(
                    source_name=source_name,
                    generation_id=str(getattr(contribution, "generation_id")),
                    external_key=str(getattr(contribution, "external_key")),
                    value=value,
                    priority=priority,
                    provenance=dict(getattr(contribution, "provenance_json", None) or {}),
                )
            )

    merged: dict[str, MergedField] = {}
    for field_name, candidates in candidates_by_field.items():
        ordered = tuple(
            sorted(
                candidates,
                key=lambda candidate: (
                    -candidate.priority,
                    candidate.source_name,
                    candidate.generation_id,
                    candidate.external_key,
                ),
            )
        )
        selected = ordered[0]
        selected_value = _stable_value(selected.value)
        merged[field_name] = MergedField(
            value=selected.value,
            source_name=selected.source_name,
            priority=selected.priority,
            candidates=ordered,
            has_conflict=any(
                _stable_value(candidate.value) != selected_value
                for candidate in ordered[1:]
            ),
        )
    return merged


def _stable_value(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
