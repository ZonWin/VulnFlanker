"""add intel collector generations

Revision ID: b4c5d6e7f809
Revises: a3b4c5d6e7f8
Create Date: 2026-08-11 15:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "b4c5d6e7f809"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "intel_collection_runs",
        sa.Column("generation_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "intel_collection_runs",
        sa.Column("update_mode", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "intel_collection_runs",
        sa.Column("cursor_before_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "intel_collection_runs",
        sa.Column("cursor_after_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "intel_collection_runs",
        sa.Column("completeness_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "intel_collection_runs",
        sa.Column("parser_version", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "intel_collection_runs",
        sa.Column("artifacts_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "intel_collection_runs",
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "intel_collection_runs",
        sa.Column("error_code", sa.String(length=64), nullable=True),
    )
    op.create_index(
        op.f("ix_intel_collection_runs_generation_id"),
        "intel_collection_runs",
        ["generation_id"],
        unique=False,
    )

    op.drop_constraint(
        "uq_intel_raw_events_provider_payload_hash",
        "intel_raw_events",
        type_="unique",
    )
    op.add_column(
        "intel_raw_events",
        sa.Column("generation_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "intel_raw_events",
        sa.Column("page_key", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "intel_raw_events",
        sa.Column("artifact_uri", sa.Text(), nullable=True),
    )
    op.add_column(
        "intel_raw_events",
        sa.Column("artifact_hash", sa.String(length=64), nullable=True),
    )
    op.create_index(
        op.f("ix_intel_raw_events_generation_id"),
        "intel_raw_events",
        ["generation_id"],
        unique=False,
    )
    op.create_unique_constraint(
        "uq_intel_raw_events_generation_record",
        "intel_raw_events",
        ["provider", "generation_id", "external_key", "payload_hash"],
    )

    op.drop_constraint(
        "uq_vulnerability_affected_scopes_source_key",
        "vulnerability_affected_scopes",
        type_="unique",
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column("generation_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column("fact_fingerprint", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column("provenance_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
    )
    for name in ("generation_id", "fact_fingerprint", "is_active"):
        op.create_index(
            op.f(f"ix_vulnerability_affected_scopes_{name}"),
            "vulnerability_affected_scopes",
            [name],
            unique=False,
        )
    op.create_unique_constraint(
        "uq_vulnerability_affected_scopes_source_key",
        "vulnerability_affected_scopes",
        ["vulnerability_id", "source_name", "generation_id", "scope_key"],
    )

    op.create_table(
        "intel_source_configs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_name", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("schedule_seconds", sa.Integer(), nullable=False, server_default="86400"),
        sa.Column("update_mode", sa.String(length=32), nullable=False, server_default="snapshot"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("page_size", sa.Integer(), nullable=True),
        sa.Column("stale_after_seconds", sa.Integer(), nullable=False, server_default="172800"),
        sa.Column("expire_after_seconds", sa.Integer(), nullable=False, server_default="604800"),
        sa.Column("cursor_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("active_generation_id", sa.String(length=36), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("settings_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_name"),
    )
    op.create_index(
        op.f("ix_intel_source_configs_active_generation_id"),
        "intel_source_configs",
        ["active_generation_id"],
        unique=False,
    )

    op.create_table(
        "vulnerability_source_contributions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=36), nullable=False),
        sa.Column("source_name", sa.String(length=64), nullable=False),
        sa.Column("generation_id", sa.String(length=36), nullable=False),
        sa.Column("raw_event_id", sa.String(length=36), nullable=True),
        sa.Column("external_key", sa.String(length=255), nullable=False),
        sa.Column("contribution_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("provenance_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("fact_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["raw_event_id"], ["intel_raw_events.id"]),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "vulnerability_id",
            "source_name",
            "generation_id",
            "external_key",
            name="uq_vulnerability_source_contributions_fact",
        ),
    )
    for name in (
        "vulnerability_id",
        "source_name",
        "generation_id",
        "raw_event_id",
        "fact_fingerprint",
        "is_active",
    ):
        op.create_index(
            op.f(f"ix_vulnerability_source_contributions_{name}"),
            "vulnerability_source_contributions",
            [name],
            unique=False,
        )


def downgrade() -> None:
    for name in reversed(
        (
            "vulnerability_id",
            "source_name",
            "generation_id",
            "raw_event_id",
            "fact_fingerprint",
            "is_active",
        )
    ):
        op.drop_index(
            op.f(f"ix_vulnerability_source_contributions_{name}"),
            table_name="vulnerability_source_contributions",
        )
    op.drop_table("vulnerability_source_contributions")

    op.drop_index(
        op.f("ix_intel_source_configs_active_generation_id"),
        table_name="intel_source_configs",
    )
    op.drop_table("intel_source_configs")

    op.drop_constraint(
        "uq_vulnerability_affected_scopes_source_key",
        "vulnerability_affected_scopes",
        type_="unique",
    )
    for name in reversed(("generation_id", "fact_fingerprint", "is_active")):
        op.drop_index(
            op.f(f"ix_vulnerability_affected_scopes_{name}"),
            table_name="vulnerability_affected_scopes",
        )
    for name in (
        "withdrawn_at",
        "is_active",
        "provenance_json",
        "fact_fingerprint",
        "generation_id",
    ):
        op.drop_column("vulnerability_affected_scopes", name)
    op.create_unique_constraint(
        "uq_vulnerability_affected_scopes_source_key",
        "vulnerability_affected_scopes",
        ["vulnerability_id", "source_name", "scope_key"],
    )

    op.drop_constraint(
        "uq_intel_raw_events_generation_record",
        "intel_raw_events",
        type_="unique",
    )
    op.drop_index(
        op.f("ix_intel_raw_events_generation_id"),
        table_name="intel_raw_events",
    )
    for name in ("artifact_hash", "artifact_uri", "page_key", "generation_id"):
        op.drop_column("intel_raw_events", name)
    op.create_unique_constraint(
        "uq_intel_raw_events_provider_payload_hash",
        "intel_raw_events",
        ["provider", "payload_hash"],
    )

    op.drop_index(
        op.f("ix_intel_collection_runs_generation_id"),
        table_name="intel_collection_runs",
    )
    for name in (
        "error_code",
        "activated_at",
        "artifacts_count",
        "parser_version",
        "completeness_json",
        "cursor_after_json",
        "cursor_before_json",
        "update_mode",
        "generation_id",
    ):
        op.drop_column("intel_collection_runs", name)
