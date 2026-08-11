"""add match evaluation runs

Revision ID: f2a3b4c5d6e7
Revises: e0f1a2b3c4d5
Create Date: 2026-08-10 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "f2a3b4c5d6e7"
down_revision = "e0f1a2b3c4d5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "match_evaluation_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("trigger_type", sa.String(length=32), nullable=False),
        sa.Column("asset_id", sa.String(length=128), nullable=True),
        sa.Column("vulnerability_id", sa.String(length=128), nullable=True),
        sa.Column("requested_by", sa.String(length=36), nullable=True),
        sa.Column("task_id", sa.String(length=255), nullable=True),
        sa.Column("active_scope_key", sa.String(length=64), nullable=True),
        sa.Column("total_count", sa.Integer(), nullable=False),
        sa.Column("processed_count", sa.Integer(), nullable=False),
        sa.Column("evaluated_count", sa.Integer(), nullable=False),
        sa.Column("skipped_count", sa.Integer(), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("sample_result_ids_json", sa.JSON(), nullable=False),
        sa.Column("recent_error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "status",
        "trigger_type",
        "asset_id",
        "vulnerability_id",
        "requested_by",
        "task_id",
        "started_at",
        "finished_at",
    ):
        op.create_index(
            op.f(f"ix_match_evaluation_runs_{column}"),
            "match_evaluation_runs",
            [column],
            unique=False,
        )
    op.create_index(
        op.f("ix_match_evaluation_runs_active_scope_key"),
        "match_evaluation_runs",
        ["active_scope_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("match_evaluation_runs")
