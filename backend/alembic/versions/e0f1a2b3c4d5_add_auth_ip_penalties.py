"""add auth ip penalties

Revision ID: e0f1a2b3c4d5
Revises: d9e8f7a6b5c4
Create Date: 2026-08-07 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "e0f1a2b3c4d5"
down_revision = "d9e8f7a6b5c4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_ip_penalties",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("ip_key", sa.String(length=64), nullable=False),
        sa.Column("last_ip_address", sa.String(length=45), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("banned_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_permanent", sa.Boolean(), nullable=False),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_banned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_by", sa.String(length=255), nullable=True),
        sa.Column("release_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_auth_ip_penalties_banned_until"),
        "auth_ip_penalties",
        ["banned_until"],
        unique=False,
    )
    op.create_index(
        op.f("ix_auth_ip_penalties_ip_key"),
        "auth_ip_penalties",
        ["ip_key"],
        unique=True,
    )
    op.create_index(
        op.f("ix_auth_ip_penalties_is_permanent"),
        "auth_ip_penalties",
        ["is_permanent"],
        unique=False,
    )
    op.create_index(
        op.f("ix_auth_ip_penalties_level"),
        "auth_ip_penalties",
        ["level"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_auth_ip_penalties_level"), table_name="auth_ip_penalties"
    )
    op.drop_index(
        op.f("ix_auth_ip_penalties_is_permanent"),
        table_name="auth_ip_penalties",
    )
    op.drop_index(
        op.f("ix_auth_ip_penalties_ip_key"), table_name="auth_ip_penalties"
    )
    op.drop_index(
        op.f("ix_auth_ip_penalties_banned_until"),
        table_name="auth_ip_penalties",
    )
    op.drop_table("auth_ip_penalties")

