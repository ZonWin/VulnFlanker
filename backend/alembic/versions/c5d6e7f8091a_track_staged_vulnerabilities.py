"""track vulnerabilities created by staged intel generations

Revision ID: c5d6e7f8091a
Revises: b4c5d6e7f809
Create Date: 2026-08-12 12:30:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "c5d6e7f8091a"
down_revision = "b4c5d6e7f809"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("staging_generation_id", sa.String(length=36), nullable=True),
    )
    op.create_index(
        op.f("ix_vulnerabilities_staging_generation_id"),
        "vulnerabilities",
        ["staging_generation_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_vulnerabilities_staging_generation_id"),
        table_name="vulnerabilities",
    )
    op.drop_column("vulnerabilities", "staging_generation_id")
