"""add structured match identities

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-08-11 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "a3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


ASSET_COMPONENT_COLUMNS = (
    ("ecosystem", sa.String(length=32)),
    ("distro", sa.String(length=64)),
    ("distro_release", sa.String(length=64)),
    ("source_package", sa.String(length=255)),
    ("binary_package", sa.String(length=255)),
    ("architecture", sa.String(length=64)),
    ("flavor", sa.String(length=64)),
    ("version_scheme", sa.String(length=32)),
    ("purl", sa.String(length=512)),
    ("cpe", sa.String(length=512)),
)

SCOPE_NULLABLE_COLUMNS = (
    ("ecosystem", sa.String(length=32)),
    ("distro", sa.String(length=64)),
    ("distro_release", sa.String(length=64)),
    ("source_package", sa.String(length=255)),
    ("binary_package", sa.String(length=255)),
    ("architecture", sa.String(length=64)),
    ("flavor", sa.String(length=64)),
    ("version_scheme", sa.String(length=32)),
    ("version_type", sa.String(length=64)),
    ("default_status", sa.String(length=32)),
    ("purl", sa.String(length=512)),
    ("cpe", sa.String(length=512)),
)


def upgrade() -> None:
    for name, column_type in ASSET_COMPONENT_COLUMNS:
        op.add_column(
            "asset_components",
            sa.Column(name, column_type, nullable=True),
        )
    for name in ("ecosystem", "distro", "source_package", "binary_package"):
        op.create_index(
            op.f(f"ix_asset_components_{name}"),
            "asset_components",
            [name],
            unique=False,
        )

    for name, column_type in SCOPE_NULLABLE_COLUMNS:
        op.add_column(
            "vulnerability_affected_scopes",
            sa.Column(name, column_type, nullable=True),
        )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="affected",
        ),
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column(
            "source_authority",
            sa.String(length=32),
            nullable=False,
            server_default="unknown",
        ),
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column(
            "authority_score",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column(
            "platforms_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )
    op.add_column(
        "vulnerability_affected_scopes",
        sa.Column(
            "structured_versions_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )
    for name in (
        "ecosystem",
        "distro",
        "source_package",
        "binary_package",
        "status",
    ):
        op.create_index(
            op.f(f"ix_vulnerability_affected_scopes_{name}"),
            "vulnerability_affected_scopes",
            [name],
            unique=False,
        )


def downgrade() -> None:
    for name in reversed(
        ("ecosystem", "distro", "source_package", "binary_package", "status")
    ):
        op.drop_index(
            op.f(f"ix_vulnerability_affected_scopes_{name}"),
            table_name="vulnerability_affected_scopes",
        )
    for name in (
        "structured_versions_json",
        "platforms_json",
        "authority_score",
        "source_authority",
        "status",
    ):
        op.drop_column("vulnerability_affected_scopes", name)
    for name, _column_type in reversed(SCOPE_NULLABLE_COLUMNS):
        op.drop_column("vulnerability_affected_scopes", name)

    for name in reversed(("ecosystem", "distro", "source_package", "binary_package")):
        op.drop_index(
            op.f(f"ix_asset_components_{name}"),
            table_name="asset_components",
        )
    for name, _column_type in reversed(ASSET_COMPONENT_COLUMNS):
        op.drop_column("asset_components", name)
