"""purge data left by failed intel generations

Revision ID: d6e7f8091a2b
Revises: c5d6e7f8091a
Create Date: 2026-08-12 14:45:00.000000
"""

from __future__ import annotations

from alembic import op


revision = "d6e7f8091a2b"
down_revision = "c5d6e7f8091a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Historical generations predate staging_generation_id. Mark only records
    # whose creation timestamp falls inside the failed run that contributed
    # them and which have never been materialized by another source.
    op.execute(
        """
        UPDATE vulnerabilities AS vulnerability
        SET staging_generation_id = candidate.generation_id
        FROM (
            SELECT DISTINCT ON (contribution.vulnerability_id)
                contribution.vulnerability_id,
                contribution.generation_id
            FROM vulnerability_source_contributions AS contribution
            JOIN intel_collection_runs AS run
              ON run.generation_id = contribution.generation_id
             AND run.status = 'failed'
            JOIN vulnerabilities AS created
              ON created.id = contribution.vulnerability_id
             AND created.created_at >= run.started_at
             AND created.created_at <= COALESCE(run.finished_at, run.updated_at)
            WHERE contribution.is_active IS FALSE
            ORDER BY contribution.vulnerability_id, run.started_at
        ) AS candidate
        WHERE vulnerability.id = candidate.vulnerability_id
          AND vulnerability.staging_generation_id IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM vulnerability_sources AS source
              WHERE source.vulnerability_id = vulnerability.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM vulnerability_source_contributions AS active_contribution
              WHERE active_contribution.vulnerability_id = vulnerability.id
                AND active_contribution.is_active IS TRUE
          )
        """
    )
    op.execute(
        """
        DELETE FROM vulnerability_affected_scopes AS scope
        USING intel_collection_runs AS run
        WHERE run.status = 'failed'
          AND scope.generation_id = run.generation_id
        """
    )
    op.execute(
        """
        DELETE FROM vulnerability_source_contributions AS contribution
        USING intel_collection_runs AS run
        WHERE run.status = 'failed'
          AND contribution.generation_id = run.generation_id
        """
    )
    op.execute(
        """
        DELETE FROM intel_raw_events AS raw_event
        USING intel_collection_runs AS run
        WHERE run.status = 'failed'
          AND raw_event.generation_id = run.generation_id
        """
    )
    op.execute(
        """
        DELETE FROM vulnerabilities AS vulnerability
        WHERE vulnerability.staging_generation_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM vulnerability_sources AS source
              WHERE source.vulnerability_id = vulnerability.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM vulnerability_source_contributions AS contribution
              WHERE contribution.vulnerability_id = vulnerability.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM vulnerability_affected_scopes AS scope
              WHERE scope.vulnerability_id = vulnerability.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM intel_raw_events AS raw_event
              WHERE raw_event.vulnerability_id = vulnerability.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM match_results AS result
              WHERE result.vulnerability_id = vulnerability.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM vulnerability_ai_enrichments AS enrichment
              WHERE enrichment.vulnerability_id = vulnerability.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM vulnerability_review_resolutions AS resolution
              WHERE resolution.vulnerability_id = vulnerability.id
          )
        """
    )
    op.execute(
        """
        UPDATE vulnerabilities
        SET staging_generation_id = NULL
        WHERE staging_generation_id IS NOT NULL
        """
    )


def downgrade() -> None:
    # Purged failed staging data was never active and is intentionally not
    # reconstructed on downgrade.
    pass
