"""Baseline: extensions needed by later phases.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-10-20 21:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Trusted extensions: creatable by the schema owner without superuser rights.
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")  # case-insensitive e-mails
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")  # fuzzy technology search


def downgrade() -> None:
    op.execute("DROP EXTENSION IF EXISTS pg_trgm")
    op.execute("DROP EXTENSION IF EXISTS citext")
