"""AI task runs without an agent (phase 4, step 4.13).

``ai.summarize``, ``ai.classify``, ``ai.extract`` and ``ai.relevance`` call the engine
through the agent runtime with a fixed configuration built by the node: their runs
carry that configuration (``spec``) and the node type (``task``) instead of an agent
version. Every run keeps the same tracing, accounting and budget checks.

Revision ID: 0011_ai_tasks
Revises: 0010_agents
Create Date: 2026-10-28 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0011_ai_tasks"
down_revision: str | None = "0010_agents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    execute_script(
        """
ALTER TABLE agent_runs ALTER COLUMN agent_id DROP NOT NULL;
ALTER TABLE agent_runs ALTER COLUMN agent_version_id DROP NOT NULL;
ALTER TABLE agent_runs ADD COLUMN task text CHECK (length(task) <= 64);
ALTER TABLE agent_runs ADD COLUMN spec jsonb;
ALTER TABLE agent_runs ADD CONSTRAINT ck_agent_runs_configuration CHECK (
    (agent_version_id IS NOT NULL AND agent_id IS NOT NULL AND task IS NULL AND spec IS NULL)
    OR (agent_version_id IS NULL AND agent_id IS NULL AND task IS NOT NULL AND spec IS NOT NULL)
);
"""
    )


def downgrade() -> None:
    execute_script(
        """
DELETE FROM agent_runs WHERE agent_id IS NULL;
ALTER TABLE agent_runs DROP CONSTRAINT ck_agent_runs_configuration;
ALTER TABLE agent_runs DROP COLUMN spec;
ALTER TABLE agent_runs DROP COLUMN task;
ALTER TABLE agent_runs ALTER COLUMN agent_version_id SET NOT NULL;
ALTER TABLE agent_runs ALTER COLUMN agent_id SET NOT NULL;
"""
    )
