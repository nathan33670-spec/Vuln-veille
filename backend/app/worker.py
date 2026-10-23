"""Celery application.

One queue per worker type, so each container only receives the work (and the
secrets) it needs: ``default``, ``collect``, ``ai`` and ``publish``.
State of record lives in PostgreSQL, so Celery results are not stored.
"""

import asyncio
import uuid

from celery import Celery
from kombu import Queue

from app.core.config import get_settings
from app.core.mailer import Mail, deliver_smtp

QUEUES = ("default", "collect", "ai", "publish")


def create_celery() -> Celery:
    settings = get_settings()
    celery = Celery("vuln_veille", broker=settings.redis_url.get_secret_value())
    celery.conf.update(
        task_queues=[Queue(name) for name in QUEUES],
        task_default_queue="default",
        task_routes={
            "collect.*": {"queue": "collect"},
            "ai.*": {"queue": "ai"},
            "publish.*": {"queue": "publish"},
        },
        # JSON only: pickle would allow code execution from a tampered message.
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        task_ignore_result=True,
        # At-least-once delivery; tasks must be idempotent (spec 02 §5).
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_time_limit=30 * 60,
        task_soft_time_limit=29 * 60,
        broker_connection_retry_on_startup=True,
        worker_hijack_root_logger=False,
    )
    return celery


app = create_celery()


@app.task(name="default.ping")
def ping() -> str:
    return "pong"


@app.task(
    name="default.send_email",
    autoretry_for=(OSError,),
    retry_backoff=30,
    retry_kwargs={"max_retries": 5},
)
def send_email(to: str, subject: str, body: str) -> None:
    deliver_smtp(get_settings(), Mail(to=to, subject=subject, body=body))


def _check(connector_id: str, workspace_id: str | None) -> None:
    from app.connectors.runtime import check_connector  # noqa: PLC0415 - worker-only import

    asyncio.run(
        check_connector(
            get_settings(),
            uuid.UUID(connector_id),
            uuid.UUID(workspace_id) if workspace_id else None,
        )
    )


# "Test the connection", on the worker holding the family's keyring (ADR-013).
@app.task(name="collect.connector_check")
def collect_connector_check(connector_id: str, workspace_id: str | None) -> None:
    _check(connector_id, workspace_id)


@app.task(name="ai.connector_check")
def ai_connector_check(connector_id: str, workspace_id: str | None) -> None:
    _check(connector_id, workspace_id)


@app.task(name="publish.connector_check")
def publish_connector_check(connector_id: str, workspace_id: str | None) -> None:
    _check(connector_id, workspace_id)


@app.task(name="collect.connector_sync")
def connector_sync(connector_id: str) -> None:
    """Periodic synchronisation of a global catalogue connector (NVD, KEV, EPSS…)."""
    from app.connectors.jobs import run_sync  # noqa: PLC0415 - worker-only import

    asyncio.run(run_sync(get_settings(), uuid.UUID(connector_id)))


@app.task(name="collect.cve_fetch")
def cve_fetch(cve_id: str) -> None:
    """Fetches a CVE an analyst entered by hand, when the catalogue lacks it."""
    from app.catalog.fetch import fetch_cve  # noqa: PLC0415 - worker-only import

    asyncio.run(fetch_cve(get_settings(), cve_id))


# Workflow engine (spec 02 §5): the orchestrator on ``default``, node tasks on the queue
# of their type (the worker holding that family's keyring).


def _advance(run_id: str, workspace_id: str) -> None:
    from app.workflows.runner import advance_entry  # noqa: PLC0415 - worker-only import

    asyncio.run(advance_entry(get_settings(), uuid.UUID(run_id), uuid.UUID(workspace_id)))


def _node(node_run_id: str, workspace_id: str) -> None:
    from app.workflows.runner import node_entry  # noqa: PLC0415 - worker-only import

    asyncio.run(node_entry(get_settings(), uuid.UUID(node_run_id), uuid.UUID(workspace_id)))


@app.task(name="default.workflow_advance")
def workflow_advance(run_id: str, workspace_id: str) -> None:
    _advance(run_id, workspace_id)


@app.task(name="default.workflow_node")
def default_workflow_node(node_run_id: str, workspace_id: str) -> None:
    _node(node_run_id, workspace_id)


@app.task(name="collect.workflow_node")
def collect_workflow_node(node_run_id: str, workspace_id: str) -> None:
    _node(node_run_id, workspace_id)


@app.task(name="ai.workflow_node")
def ai_workflow_node(node_run_id: str, workspace_id: str) -> None:
    _node(node_run_id, workspace_id)


@app.task(name="ai.agent_run")
def agent_run(run_id: str, workspace_id: str) -> None:
    """One agent run (test, workflow node): engine on the llm keyring, tools on the
    agent's source connectors (ADR-027)."""
    from app.ai.agents.runtime import run_entry  # noqa: PLC0415 - worker-only import

    asyncio.run(run_entry(get_settings(), uuid.UUID(run_id), uuid.UUID(workspace_id)))


@app.task(name="ai.engine_probe")
def engine_probe(probe_id: str, connector_id: str, workspace_id: str | None) -> None:
    """A question asked from the interface to an engine's model (ADR-032)."""
    from app.ai.probe import run_probe  # noqa: PLC0415 - worker-only import

    asyncio.run(
        run_probe(
            get_settings(),
            uuid.UUID(probe_id),
            uuid.UUID(connector_id),
            uuid.UUID(workspace_id) if workspace_id else None,
        )
    )


@app.task(name="ai.evaluation_run")
def evaluation_run(run_id: str, workspace_id: str) -> None:
    """Engine evaluation bench: an agent version on the reference cases (spec 07 §4.6)."""
    from app.ai.evaluation.runner import evaluation_entry  # noqa: PLC0415 - worker-only import

    asyncio.run(evaluation_entry(get_settings(), uuid.UUID(run_id), uuid.UUID(workspace_id)))


@app.task(name="ai.bulletin_draft")
def bulletin_draft(request_id: str, workspace_id: str) -> None:
    """A bulletin draft, a regenerated field or a translation (spec 04 §3)."""
    from app.bulletins.runner import draft_entry  # noqa: PLC0415 - worker-only import

    asyncio.run(draft_entry(get_settings(), uuid.UUID(request_id), uuid.UUID(workspace_id)))


@app.task(name="default.publication_mail")
def publication_mail(event_id: str, workspace_id: str) -> None:
    """Bulletins by e-mail to the client users who asked for them (Q44, Q45)."""
    from app.portal.mailing import publication_mail_entry  # noqa: PLC0415 - worker-only

    asyncio.run(
        publication_mail_entry(get_settings(), uuid.UUID(event_id), uuid.UUID(workspace_id))
    )


@app.task(name="publish.push")
def publish_push(publication_id: str, workspace_id: str) -> None:
    """One attempt of a push to a publication connector (spec 05 §4)."""
    from app.publish.runner import push_entry  # noqa: PLC0415 - worker-only import

    asyncio.run(push_entry(get_settings(), uuid.UUID(publication_id), uuid.UUID(workspace_id)))


@app.task(name="publish.workflow_node")
def publish_workflow_node(node_run_id: str, workspace_id: str) -> None:
    _node(node_run_id, workspace_id)


@app.task(name="default.workflow_webhook")
def workflow_webhook(trigger_id: str, timestamp: str, signature: str, body: str) -> None:
    """Incoming webhook, verified here: this worker holds the ``webhook`` keyring."""
    import base64  # noqa: PLC0415

    from app.workflows.runner import webhook_entry  # noqa: PLC0415 - worker-only import

    asyncio.run(
        webhook_entry(
            get_settings(), uuid.UUID(trigger_id), timestamp, signature, base64.b64decode(body)
        )
    )
