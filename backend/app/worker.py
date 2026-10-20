"""Celery application.

One queue per worker type, so each container only receives the work (and the
secrets) it needs: ``default``, ``collect``, ``ai`` and ``publish``.
State of record lives in PostgreSQL, so Celery results are not stored.
"""

from celery import Celery
from kombu import Queue

from app.core.config import get_settings

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
