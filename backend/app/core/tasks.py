"""Background task dispatch from the APIs (the workers run them, ADR-005).

The APIs never import task code: they send a task by name to its queue. Tests use
``MemoryTaskQueue`` to assert what would have been sent.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol


class TaskQueue(Protocol):
    def send(
        self, name: str, kwargs: dict[str, Any], *, task_id: str | None = None, countdown: int = 0
    ) -> None: ...

    def revoke(self, task_id: str) -> None: ...


class CeleryTaskQueue:
    def send(
        self, name: str, kwargs: dict[str, Any], *, task_id: str | None = None, countdown: int = 0
    ) -> None:
        from app.worker import app  # noqa: PLC0415 - avoid importing Celery at app import

        app.send_task(name, kwargs=kwargs, task_id=task_id, countdown=countdown or None)

    def revoke(self, task_id: str) -> None:
        from app.worker import app  # noqa: PLC0415

        app.control.revoke(task_id, terminate=False)


@dataclass
class MemoryTaskQueue:
    sent: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    revoked: list[str] = field(default_factory=list)

    def send(
        self, name: str, kwargs: dict[str, Any], *, task_id: str | None = None, countdown: int = 0
    ) -> None:
        self.sent.append((name, kwargs))

    def revoke(self, task_id: str) -> None:
        self.revoked.append(task_id)
