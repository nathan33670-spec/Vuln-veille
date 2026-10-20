"""Background task dispatch from the APIs (the workers run them, ADR-005).

The APIs never import task code: they send a task by name to its queue. Tests use
``MemoryTaskQueue`` to assert what would have been sent.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol


class TaskQueue(Protocol):
    def send(self, name: str, kwargs: dict[str, Any]) -> None: ...


class CeleryTaskQueue:
    def send(self, name: str, kwargs: dict[str, Any]) -> None:
        from app.worker import app  # noqa: PLC0415 - avoid importing Celery at app import

        app.send_task(name, kwargs=kwargs)


@dataclass
class MemoryTaskQueue:
    sent: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def send(self, name: str, kwargs: dict[str, Any]) -> None:
        self.sent.append((name, kwargs))
