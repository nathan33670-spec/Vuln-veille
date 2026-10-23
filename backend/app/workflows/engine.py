"""Workflow executor (spec 02 §5).

- ``start_run`` records a run, frozen on a version; a run is unique per
  ``(workflow, idempotency_key)`` so a replayed trigger starts nothing twice.
- ``advance`` (the orchestrator, queue ``default``) holds the run's row lock, works out
  which nodes are ready and queues one task per node on its type's queue. It is
  idempotent: any number of concurrent or replayed calls converge.
- ``execute_node`` (the node task) claims its ``node_run`` atomically, runs the node
  and writes its bounded output and status in the same transaction as the node's own
  database effects, then asks the orchestrator to advance.
- ``sweep`` (scheduler) recovers lost work: tasks whose worker died, lost messages,
  runs waiting for a concurrency slot, runs past their deadline.
"""

import asyncio
import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ai.agents.invoke import WorkerAgents
from app.ai.agents.runtime import AgentDeps, EngineFactory
from app.connectors.base import ConnectorContext
from app.connectors.models import Connector
from app.connectors.quotas import QuotaExceededError
from app.connectors.runtime import build_context
from app.core.config import Settings
from app.core.ids import uuid7
from app.core.logging import get_logger
from app.core.rls import init_context, set_context
from app.core.tasks import TaskQueue
from app.net.safe_http import EgressError, SafeHttpClient
from app.vault.crypto import VaultError
from app.vault.service import Vault
from app.workflows.base import (
    Item,
    NodeCategory,
    NodeContext,
    NodeError,
    Outputs,
    RunInfo,
)
from app.workflows.expressions import ExpressionError
from app.workflows.graph import Compiled, GraphValidationError, compile_graph
from app.workflows.models import NodeRun, Workflow, WorkflowApproval, WorkflowRun, WorkflowVersion
from app.workflows.repo import WorkspaceRepo

log = get_logger(__name__)

ADVANCE_TASK = "default.workflow_advance"
NODE_TASK = "{queue}.workflow_node"
MAIL_TASK = "default.send_email"
TERMINAL_RUN = frozenset({"succeeded", "failed", "cancelled", "timed_out"})
ACTIVE_NODE = frozenset({"queued", "running", "waiting_approval"})
MAX_ERROR = 500
SWEEP_GRACE = timedelta(minutes=2)
LOST_MESSAGE_AFTER = timedelta(minutes=10)
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class Limits:
    """Defaults of spec 02 §5 (per-workspace overrides come with workspace settings)."""

    max_items_per_output: int = 5000
    max_item_bytes: int = 256 * 1024
    max_output_bytes: int = 5 * 1024 * 1024
    max_payload_bytes: int = 256 * 1024
    run_timeout: timedelta = timedelta(minutes=30)
    concurrent_per_workflow: int = 5
    concurrent_per_workspace: int = 20


LIMITS = Limits()


@dataclass
class EngineDeps:
    sessions: async_sessionmaker[AsyncSession]
    tasks: TaskQueue
    settings: Settings
    clock: Clock = field(default=lambda: datetime.now(UTC))
    limits: Limits = LIMITS
    redis: Redis | None = None
    http: SafeHttpClient | None = None  # tests: replaces every connector's client
    agent_engine: EngineFactory | None = None  # tests: a simulated AI engine
    vault: Vault | None = None  # tests: keyrings given directly

    def agents(self, workspace_id: uuid.UUID) -> WorkerAgents:
        deps = AgentDeps(
            self.settings,
            self.vault or Vault.from_settings(self.settings),
            clock=self.clock,
            redis=self.redis,
            tasks=self.tasks,
            http=self.http,
            engine_for=self.agent_engine,
        )
        return WorkerAgents(self.sessions, deps, workspace_id)


# Bounded outputs ---------------------------------------------------------------


def _normalised(entry: Any) -> Item | None:
    if not isinstance(entry, dict) or not isinstance(entry.get("json"), dict):
        return None
    meta = entry.get("meta") if isinstance(entry.get("meta"), dict) else {}
    loaded: Item = json.loads(json.dumps({"json": entry["json"], "meta": meta}, default=str))
    return loaded


def bound_outputs(
    outputs: Outputs, ports: tuple[str, ...], limits: Limits = LIMITS
) -> tuple[dict[str, list[Item]], int, bool]:
    """Keeps declared ports, JSON items, and the item, size and total limits."""
    bounded: dict[str, list[Item]] = {}
    count, total, truncated = 0, 0, False
    for port in ports:
        kept: list[Item] = []
        for raw in outputs.get(port, []) or []:
            entry = _normalised(raw)
            if entry is None:
                truncated = True
                continue
            size = len(json.dumps(entry))
            if (
                size > limits.max_item_bytes
                or count >= limits.max_items_per_output
                or total + size > limits.max_output_bytes
            ):
                truncated = True
                continue
            kept.append(entry)
            count += 1
            total += size
        bounded[port] = kept
    if set(outputs) - set(ports):
        truncated = True
    return bounded, count, truncated


# Runs --------------------------------------------------------------------------


class RunRefusedError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


async def start_run(
    db: AsyncSession,
    workflow: Workflow,
    version: WorkflowVersion,
    *,
    trigger_node_id: str,
    trigger_type: str,
    payload: dict[str, Any],
    idempotency_key: str | None,
    now: datetime,
    actor: uuid.UUID | None = None,
    limits: Limits = LIMITS,
) -> uuid.UUID | None:
    """Records a queued run; None if this idempotency key already started one."""
    if len(json.dumps(payload, default=str)) > limits.max_payload_bytes:
        raise RunRefusedError("payload_too_large")
    run_id = uuid7()
    inserted = await db.execute(
        insert(WorkflowRun)
        .values(
            id=run_id,
            workspace_id=workflow.workspace_id,
            workflow_id=workflow.id,
            version_id=version.id,
            trigger_type=trigger_type,
            trigger_node_id=trigger_node_id,
            triggered_by=actor,
            trigger_payload=json.loads(json.dumps(payload, default=str)),
            idempotency_key=idempotency_key,
            status="queued",
            cancel_requested=False,
            queued_at=now,
            stats={},
        )
        .on_conflict_do_nothing(constraint="uq_workflow_runs_idempotency")
        .returning(WorkflowRun.id)
    )
    return inserted.scalar_one_or_none()


def advance_task(tasks: TaskQueue, run_id: uuid.UUID, workspace_id: uuid.UUID) -> None:
    tasks.send(ADVANCE_TASK, {"run_id": str(run_id), "workspace_id": str(workspace_id)})


_COMPILED: dict[uuid.UUID, Compiled] = {}


def compiled_version(version: WorkflowVersion) -> Compiled:
    """Versions are immutable: their compiled form is cached by id."""
    cached = _COMPILED.get(version.id)
    if cached is None:
        cached = compile_graph(version.graph)
        if len(_COMPILED) > 500:  # noqa: PLR2004 - bounded cache
            _COMPILED.clear()
        _COMPILED[version.id] = cached
    return cached


async def compiled_run(db: AsyncSession, run: WorkflowRun) -> Compiled:
    """The graph a run executes: its version's, or the edited one of a test run."""
    if run.mode == "test":
        assert run.test_graph is not None  # noqa: S101 - database constraint
        return compile_graph(run.test_graph)
    version = await db.get(WorkflowVersion, run.version_id)
    assert version is not None  # noqa: S101 - foreign key
    return compiled_version(version)


def _latest(node_runs: list[NodeRun]) -> dict[str, NodeRun]:
    latest: dict[str, NodeRun] = {}
    for node_run in node_runs:
        current = latest.get(node_run.node_id)
        if current is None or node_run.attempt > current.attempt:
            latest[node_run.node_id] = node_run
    return latest


def _settled(compiled: Compiled, node_run: NodeRun | None) -> bool:
    """Final state from which downstream nodes may proceed."""
    if node_run is None:
        return False
    if node_run.status in ("succeeded", "skipped"):
        return True
    if node_run.status == "failed":
        settings = compiled.graph.node(node_run.node_id).settings
        return node_run.attempt >= settings.retry.max_attempts and settings.on_error != "stop"
    return False


def gather_inputs(compiled: Compiled, node_id: str, latest: dict[str, NodeRun]) -> Outputs:
    inputs: Outputs = {port: [] for port in compiled.types[node_id].inputs}
    for source, source_port, target_port in compiled.upstream.get(node_id, []):
        parent = latest.get(source)
        if parent is None or parent.status not in ("succeeded", "failed"):
            continue
        if parent.status == "failed" and source_port != "error":
            continue
        inputs.setdefault(target_port, []).extend(parent.output.get(source_port, []))
    return inputs


async def _slot_available(db: AsyncSession, run: WorkflowRun, limits: Limits) -> bool:
    # Serialises starts within a workspace so two runs cannot take the last slot.
    digest = hashlib.sha256(f"workflow_slots:{run.workspace_id}".encode()).digest()
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:id)"),
        {"id": int.from_bytes(digest[:8], "big", signed=True)},
    )
    running = select(func.count()).where(
        WorkflowRun.workspace_id == run.workspace_id, WorkflowRun.status == "running"
    )
    in_workspace = (await db.execute(running)).scalar_one()
    in_workflow = (
        await db.execute(running.where(WorkflowRun.workflow_id == run.workflow_id))
    ).scalar_one()
    return (
        in_workspace < limits.concurrent_per_workspace
        and in_workflow < limits.concurrent_per_workflow
    )


def _new_node_run(
    run: WorkflowRun, node_id: str, attempt: int, status: str, queue: str, now: datetime
) -> NodeRun:
    return NodeRun(
        id=uuid7(),
        workspace_id=run.workspace_id,
        run_id=run.id,
        node_id=node_id,
        attempt=attempt,
        status=status,
        queue=queue,
        scheduled_at=now,
        input_count=0,
        output={},
        output_count=0,
        output_truncated=False,
        logs=[],
        metrics={},
    )


@dataclass
class _Advance:
    db: AsyncSession
    run: WorkflowRun
    compiled: Compiled
    latest: dict[str, NodeRun]
    now: datetime
    tasks: TaskQueue
    limits: Limits
    queued: list[NodeRun] = field(default_factory=list)
    countdowns: dict[uuid.UUID, int] = field(default_factory=dict)
    approvals: list[str] = field(default_factory=list)

    def add(self, node_run: NodeRun) -> None:
        self.db.add(node_run)
        self.latest[node_run.node_id] = node_run

    def queue(self, node_id: str, attempt: int, inputs: Outputs, countdown: int = 0) -> None:
        node_type = self.compiled.types[node_id]
        node_run = _new_node_run(self.run, node_id, attempt, "queued", node_type.queue, self.now)
        node_run.input_count = sum(len(v) for v in inputs.values())
        node_run.task_id = str(node_run.id)
        settings = self.compiled.graph.node(node_id).settings
        node_run.metrics = {"timeout_seconds": settings.timeout_seconds}
        node_run.scheduled_at = self.now + timedelta(seconds=countdown)
        self.add(node_run)
        self.queued.append(node_run)
        self.countdowns[node_run.id] = countdown

    def trigger(self, node_id: str) -> None:
        if node_id != self.run.trigger_node_id:
            self.add(_new_node_run(self.run, node_id, 1, "skipped", "default", self.now))
            return
        node_run = _new_node_run(self.run, node_id, 1, "succeeded", "default", self.now)
        payload = {
            "json": self.run.trigger_payload,
            "meta": {"source": f"trigger.{self.run.trigger_type}"},
        }
        node_run.output = {"out": [payload]}
        node_run.output_count = 1
        node_run.started_at = node_run.finished_at = self.now
        self.add(node_run)

    def step(self, node_id: str) -> bool:  # noqa: PLR0911 - one return per node state
        """Moves one node forward; True if something changed."""
        node_type = self.compiled.types[node_id]
        latest = self.latest.get(node_id)
        if latest is None:
            if node_type.category == NodeCategory.TRIGGER:
                self.trigger(node_id)
                return True
            parents = {src for src, _, _ in self.compiled.upstream.get(node_id, [])}
            if not all(_settled(self.compiled, self.latest.get(p)) for p in parents):
                return False
            inputs = gather_inputs(self.compiled, node_id, self.latest)
            if not any(inputs.values()) and not node_type.runs_without_items:
                self.add(_new_node_run(self.run, node_id, 1, "skipped", node_type.queue, self.now))
                return True
            if node_type.waits_for_approval:
                self.wait_for_approval(node_id, inputs)
                return True
            self.queue(node_id, 1, inputs)
            return True
        if latest.status == "failed":
            settings = self.compiled.graph.node(node_id).settings
            if latest.attempt < settings.retry.max_attempts and latest.error != "cancelled":
                inputs = gather_inputs(self.compiled, node_id, self.latest)
                backoff = settings.retry.backoff_seconds * latest.attempt
                self.queue(node_id, latest.attempt + 1, inputs, countdown=backoff)
                return True
        return False

    def wait_for_approval(self, node_id: str, inputs: Outputs) -> None:
        node_run = _new_node_run(self.run, node_id, 1, "waiting_approval", "default", self.now)
        node_run.input_count = sum(len(v) for v in inputs.values())
        node_run.output = {"pending": inputs.get("in", [])}
        self.add(node_run)
        self.db.add(
            WorkflowApproval(
                id=uuid7(),
                workspace_id=self.run.workspace_id,
                run_id=self.run.id,
                node_id=node_id,
                requested_at=self.now,
                comment="",
            )
        )
        self.approvals.append(node_id)

    def stopping_failure(self) -> NodeRun | None:
        for node_run in self.latest.values():
            if node_run.status != "failed":
                continue
            settings = self.compiled.graph.node(node_run.node_id).settings
            if settings.on_error == "stop" and node_run.attempt >= settings.retry.max_attempts:
                return node_run
        return None


def _finish(run: WorkflowRun, status: str, now: datetime, error: str | None = None) -> None:
    run.status = status
    run.finished_at = now
    if error:
        run.error = error[:MAX_ERROR]


def _stats(latest: dict[str, NodeRun]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for node_run in latest.values():
        counts[node_run.status] = counts.get(node_run.status, 0) + 1
    return {"nodes": counts, "items": sum(n.output_count for n in latest.values())}


def _stop_active(state: _Advance, reason: str) -> None:
    for node_run in state.latest.values():
        if node_run.status in ACTIVE_NODE:
            if node_run.status == "running" and node_run.task_id:
                state.tasks.revoke(node_run.task_id)
            node_run.status = "cancelled"
            node_run.error = reason
            node_run.finished_at = state.now


async def advance(
    db: AsyncSession, run_id: uuid.UUID, tasks: TaskQueue, now: datetime, limits: Limits = LIMITS
) -> str | None:
    """One orchestration step under the run's row lock; returns the run status."""
    run = (
        await db.execute(select(WorkflowRun).where(WorkflowRun.id == run_id).with_for_update())
    ).scalar_one_or_none()
    if run is None or run.status in TERMINAL_RUN:
        await db.commit()
        return run.status if run else None
    try:
        compiled = await compiled_run(db, run)
    except GraphValidationError:
        _finish(run, "failed", now, "invalid_graph")
        await db.commit()
        return run.status
    node_runs = list((await db.execute(select(NodeRun).where(NodeRun.run_id == run.id))).scalars())
    state = _Advance(db, run, compiled, _latest(node_runs), now, tasks, limits)

    if run.cancel_requested:
        _stop_active(state, "cancelled")
        _finish(run, "cancelled", now)
    elif run.status == "queued" and not await _slot_available(db, run, limits):
        await db.commit()
        return run.status
    else:
        if run.status == "queued":
            run.status, run.started_at = "running", now
            run.deadline_at = now + limits.run_timeout
        if run.status == "running" and run.deadline_at and now > run.deadline_at:
            _stop_active(state, "run_timed_out")
            _finish(run, "timed_out", now, "run_timed_out")
        elif run.mode == "test":
            _progress_test(state)
        else:
            _progress(state)
    run.stats = _stats(state.latest)
    await db.flush()
    status = run.status
    queued = [(n.id, n.queue, n.task_id, state.countdowns.get(n.id, 0)) for n in state.queued]
    approvals = list(state.approvals)
    workspace_id, workflow_id = run.workspace_id, run.workflow_id
    await db.commit()

    for node_run_id, queue, task_id, countdown in queued:
        tasks.send(
            NODE_TASK.format(queue=queue),
            {"node_run_id": str(node_run_id), "workspace_id": str(workspace_id)},
            task_id=task_id,
            countdown=countdown,
        )
    if approvals:
        await _notify_approvals(db, tasks, workspace_id, workflow_id, run_id, approvals)
    if status in TERMINAL_RUN:
        await _wake_queued(db, tasks, workspace_id)
    return status


def _progress_test(state: _Advance) -> None:
    """A test run (editor): the node under test only, once, with its pinned inputs."""
    run = state.run
    node_id = run.test_node_id or ""
    latest = state.latest.get(node_id)
    if latest is None:
        state.queue(node_id, 1, run.test_inputs or {})
    elif latest.status in ("succeeded", "skipped"):
        _finish(run, "succeeded", state.now)
    elif latest.status == "failed":
        _finish(run, "failed", state.now, latest.error)


def _progress(state: _Advance) -> None:
    for _ in range(len(state.compiled.order) + 1):
        failure = state.stopping_failure()
        if failure is not None:
            _stop_active(state, "run_failed")
            _finish(state.run, "failed", state.now, f"{failure.node_id}: {failure.error}")
            return
        changed = False
        for node_id in state.compiled.order:
            changed = state.step(node_id) or changed
        if not changed:
            break
    statuses = {n.status for n in state.latest.values()}
    every_node = len(state.latest) == len(state.compiled.order)
    if every_node and not statuses & ACTIVE_NODE:
        _finish(state.run, "succeeded", state.now)
    elif "waiting_approval" in statuses and not statuses & {"queued", "running"}:
        state.run.status = "waiting_approval"
    else:
        state.run.status = "running"


async def _notify_approvals(
    db: AsyncSession,
    tasks: TaskQueue,
    workspace_id: uuid.UUID,
    workflow_id: uuid.UUID,
    run_id: uuid.UUID,
    nodes: list[str],
) -> None:
    workflow = await db.get(Workflow, workflow_id)
    repo = WorkspaceRepo(db, workspace_id, datetime.now(UTC))
    subject = f"[Vuln-Veille] Validation attendue : {workflow.name if workflow else ''}"[:200]
    body = (
        "Une exécution attend votre validation dans l'espace de travail.\n"
        f"Exécution : {run_id}\nÉtape(s) : {', '.join(nodes)}\n"
    )
    for email in await repo.analyst_emails():
        tasks.send(MAIL_TASK, {"to": email, "subject": subject, "body": body})
    await db.commit()


async def _wake_queued(db: AsyncSession, tasks: TaskQueue, workspace_id: uuid.UUID) -> None:
    rows = await db.execute(
        select(WorkflowRun.id)
        .where(WorkflowRun.workspace_id == workspace_id, WorkflowRun.status == "queued")
        .order_by(WorkflowRun.queued_at)
        .limit(LIMITS.concurrent_per_workspace)
    )
    for (queued_id,) in rows.all():
        advance_task(tasks, queued_id, workspace_id)
    await db.commit()


async def decide_approval(
    db: AsyncSession,
    run: WorkflowRun,
    node_id: str,
    *,
    approved: bool,
    actor: uuid.UUID,
    comment: str,
    now: datetime,
    limits: Limits = LIMITS,
) -> bool:
    """Records a decision; False if nothing was waiting (already decided)."""
    node_run = (
        await db.execute(
            select(NodeRun)
            .where(
                NodeRun.run_id == run.id,
                NodeRun.node_id == node_id,
                NodeRun.status == "waiting_approval",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    approval = (
        await db.execute(
            select(WorkflowApproval).where(
                WorkflowApproval.run_id == run.id, WorkflowApproval.node_id == node_id
            )
        )
    ).scalar_one_or_none()
    if node_run is None or approval is None or approval.decision is not None:
        return False
    items = node_run.output.get("pending", [])
    port = "approved" if approved else "rejected"
    node_run.output = {"approved": [], "rejected": [], port: items}
    node_run.output_count = len(items)
    node_run.status = "succeeded"
    node_run.finished_at = now
    approval.decision = port
    approval.decided_by = actor
    approval.decided_at = now
    approval.comment = comment[:2000]
    if run.status == "waiting_approval":
        run.status = "running"
        run.deadline_at = now + limits.run_timeout  # waiting time does not count
    return True


# Node tasks --------------------------------------------------------------------


@dataclass
class WorkerConnectors:
    """Connector access for a node: the run's workspace connectors and global ones."""

    db: AsyncSession
    deps: EngineDeps
    workspace_id: uuid.UUID
    vault: Vault | None = None

    async def open(self, connector_id: uuid.UUID, kinds: tuple[str, ...]) -> ConnectorContext:
        connector = await self.db.get(Connector, connector_id)
        if (
            connector is None
            or connector.kind not in kinds
            or connector.workspace_id not in (None, self.workspace_id)
        ):
            raise NodeError("connector_not_found")
        if not connector.enabled:
            raise NodeError("connector_disabled")
        vault = self.vault or Vault.from_settings(self.deps.settings)
        try:
            _, context = await build_context(
                self.db, self.deps.settings, vault, connector, self.deps.redis
            )
        except EgressError as exc:
            raise NodeError(f"egress: {exc.code}") from None
        except VaultError:
            raise NodeError("secret_unavailable") from None
        except (ValidationError, KeyError):
            raise NodeError("invalid_connector_configuration") from None
        if self.deps.http is not None:
            context.http = self.deps.http
        return context


async def _claim(db: AsyncSession, node_run_id: uuid.UUID, now: datetime) -> bool:
    claimed = await db.execute(
        update(NodeRun)
        .where(NodeRun.id == node_run_id, NodeRun.status == "queued")
        .values(status="running", started_at=now, heartbeat_at=now)
        .returning(NodeRun.id)
    )
    return claimed.scalar_one_or_none() is not None


def _error_items(node_id: str, code: str, inputs: Outputs) -> list[Item]:
    return [
        {"json": {"error": code, "node": node_id, "item": entry.get("json", {})}, "meta": {}}
        for entry in inputs.get("in", [])[:100]
    ] or [{"json": {"error": code, "node": node_id}, "meta": {}}]


async def execute_node(
    deps: EngineDeps, node_run_id: uuid.UUID, workspace_id: uuid.UUID, *, dry_run: bool = False
) -> str | None:
    """Runs one node task; returns the node_run's final status (None: nothing to do)."""
    async with deps.sessions() as db:
        init_context(db)
        await set_context(db, workspace_ids=(workspace_id,))
        now = deps.clock()
        if not await _claim(db, node_run_id, now):
            await db.commit()
            return None
        node_run = await db.get(NodeRun, node_run_id)
        assert node_run is not None  # noqa: S101 - just claimed
        run = await db.get(WorkflowRun, node_run.run_id)
        assert run is not None  # noqa: S101 - foreign key
        if run.cancel_requested or run.status in TERMINAL_RUN:
            node_run.status, node_run.error, node_run.finished_at = "cancelled", "cancelled", now
            await db.commit()
            advance_task(deps.tasks, run.id, workspace_id)
            return "cancelled"
        run_id = run.id
        await db.commit()
        status = await _run_node(deps, db, run, node_run, dry_run=dry_run)
    advance_task(deps.tasks, run_id, workspace_id)
    return status


async def _run_node(
    deps: EngineDeps, db: AsyncSession, run: WorkflowRun, node_run: NodeRun, *, dry_run: bool
) -> str:
    workflow = await db.get(Workflow, run.workflow_id)
    assert workflow is not None  # noqa: S101 - foreign key
    compiled = await compiled_run(db, run)
    testing = run.mode == "test"
    dry_run = dry_run or testing  # output nodes have no external effect in a test
    node_id, node_run_id, run_id = node_run.node_id, node_run.id, run.id
    node_type = compiled.types[node_id]
    settings = compiled.graph.node(node_id).settings
    latest = _latest(
        list((await db.execute(select(NodeRun).where(NodeRun.run_id == run_id))).scalars())
    )
    inputs = (run.test_inputs or {}) if testing else gather_inputs(compiled, node_id, latest)
    upstream = {
        src: latest[src].output.get(port, [])
        for src, port, _ in compiled.upstream.get(node_id, [])
        if src in latest
    }
    now = deps.clock()
    ctx = NodeContext(
        workspace_id=run.workspace_id,
        run=RunInfo(run_id, run.workflow_id, run.trigger_type, run.trigger_payload, workflow.name),
        node_id=node_id,
        now=now,
        repo=WorkspaceRepo(db, run.workspace_id, now, run_id, node_id),
        connectors=WorkerConnectors(db, deps, run.workspace_id, deps.vault),
        upstream=upstream,
        dry_run=dry_run,
        agents=deps.agents(run.workspace_id),
        node_run_id=node_run_id,
    )
    started = asyncio.get_running_loop().time()
    error: str | None = None
    try:
        outputs = await asyncio.wait_for(
            node_type().execute(ctx, compiled.params[node_id], inputs),
            timeout=settings.timeout_seconds,
        )
        bounded, count, truncated = bound_outputs(outputs, node_type.outputs, deps.limits)
    except NodeError as exc:
        error = exc.code
    except ExpressionError as exc:
        error = f"expression: {exc}"
    except TimeoutError:
        error = "timeout"
    except QuotaExceededError as exc:
        error = f"quota_exceeded: {exc.window}"
    except Exception:
        # Node code failed: log the type only (messages may quote collected content).
        log.exception("workflow_node_failed", node_type=node_type.type)
        error = "internal_error"
    elapsed = round(asyncio.get_running_loop().time() - started, 3)

    if error is None:
        try:
            if testing:
                await db.rollback()  # a test leaves no data behind, only its output
            current = await db.get(NodeRun, node_run_id)
            assert current is not None  # noqa: S101
            current.status = "succeeded"
            current.output = bounded
            current.output_count = count
            current.output_truncated = truncated
            current.logs = ctx.logs
            current.finished_at = deps.clock()
            current.metrics = {**current.metrics, "duration_seconds": elapsed}
            await db.commit()
        except Exception:
            log.exception("workflow_node_store_failed", node_type=node_type.type)
            error = "store_failed"
        else:
            for to, subject, body in ctx.mails:
                deps.tasks.send(MAIL_TASK, {"to": to, "subject": subject, "body": body})
            if not testing:
                for name, kwargs in ctx.tasks:
                    deps.tasks.send(name, kwargs)
            return "succeeded"

    await db.rollback()  # the node's own database effects are undone
    current = await db.get(NodeRun, node_run_id)
    assert current is not None  # noqa: S101
    current.status = "failed"
    current.error = error[:MAX_ERROR]
    current.logs = ctx.logs
    current.finished_at = deps.clock()
    current.metrics = {**current.metrics, "duration_seconds": elapsed}
    current.output = {"error": _error_items(node_id, current.error, inputs)}
    await db.commit()
    return "failed"


# Recovery ----------------------------------------------------------------------


async def sweep(db: AsyncSession, tasks: TaskQueue, now: datetime) -> dict[str, int]:
    """Cross-workspace recovery (worker role, platform-admin context)."""
    await set_context(db, is_platform_admin=True)
    lost = await db.execute(
        update(NodeRun)
        .where(
            NodeRun.status == "running",
            NodeRun.started_at
            + func.make_interval(
                0,
                0,
                0,
                0,
                0,
                0,
                func.coalesce(NodeRun.metrics["timeout_seconds"].as_integer(), 3600),
            )
            + SWEEP_GRACE
            < now,
        )
        .values(status="failed", error="worker_lost", finished_at=now)
        .returning(NodeRun.run_id, NodeRun.workspace_id)
    )
    to_advance = {(run_id, ws) for run_id, ws in lost.all()}
    recovered = len(to_advance)
    stale = await db.execute(
        select(NodeRun.id, NodeRun.queue, NodeRun.workspace_id)
        .where(NodeRun.status == "queued", NodeRun.scheduled_at < now - LOST_MESSAGE_AFTER)
        .limit(500)
    )
    resent = 0
    for node_run_id, queue, workspace_id in stale.all():
        tasks.send(
            NODE_TASK.format(queue=queue),
            {"node_run_id": str(node_run_id), "workspace_id": str(workspace_id)},
            task_id=str(node_run_id),
        )
        resent += 1
    pending = await db.execute(
        select(WorkflowRun.id, WorkflowRun.workspace_id)
        .where(
            (WorkflowRun.status == "queued")
            | ((WorkflowRun.status == "running") & (WorkflowRun.deadline_at < now))
        )
        .limit(500)
    )
    to_advance |= {(run_id, ws) for run_id, ws in pending.all()}
    await db.commit()
    for run_id, workspace_id in to_advance:
        advance_task(tasks, run_id, workspace_id)
    return {"recovered": recovered, "resent": resent, "advanced": len(to_advance)}
