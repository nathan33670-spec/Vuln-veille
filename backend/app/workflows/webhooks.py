"""Incoming webhooks (``trigger.webhook``, spec 02 §6).

The public endpoint never touches the database: it checks size, rate, headers and
timestamp freshness, then queues the request. The ``default`` worker, which alone
holds the ``webhook`` keyring, checks the HMAC-SHA256 signature of
``"<timestamp>.<body>"`` and starts the run; a replayed request (same signature)
maps to the same idempotency key and starts nothing, and an old timestamp is refused.
The caller always gets the same answer, so trigger ids cannot be probed.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import uuid
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.rls import set_context
from app.core.tasks import TaskQueue
from app.vault.crypto import VaultError
from app.vault.keys import SecretPurpose
from app.vault.service import Vault, resolve_secret
from app.workflows.dispatch import fire
from app.workflows.engine import advance_task
from app.workflows.models import WorkflowTrigger

log = get_logger(__name__)

WEBHOOK_TASK = "default.workflow_webhook"
SIGNATURE_HEADER = "x-vv-signature"
TIMESTAMP_HEADER = "x-vv-timestamp"
MAX_BODY_BYTES = 256 * 1024
TOLERANCE_SECONDS = 300
SIGNATURE = re.compile(r"^sha256=[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^[0-9]{10}$")


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def fresh(timestamp: str, now: datetime) -> bool:
    return bool(TIMESTAMP.fullmatch(timestamp)) and (
        abs(now.timestamp() - int(timestamp)) <= TOLERANCE_SECONDS
    )


def well_formed(timestamp: str | None, signature: str | None) -> bool:
    return bool(
        timestamp
        and signature
        and TIMESTAMP.fullmatch(timestamp)
        and SIGNATURE.fullmatch(signature)
    )


def enqueue(
    tasks: TaskQueue, trigger_id: uuid.UUID, timestamp: str, signature: str, body: bytes
) -> None:
    tasks.send(
        WEBHOOK_TASK,
        {
            "trigger_id": str(trigger_id),
            "timestamp": timestamp,
            "signature": signature,
            "body": base64.b64encode(body).decode(),
        },
    )


async def receive(  # noqa: PLR0911 - one outcome per check
    db: AsyncSession,
    vault: Vault,
    tasks: TaskQueue,
    *,
    trigger_id: uuid.UUID,
    timestamp: str,
    signature: str,
    body: bytes,
    now: datetime,
) -> str:
    """Worker side (worker role, platform-admin context). Returns an outcome code."""
    await set_context(db, is_platform_admin=True)
    trigger = await db.get(WorkflowTrigger, trigger_id)
    if trigger is None or trigger.type != "webhook" or not trigger.enabled:
        return "unknown_trigger"
    if trigger.webhook_secret_id is None:
        return "no_secret"
    if not fresh(timestamp, now) or len(body) > MAX_BODY_BYTES:
        return "refused"
    try:
        secret = await resolve_secret(
            db,
            vault,
            trigger.webhook_secret_id,
            purpose=SecretPurpose.WEBHOOK,
            workspace_id=trigger.workspace_id,
        )
    except VaultError:
        log.warning("webhook_secret_unavailable")
        return "secret_unavailable"
    if not hmac.compare_digest(sign(secret, timestamp, body), signature):
        return "bad_signature"
    try:
        payload = json.loads(body)
    except ValueError:
        return "invalid_body"
    if not isinstance(payload, dict):
        return "invalid_body"
    started: list[tuple[uuid.UUID, uuid.UUID]] = []
    key = "webhook:" + hashlib.sha256(signature.encode()).hexdigest()
    await fire(db, trigger, payload, key, now, started)
    await db.commit()
    for run_id, workspace_id in started:
        advance_task(tasks, run_id, workspace_id)
    return "started" if started else "ignored"
