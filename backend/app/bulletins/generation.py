"""Draft generation (spec 04 §3): context, structured AI output, computed fields,
deterministic rendering, the bulletin and its revision.

Used by the ``ai`` worker for draft requests and by the ``bulletin.generate_draft``
workflow node; the AI call goes through the agent runtime (budget, trace, injection
guards, output validated against the template's schema), never through a provider SDK.
"""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.spec import AgentSpec
from app.bulletins.facts import Facts, vulnerability_facts
from app.bulletins.fields import clean_fields, output_schema, system_prompt
from app.bulletins.models import (
    Bulletin,
    BulletinRefCounter,
    BulletinRevision,
    BulletinSettings,
    BulletinTechnology,
    BulletinTemplateVersion,
    BulletinVulnerability,
)
from app.bulletins.render import content_hash, markdown_to_html, render_markdown
from app.bulletins.selection import computed_fields
from app.bulletins.spec import TemplateSpec, parse_spec
from app.core.ids import uuid7
from app.vulns.models import VulnerabilityTechnology
from app.watch.models import CollectedItem

GENERATION_LIMITS = {
    "max_turns": 3,
    "max_tool_calls": 0,
    "max_output_tokens": 8192,
    "timeout_seconds": 300,
}
MAX_EVIDENCE = 10
EVIDENCE_CHARS = 3000
TEXT_CHARS = 20000

# (task, spec, payload, context_id) -> AgentResult (app.ai.agents.invoke)
TaskRunner = Callable[[str, AgentSpec, dict[str, Any], str], Awaitable[Any]]


class GenerationError(RuntimeError):
    """A draft could not be produced; the message is a stable code, no content."""


@dataclass
class Rendered:
    fields: dict[str, Any]
    markdown: str
    html: str
    content_hash: str


@dataclass
class Generated:
    fields: dict[str, Any]
    agent_run_id: uuid.UUID | None
    cost_usd: Any = None
    flags: list[Any] = field(default_factory=list)


def render(spec: TemplateSpec, fields: dict[str, Any], tlp: str) -> Rendered:
    markdown = render_markdown(
        spec.render_template, {"fields": fields, "tlp": tlp, "language": spec.language}
    )
    return Rendered(fields, markdown, markdown_to_html(markdown), content_hash(fields, markdown))


async def _evidence(
    db: AsyncSession, workspace_id: uuid.UUID, facts: Facts
) -> list[dict[str, Any]]:
    """Collected texts behind the vulnerability: bounded, and marked untrusted by the
    runtime when they reach the engine."""
    from app.vulns.models import Evidence  # noqa: PLC0415 - avoids an import cycle

    rows = await db.execute(
        select(CollectedItem.url, CollectedItem.title, CollectedItem.content_text, Evidence.kind)
        .join(Evidence, Evidence.collected_item_id == CollectedItem.id)
        .where(
            Evidence.vulnerability_id == facts.vulnerability_id,
            Evidence.workspace_id == workspace_id,
        )
        .order_by(Evidence.created_at.desc())
        .limit(MAX_EVIDENCE)
    )
    return [
        {
            "kind": kind,
            "url": url,
            "title": (title or "")[:300],
            "text": (text or "")[:EVIDENCE_CHARS],
        }
        for url, title, text, kind in rows.all()
    ]


async def build_payload(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    facts_list: list[Facts],
    *,
    text: str = "",
    urls: list[str] | None = None,
    source_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "vulnerabilities": [
            {
                **{k: v for k, v in f.values.items() if v not in (None, [], "")},
                "evidence": await _evidence(db, workspace_id, f),
            }
            for f in facts_list
        ]
    }
    if text.strip():
        payload["analyst_text"] = text[:TEXT_CHARS]
    if urls:
        payload["urls"] = urls[:20]
    if source_fields is not None:
        payload["source_bulletin"] = source_fields
    return payload


def agent_spec(
    spec: TemplateSpec, *, extra_instructions: str = "", only: str | None = None,
    translation: bool = False,
) -> AgentSpec:  # fmt: skip
    return AgentSpec.model_validate(
        {
            "system_prompt": system_prompt(
                spec, extra_instructions=extra_instructions, only=only, translation=translation
            ),
            "output_schema": output_schema(spec, only),
            "limits": GENERATION_LIMITS,
        }
    )


async def generate_ai_fields(
    run_task: TaskRunner,
    spec: TemplateSpec,
    payload: dict[str, Any],
    context_id: str,
    *,
    extra_instructions: str = "",
    only: str | None = None,
    translation: bool = False,
) -> Generated:
    if not any(f.generation.mode == "ai" for f in spec.fields if only in (None, f.key)):
        return Generated({}, None)
    result = await run_task(
        "bulletin.translate" if translation else "bulletin.draft",
        agent_spec(spec, extra_instructions=extra_instructions, only=only, translation=translation),
        payload,
        context_id,
    )
    if not result.succeeded or not isinstance(result.output, dict):
        raise GenerationError(result.error or result.status)
    return Generated(
        dict(result.output), result.run_id, result.cost_usd, list(result.injection_flags)
    )


async def next_ref(db: AsyncSession, workspace_id: uuid.UUID, now: datetime) -> str:
    """``PREFIX-YYYY-NNNN``: the workspace's prefix (Q37), a counter per year."""
    settings = await db.get(BulletinSettings, workspace_id)
    prefix = settings.ref_prefix if settings else "BUL"
    counter = await db.execute(
        insert(BulletinRefCounter)
        .values(workspace_id=workspace_id, year=now.year, last_no=1)
        .on_conflict_do_update(
            index_elements=["workspace_id", "year"],
            set_={"last_no": BulletinRefCounter.last_no + 1},
        )
        .returning(BulletinRefCounter.last_no)
    )
    return f"{prefix}-{now.year}-{counter.scalar_one():04d}"


async def add_revision(
    db: AsyncSession,
    bulletin: Bulletin,
    spec: TemplateSpec,
    fields: dict[str, Any],
    *,
    by_type: str,
    by: uuid.UUID | None,
    agent_run_id: uuid.UUID | None,
    note: str,
    now: datetime,
) -> BulletinRevision:
    rendered = render(spec, fields, bulletin.tlp)
    last = (
        await db.execute(
            select(BulletinRevision.rev_no)
            .where(BulletinRevision.bulletin_id == bulletin.id)
            .order_by(BulletinRevision.rev_no.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    revision = BulletinRevision(
        id=uuid7(),
        workspace_id=bulletin.workspace_id,
        bulletin_id=bulletin.id,
        rev_no=(last or 0) + 1,
        fields=rendered.fields,
        rendered_markdown=rendered.markdown,
        rendered_html=rendered.html,
        content_hash=rendered.content_hash,
        created_by_type=by_type,
        created_by=by,
        agent_run_id=agent_run_id,
        change_note=note[:500],
        created_at=now,
    )
    db.add(revision)
    await db.flush()
    bulletin.current_revision_id = revision.id
    bulletin.title = str(fields.get("title") or bulletin.title or bulletin.ref)[:300]
    severity = fields.get("severity")
    if severity in ("low", "medium", "high", "critical"):
        bulletin.severity = severity
    bulletin.updated_at = now
    return revision


@dataclass
class DraftInput:
    workspace_id: uuid.UUID
    version: BulletinTemplateVersion
    vulnerability_ids: list[uuid.UUID]
    text: str = ""
    urls: list[str] = field(default_factory=list)
    extra_instructions: str = ""
    author: uuid.UUID | None = None
    translation_of: Bulletin | None = None
    source_fields: dict[str, Any] | None = None


async def create_draft(
    db: AsyncSession, run_task: TaskRunner, draft: DraftInput, context_id: str, now: datetime
) -> tuple[Bulletin, Generated]:
    """Generates and stores a new bulletin (status ``draft``, revision 1 by the AI)."""
    spec = parse_spec(draft.version.spec)
    facts_list = [
        f
        for f in [
            await vulnerability_facts(db, draft.workspace_id, v) for v in draft.vulnerability_ids
        ]
        if f is not None
    ]
    payload = await build_payload(
        db,
        draft.workspace_id,
        facts_list,
        text=draft.text,
        urls=draft.urls,
        source_fields=draft.source_fields,
    )
    generated = await generate_ai_fields(
        run_task,
        spec,
        payload,
        context_id,
        extra_instructions=draft.extra_instructions,
        translation=draft.source_fields is not None,
    )
    values: dict[str, Any] = {}
    if draft.source_fields is not None:  # a translation keeps the source's data fields
        values.update({k: v for k, v in draft.source_fields.items() if spec.field(k)})
    elif facts_list:
        values.update(computed_fields(spec, facts_list[0]))
    values.update(generated.fields)
    fields, errors = clean_fields(spec, values)
    blocking = [e for e in errors if e["code"] not in ("missing",)]
    if blocking:
        raise GenerationError("invalid_output")
    bulletin = Bulletin(
        id=uuid7(),
        workspace_id=draft.workspace_id,
        ref=await next_ref(db, draft.workspace_id, now),
        language=spec.language,
        translation_of=draft.translation_of.id if draft.translation_of else None,
        title=str(fields.get("title") or "")[:300] or "—",
        status="draft",
        tlp=draft.translation_of.tlp if draft.translation_of else spec.tlp,
        audience_type=draft.translation_of.audience_type if draft.translation_of else "all_clients",
        template_version_id=draft.version.id,
        author_id=draft.author,
        created_at=now,
        updated_at=now,
    )
    db.add(bulletin)
    await db.flush()
    await add_revision(
        db,
        bulletin,
        spec,
        fields,
        by_type="ai",
        by=None,
        agent_run_id=generated.agent_run_id,
        note="Traduction" if draft.source_fields is not None else "Draft généré",
        now=now,
    )
    for vulnerability_id in [f.vulnerability_id for f in facts_list if f.vulnerability_id]:
        db.add(
            BulletinVulnerability(
                bulletin_id=bulletin.id,
                vulnerability_id=vulnerability_id,
                workspace_id=draft.workspace_id,
            )
        )
    technologies = (
        await db.execute(
            select(VulnerabilityTechnology.technology_id)
            .where(VulnerabilityTechnology.vulnerability_id.in_(draft.vulnerability_ids))
            .distinct()
        )
    ).scalars()
    for technology_id in technologies:
        db.add(
            BulletinTechnology(
                bulletin_id=bulletin.id,
                technology_id=technology_id,
                workspace_id=draft.workspace_id,
            )
        )
    await db.flush()
    return bulletin, generated
