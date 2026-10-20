"""First administrator creation (``python -m app.cli bootstrap-admin``).

There is no default account (SECURITY.md §4.1): the first administrator is created
from the command line on the server, and receives a one-time invitation link printed
on the console. The command refuses to run once an administrator exists.
"""

from sqlalchemy import or_, select

from app.audit.service import AuditContext, AuditEntry, record
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context
from app.iam.models import User, UserGlobalRole, Workspace, WorkspaceMembership
from app.iam.tokens import issue_token


class AdminAlreadyExistsError(Exception):
    pass


async def bootstrap_admin(settings: Settings, email: str, display_name: str) -> str:
    """Creates the invited administrator and returns the invitation link."""
    engine = create_engine(settings.database_url_app.get_secret_value())
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            voc = (
                await db.execute(select(Workspace).where(Workspace.grants_platform_admin.is_(True)))
            ).scalar_one()
            existing = (
                await db.execute(
                    select(User.id)
                    .outerjoin(UserGlobalRole, UserGlobalRole.user_id == User.id)
                    .outerjoin(WorkspaceMembership, WorkspaceMembership.user_id == User.id)
                    .where(User.status != "disabled")
                    .where(
                        or_(
                            UserGlobalRole.role == "platform_admin",
                            (WorkspaceMembership.workspace_id == voc.id)
                            & (WorkspaceMembership.role == "analyst"),
                        )
                    )
                    .limit(1)
                )
            ).first()
            if existing is not None:
                raise AdminAlreadyExistsError

            user = User(
                email=email.lower(),
                display_name=display_name,
                user_type="internal",
                status="invited",
                failed_login_count=0,
                locale="fr",
            )
            db.add(user)
            await db.flush()
            db.add(UserGlobalRole(user_id=user.id, role="platform_admin"))
            db.add(WorkspaceMembership(user_id=user.id, workspace_id=voc.id, role="analyst"))
            token = await issue_token(db, settings, user, "invitation", "backoffice", None)
            await record(
                db,
                AuditContext(actor_type="system"),
                AuditEntry(
                    action="admin.bootstrap_admin",
                    target_type="user",
                    target_id=str(user.id),
                    workspace_id=voc.id,
                ),
            )
            await db.commit()
            return f"{settings.origin_for('backoffice')}/invitation#token={token}"
    finally:
        await engine.dispose()
