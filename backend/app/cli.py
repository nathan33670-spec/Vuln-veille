"""Administration commands: ``python -m app.cli <command>``."""

import argparse
import asyncio
import base64
import json
import os
import sys
from pathlib import Path

import asyncpg
from pydantic import SecretStr

from app.app_factory import create_app
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.db_roles import RolePasswords, provision_roles
from app.iam.bootstrap import AdminAlreadyExistsError, bootstrap_admin


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"missing environment variable {name}")
    return value


async def _provision_db_roles() -> None:
    admin_dsn = _require_env("VV_DB_ADMIN_URL")
    database = _require_env("VV_DB_NAME")
    passwords = RolePasswords(
        migrator=_require_env("VV_DB_PASSWORD_MIGRATOR"),
        app=_require_env("VV_DB_PASSWORD_APP"),
        worker=_require_env("VV_DB_PASSWORD_WORKER"),
        portal=_require_env("VV_DB_PASSWORD_PORTAL"),
    )
    conn = await asyncpg.connect(admin_dsn)
    try:
        async with conn.transaction():
            await provision_roles(conn, database, passwords)
    finally:
        await conn.close()
    print("database roles provisioned")  # noqa: T201 - CLI output


def _export_openapi(output_dir: Path) -> None:
    # The schema does not depend on infrastructure: placeholders, never connected to.
    unused = SecretStr("postgresql://unused@localhost/unused")
    settings = Settings(
        environment="dev",
        database_url_app=unused,
        database_url_portal=unused,
        database_url_worker=unused,
        database_url_migrator=unused,
        redis_url=SecretStr("redis://localhost:6379/0"),
        secret_key=SecretStr("schema-export-only-not-a-secret-0123456789"),
        kek_totp=SecretStr(base64.b64encode(bytes(32)).decode()),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    for audience in ("backoffice", "portal"):
        app = create_app(audience, settings)
        target = output_dir / f"openapi-{audience}.json"
        target.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n")
        print(f"wrote {target}")  # noqa: T201 - CLI output


async def _bootstrap_admin(email: str, name: str) -> None:
    settings = get_settings()
    configure_logging("WARNING")
    try:
        link = await bootstrap_admin(settings, email, name)
    except AdminAlreadyExistsError:
        sys.exit("an administrator already exists: use the back-office to invite users")
    # Printed once, never logged. Valid for the invitation lifetime; then re-run is refused,
    # so resend from another admin or reset the database.
    print("Administrator invited. Open this link to choose a password and enrol MFA:")  # noqa: T201
    print(link)  # noqa: T201


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="app.cli", description="Vuln-Veille administration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("provision-db-roles", help="create or update the PostgreSQL roles")
    export = sub.add_parser("export-openapi", help="write the OpenAPI schemas of both APIs")
    export.add_argument("--output-dir", type=Path, default=Path("openapi"))
    boot = sub.add_parser("bootstrap-admin", help="invite the first platform administrator")
    boot.add_argument("--email", required=True)
    boot.add_argument("--name", required=True)

    args = parser.parse_args(argv)
    if args.command == "provision-db-roles":
        asyncio.run(_provision_db_roles())
    elif args.command == "export-openapi":
        _export_openapi(args.output_dir)
    elif args.command == "bootstrap-admin":
        asyncio.run(_bootstrap_admin(args.email, args.name))


if __name__ == "__main__":
    main()
