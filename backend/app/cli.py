"""Administration commands: ``python -m app.cli <command>``."""

import argparse
import asyncio
import base64
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
from pydantic import SecretStr

from app.app_factory import create_app
from app.connectors.egress_acl import connector_domains, render_acl, static_domains
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.db_roles import RolePasswords, provision_roles
from app.iam.bootstrap import AdminAlreadyExistsError, bootstrap_admin
from app.vault.admin import add_key, rotate
from app.vault.keys import KeyFormatError, SecretPurpose
from app.vault.service import VaultConfigError


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


def _vault_keygen(purpose: SecretPurpose, key_id: str, keyring_dir: Path) -> None:
    try:
        public = add_key(keyring_dir, purpose, key_id)
    except (KeyFormatError, VaultConfigError) as exc:
        sys.exit(str(exc))
    # The private key only goes to the keyring file; the public key is not secret.
    print(f"added key {key_id} to {purpose}.keyring; set in .env:")  # noqa: T201
    print(f"VV_VAULT_PUBLIC_KEY_{purpose.upper()}={public}")  # noqa: T201


def _vault_rotate(purpose: SecretPurpose) -> None:
    configure_logging("WARNING")
    try:
        count = asyncio.run(rotate(get_settings(), purpose))
    except VaultConfigError as exc:
        sys.exit(str(exc))
    print(f"{count} {purpose} secret(s) re-wrapped for the current key")  # noqa: T201


def _egress_acl(output: Path, with_connectors: bool) -> None:
    domains = static_domains()
    if with_connectors:
        domains |= asyncio.run(connector_domains(get_settings()))
    output.write_text(render_acl(domains))
    print(f"wrote {output} ({len(domains)} domains); restart smokescreen to apply")  # noqa: T201


def _seed_workflows() -> None:
    from app.workflows.seeds import seed_all  # noqa: PLC0415 - loads the node registry

    configure_logging("WARNING")
    created = asyncio.run(seed_all(get_settings(), datetime.now(UTC)))
    for slug, keys in created.items():
        print(f"{slug}: {', '.join(keys) or 'already seeded'}")  # noqa: T201


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="app.cli", description="Vuln-Veille administration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("provision-db-roles", help="create or update the PostgreSQL roles")
    export = sub.add_parser("export-openapi", help="write the OpenAPI schemas of both APIs")
    export.add_argument("--output-dir", type=Path, default=Path("openapi"))
    boot = sub.add_parser("bootstrap-admin", help="invite the first platform administrator")
    boot.add_argument("--email", required=True)
    boot.add_argument("--name", required=True)

    purposes = [p.value for p in SecretPurpose]
    keygen = sub.add_parser("vault-keygen", help="add a new vault key for a purpose")
    keygen.add_argument("--purpose", required=True, choices=purposes)
    keygen.add_argument("--key-id", required=True, help="e.g. k20270101")
    keygen.add_argument("--keyring-dir", type=Path, required=True)
    rot = sub.add_parser("vault-rotate", help="re-wrap a purpose's secrets for its current key")
    rot.add_argument("--purpose", required=True, choices=purposes)

    acl = sub.add_parser("egress-acl", help="write the smokescreen allow-list")
    acl.add_argument("--output", type=Path, required=True)
    acl.add_argument(
        "--static-only", action="store_true", help="only the domains declared by the types"
    )

    sub.add_parser("seed-workflows", help="create the delivered workflows (disabled) per workspace")

    args = parser.parse_args(argv)
    if args.command == "provision-db-roles":
        asyncio.run(_provision_db_roles())
    elif args.command == "export-openapi":
        _export_openapi(args.output_dir)
    elif args.command == "bootstrap-admin":
        asyncio.run(_bootstrap_admin(args.email, args.name))
    elif args.command == "vault-keygen":
        _vault_keygen(SecretPurpose(args.purpose), args.key_id, args.keyring_dir)
    elif args.command == "vault-rotate":
        _vault_rotate(SecretPurpose(args.purpose))
    elif args.command == "egress-acl":
        _egress_acl(args.output, with_connectors=not args.static_only)
    elif args.command == "seed-workflows":
        _seed_workflows()


if __name__ == "__main__":
    main()
