"""Every outbound connection goes through SafeHttpClient (CLAUDE.md, SECURITY.md §4.6).

Network libraries may only be imported by ``app/net/``; the SMTP relay (configured by
the operator, never by users) is the single documented exception.
"""

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"
NETWORK_MODULES = {
    "httpx",
    "httpcore",
    "requests",
    "aiohttp",
    "urllib3",
    "urllib.request",
    "http.client",
    "socket",
    "pycurl",
    "ftplib",
    "smtplib",
    "telnetlib",
    "websockets",
}
ALLOWED = {
    "net/": NETWORK_MODULES,
    "core/mailer.py": {"smtplib"},  # operator-configured relay (VV_SMTP_*)
}


def _imports(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def _is_network(module: str) -> bool:
    return any(module == m or module.startswith(m + ".") for m in NETWORK_MODULES)


def test_network_libraries_are_only_used_by_the_egress_layer() -> None:
    offenders = []
    for path in APP.rglob("*.py"):
        relative = path.relative_to(APP).as_posix()
        allowed = next(
            (mods for prefix, mods in ALLOWED.items() if relative.startswith(prefix)), set()
        )
        for module in _imports(ast.parse(path.read_text(), str(path))):
            if _is_network(module) and not any(
                module == m or module.startswith(m + ".") for m in allowed
            ):
                offenders.append(f"{relative}: {module}")
    assert offenders == [], "use app.net.safe_http.SafeHttpClient instead"


def test_the_guard_detects_offenders() -> None:
    tree = ast.parse("import httpx\nfrom urllib.request import urlopen\nfrom socket import socket")
    assert {m for m in _imports(tree) if _is_network(m)} >= {"httpx", "urllib.request", "socket"}
