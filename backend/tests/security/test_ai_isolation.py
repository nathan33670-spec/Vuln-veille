"""Provider code stays in ``app/ai/engines`` (CLAUDE.md, ADR-011): switching the
preferred engine must remain configuration, never a code change elsewhere."""

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"
ENGINES = APP / "ai" / "engines"
PROVIDER_MODULES = ("anthropic", "google.genai", "google.generativeai", "openai", "httpx2")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def test_provider_sdks_are_only_imported_by_the_adapters() -> None:
    offenders = []
    for path in APP.rglob("*.py"):
        if ENGINES in path.parents:
            continue
        for module in _imports(path):
            if any(module == p or module.startswith(p + ".") for p in PROVIDER_MODULES):
                offenders.append(f"{path.relative_to(APP)}: {module}")
    assert offenders == []


def test_guard_sees_the_adapters() -> None:
    assert "anthropic" in _imports(ENGINES / "anthropic.py")
    assert "google.genai" in _imports(ENGINES / "gemini.py")
