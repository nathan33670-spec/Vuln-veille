"""No invisible or bidirectional-override characters in the code (Trojan Source)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HIDDEN = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
SUFFIXES = {".py", ".ts", ".tsx", ".js", ".sql", ".sh", ".yml", ".yaml", ".toml", ".json"}
SKIP = {"node_modules", ".venv", "dist", ".git", "__pycache__", ".mypy_cache", ".ruff_cache"}


def test_no_hidden_characters_in_sources() -> None:
    offenders = []
    for path in ROOT.rglob("*"):
        if path.suffix not in SUFFIXES or SKIP & set(path.parts) or not path.is_file():
            continue
        for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if HIDDEN.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert offenders == []


def test_the_guard_detects_hidden_characters() -> None:
    assert HIDDEN.search("admin\u202e\u2066 = True")
    assert not HIDDEN.search("plain ascii and accents: é à ü")
