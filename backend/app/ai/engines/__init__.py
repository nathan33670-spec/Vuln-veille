"""Provider adapters: the only place with code specific to an AI provider (CLAUDE.md).
Importing this package registers the ``ai_engine`` connector types."""

from app.ai.engines import anthropic, gemini, openai_compatible  # noqa: F401
