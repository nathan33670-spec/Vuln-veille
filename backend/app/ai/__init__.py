"""AI engine layer (spec 03 §3, spec 07 §4, ADR-011).

Agents and workflow nodes only speak the provider-neutral types of ``app.ai.types``;
everything specific to a provider lives in ``app.ai.engines`` (CLAUDE.md rule), so the
preferred engine can change from Gemini to an OpenAI-compatible LLMaaS or Claude by
configuration alone.
"""
