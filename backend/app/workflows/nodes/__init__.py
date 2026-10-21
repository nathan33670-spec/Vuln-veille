"""Built-in node types; importing this package registers them (spec 02 §7)."""

from app.workflows.nodes import control, sources, transforms, triggers, vulns  # noqa: F401
