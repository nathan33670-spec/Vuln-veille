"""Built-in node types; importing this package registers them (spec 02 §7)."""

from app.workflows.nodes import (  # noqa: F401
    ai,
    bulletins,
    control,
    publish,
    sources,
    transforms,
    triggers,
    vulns,
    watch,
)
