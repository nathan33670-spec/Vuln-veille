"""AI agents (spec 03): versioned configurations, a tool loop controlled by our code,
read-only tools on the workspace's connectors, prompt-injection guards and budgets.

The agent reads, summarises and proposes; it never acts. Any database write is done
by a deterministic node after schema validation, and any publication by a human.
"""
