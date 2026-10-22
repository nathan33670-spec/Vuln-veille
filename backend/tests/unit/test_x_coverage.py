"""X coverage indicator (plan 4.18): what counts as found, and the comparison with the
hand-checked sample."""

import uuid

from app.ai.agents.models import AgentStep
from app.ai.coverage import XCoverageCheck, indicator, posts_in, read_posts

POST = "https://x.com/researcher/status/1850000000001"


def _step(name: str, content: dict | None = None, error: str | None = None) -> AgentStep:  # type: ignore[type-arg]
    payload: dict = {"name": name, "content": content or {}}  # type: ignore[type-arg]
    if error:
        payload["error"] = error
    return AgentStep(agent_run_id=uuid.uuid4(), seq=1, type="tool_result", payload=payload)


def test_posts_are_canonical_and_only_read_ones_count() -> None:
    assert posts_in({"a": ["see https://twitter.com/researcher/status/1850000000001 !"]}) == {POST}
    read = _step(
        "x_read",
        {"documents": [{"untrusted_document": {"url": POST, "content": "PoC"}}]},
    )
    withdrawn = _step("x_read", {"documents": [{"x_post": {"url": POST, "withdrawn": True}}]})
    failed = _step("x_read", error="http_503")
    other = _step("github_get", {"documents": [{"untrusted_document": {"url": POST}}]})
    assert read_posts([read]) == {POST}
    assert read_posts([withdrawn, failed, other]) == set()


def _check(cve_id: str, has: bool) -> XCoverageCheck:
    return XCoverageCheck(cve_id=cve_id, has_discussion=has)


def test_indicator_against_the_hand_checked_sample() -> None:
    found = {"CVE-1": True, "CVE-2": False, "CVE-3": True, "CVE-4": False}
    checks = [
        _check("CVE-1", True),  # found: true positive
        _check("CVE-2", True),  # missed
        _check("CVE-3", False),  # found where the analyst saw nothing
        _check("CVE-9", True),  # not investigated: not compared
    ]
    result = indicator(found, checks)
    assert result["investigated"] == 4
    assert result["with_x_discussion"] == 2
    assert result["coverage_rate"] == 0.5
    sample = result["sample"]
    assert sample["compared"] == 3
    assert sample["recall"] == 0.5
    assert sample["precision"] == 0.5
    assert sample["missed"] == ["CVE-2"]
    assert indicator({}, [])["coverage_rate"] is None
