"""The README test-count badge must match the suite it advertises.

It went stale twice (105 -> 152 while the suite grew to 168), so the number is now enforced by a
test: the static badge and the `make test` comment must both equal the number of collected tests.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BADGE = re.compile(r"tests-(\d+)%20passed")
MAKE_COMMENT = re.compile(r"make test\s+#\s+(\d+) tests")


@pytest.fixture(scope="module")
def collected() -> int:
    """Number of tests the suite collects (subprocess: pytest inside pytest)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=300,
    )
    total = sum(
        int(match.group(1))
        for line in proc.stdout.splitlines()
        if (match := re.match(r"^tests/\S+:\s+(\d+)$", line.strip()))
    )
    assert total > 0, f"could not count collected tests:\n{proc.stdout[-500:]}\n{proc.stderr[-500:]}"
    return total


@pytest.mark.parametrize("readme_name", ["README.md", "README.ja.md"])
def test_badge_matches_the_suite(readme_name: str, collected: int):
    text = (REPO_ROOT / readme_name).read_text(encoding="utf-8")
    match = BADGE.search(text)
    assert match, f"{readme_name} has no test-count badge"
    assert int(match.group(1)) == collected, (
        f"{readme_name} advertises {match.group(1)} tests but the suite collects {collected}"
    )


@pytest.mark.parametrize("readme_name", ["README.md", "README.ja.md"])
def test_testing_section_matches_the_suite(readme_name: str, collected: int):
    text = (REPO_ROOT / readme_name).read_text(encoding="utf-8")
    match = MAKE_COMMENT.search(text)
    assert match, f"{readme_name} Testing section must state the test count"
    assert int(match.group(1)) == collected, (
        f"{readme_name} Testing section says {match.group(1)} tests but the suite collects {collected}"
    )
