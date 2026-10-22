"""Keep package metadata aligned with the application's runtime requirements."""

import re
from pathlib import Path

from packaging.specifiers import SpecifierSet


def test_python_requirement_matches_evaluated_union_annotations():
    """Python 3.9 cannot import Settings; Python 3.10 is the minimum runtime."""
    project = Path(__file__).resolve().parents[2] / "pyproject.toml"
    requirement = re.search(
        r'^requires-python = "([^"]+)"', project.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert requirement is not None
    supported = SpecifierSet(requirement.group(1))
    assert "3.9" not in supported
    assert "3.10" in supported
