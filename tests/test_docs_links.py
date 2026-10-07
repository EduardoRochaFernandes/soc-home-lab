"""Every relative link in the Markdown files must resolve to a file in the repo."""

import re
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parent.parent
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE_RE = re.compile(r"^```.*?^```", re.S | re.M)
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")
# Links that only make sense on github.com (milestones, issue forms).
GITHUB_ONLY = ("../../milestone/", "../../issues/", "../../../issues/")


def markdown_files():
    return sorted(
        p for p in ROOT.rglob("*.md") if ".git" not in p.parts and "node_modules" not in p.parts
    )


@pytest.mark.parametrize("md", markdown_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(md):
    text = FENCE_RE.sub("", md.read_text(encoding="utf-8"))
    broken = []
    for target in LINK_RE.findall(text):
        if target.startswith(SKIP_PREFIXES) or target.startswith(GITHUB_ONLY):
            continue
        path = unquote(target.split("#", 1)[0])
        if path and not (md.parent / path).resolve().exists():
            broken.append(target)
    assert not broken, f"{md.relative_to(ROOT)} has broken links: {broken}"
