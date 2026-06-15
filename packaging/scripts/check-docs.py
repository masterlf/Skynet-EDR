#!/usr/bin/env python3
"""Validate the repository documentation map and local Markdown links."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_DOCS = [
    "docs/README.md",
    "docs/INSTALL.md",
    "docs/QUICKSTART.md",
    "docs/CONCEPTS.md",
    "docs/ARCHITECTURE.md",
    "docs/EVENT_SCHEMA.md",
    "docs/INTEGRATIONS.md",
    "docs/DETECTIONS.md",
    "docs/OPERATIONS.md",
    "docs/RELEASE_PROCESS.md",
]

LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")


def slugify(heading: str) -> str:
    heading = re.sub(r"<[^>]+>", "", heading).strip().lower()
    heading = re.sub(r"[`*_~]", "", heading)
    heading = re.sub(r"[^a-z0-9\s-]", "", heading)
    heading = re.sub(r"\s+", "-", heading)
    heading = re.sub(r"-+", "-", heading).strip("-")
    return heading


def markdown_files() -> list[Path]:
    ignored_parts = {".git", ".hermes", "target", "dist"}
    return [
        path
        for path in ROOT.rglob("*.md")
        if not any(part in ignored_parts for part in path.relative_to(ROOT).parts)
    ]


def anchors_for(path: Path) -> set[str]:
    anchors: set[str] = set()
    duplicates: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADING_RE.match(line)
        if not match:
            continue
        base = slugify(match.group(2))
        if not base:
            continue
        count = duplicates.get(base, 0)
        anchors.add(base if count == 0 else f"{base}-{count}")
        duplicates[base] = count + 1
    return anchors


def is_external(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme in {"http", "https", "mailto"}


def validate_required_docs(errors: list[str]) -> None:
    for rel in REQUIRED_DOCS:
        path = ROOT / rel
        if not path.is_file():
            errors.append(f"missing required documentation file: {rel}")

    readme = ROOT / "README.md"
    docs_index = ROOT / "docs/README.md"
    if readme.is_file() and "docs/README.md" not in readme.read_text(encoding="utf-8"):
        errors.append("README.md must link to docs/README.md as the documentation hub")
    if docs_index.is_file():
        text = docs_index.read_text(encoding="utf-8")
        for rel in REQUIRED_DOCS[1:]:
            name = Path(rel).name
            if name not in text:
                errors.append(f"docs/README.md must link to {rel}")


def validate_links(errors: list[str]) -> None:
    anchor_cache: dict[Path, set[str]] = {}
    for md in markdown_files():
        text = md.read_text(encoding="utf-8")
        for line_no, target in enumerate(LINK_RE.findall(text), start=1):
            if is_external(target) or target.startswith("#"):
                continue
            path_part, _, fragment = target.partition("#")
            path_part = unquote(path_part)
            if not path_part:
                candidate = md
            else:
                candidate = (md.parent / path_part).resolve()
            try:
                candidate.relative_to(ROOT)
            except ValueError:
                errors.append(f"{md.relative_to(ROOT)}:{line_no}: link escapes repository: {target}")
                continue
            if not candidate.exists():
                errors.append(f"{md.relative_to(ROOT)}:{line_no}: missing link target: {target}")
                continue
            if fragment and candidate.suffix.lower() == ".md":
                anchors = anchor_cache.setdefault(candidate, anchors_for(candidate))
                if fragment.lower() not in anchors:
                    errors.append(
                        f"{md.relative_to(ROOT)}:{line_no}: missing anchor #{fragment} in {candidate.relative_to(ROOT)}"
                    )


def main() -> int:
    errors: list[str] = []
    validate_required_docs(errors)
    validate_links(errors)
    if errors:
        print("documentation check failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"documentation check passed: {len(markdown_files())} markdown files validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
