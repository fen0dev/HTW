"""Helpers shared by the tool adapters.

Scanner output is untrusted input: it is derived from the scanned content. Adapters
read it defensively and never assume a field exists or has the expected type.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from htw.errors import ToolError

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

# Package type names used by the tools, mapped to OSV ecosystem names.
ECOSYSTEMS = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm", "bun": "npm",
    "python": "PyPI", "pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "uv": "PyPI",
    "python-pkg": "PyPI", "pypi": "PyPI", "conda-pkg": "Conda",
    "go-module": "Go", "gomod": "Go", "gobinary": "Go", "go": "Go",
    "rust-crate": "crates.io", "cargo": "crates.io", "rust-binary": "crates.io",
    "java-archive": "Maven", "pom": "Maven", "jar": "Maven", "gradle": "Maven",
    "sbt": "Maven", "maven": "Maven",
    "gem": "RubyGems", "bundler": "RubyGems", "gemspec": "RubyGems", "rubygems": "RubyGems",
    "php-composer": "Packagist", "composer": "Packagist", "packagist": "Packagist",
    "dotnet": "NuGet", "nuget": "NuGet", "dotnet-core": "NuGet", "packages-props": "NuGet",
    "hex": "Hex", "mix-lock": "Hex", "erlang-otp": "Hex",
    "dart-pub": "Pub", "pub": "Pub", "pubspec-lock": "Pub",
    "swift": "SwiftURL", "cocoapods": "CocoaPods", "pod": "CocoaPods",
    "conan": "ConanCenter", "conan-lock": "ConanCenter",
    "hackage": "Hackage", "github-action": "GitHub Actions",
}  # fmt: skip


def ecosystem_for(package_type: object) -> str:
    text = str(package_type or "").strip()
    return ECOSYSTEMS.get(text.lower(), text or "unknown")


def parse_json(tool: str, text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        preview = " ".join(text[:200].split())
        raise ToolError(
            f"{tool} did not produce valid JSON"
            + (f" (output starts: {preview!r})" if preview else "")
        ) from None


def read_json_file(tool: str, path: Path) -> Any:
    try:
        return parse_json(tool, path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        raise ToolError(f"{tool} did not write its report: {exc}") from None


def as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        match = re.match(r"\s*(\d+)", value)
        if match and int(match.group(1)) > 0:
            return int(match.group(1))
    return None


def as_float(value: object) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 10 else None


def cwe_ids(*values: object) -> tuple[str, ...]:
    """Extract CWE identifiers from strings, numbers or nested lists of them."""
    found: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, (list, tuple)):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            visit(value.get("id") or value.get("cwe"))
        elif isinstance(value, int) and not isinstance(value, bool):
            found.append(f"CWE-{value}")
        elif isinstance(value, str):
            matches = _CWE_RE.findall(value)
            if matches:
                found.extend(match.upper() for match in matches)
            elif value.strip().isdigit():
                found.append(f"CWE-{value.strip()}")

    for value in values:
        visit(value)
    return tuple(dict.fromkeys(found))


def unique(values: list[str], limit: int = 8) -> tuple[str, ...]:
    return tuple(dict.fromkeys(v for v in values if isinstance(v, str) and v))[:limit]


def http_links(values: list[Any], limit: int = 4) -> tuple[str, ...]:
    """Keep only http(s) links: reference fields end up as links in reports."""
    return unique(
        [v for v in values if isinstance(v, str) and v.startswith(("https://", "http://"))], limit
    )
