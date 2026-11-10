"""Syft: software bill of materials (CycloneDX)."""

from __future__ import annotations

from pathlib import Path

from htw.core.finding import Finding
from htw.detect.model import PACKAGE_MANAGER, StackProfile
from htw.scanners.base import ScanContext, ToolAdapter

SBOM_CYCLONEDX = "sbom.cdx.json"
SBOM_SYFT = "sbom.syft.json"


def anchore_excludes(root: Path, patterns: tuple[str, ...]) -> list[str]:
    """Translate asset `exclude` patterns to the glob form Syft and Grype accept."""
    arguments = []
    for raw in patterns:
        pattern = raw.strip().strip("/")
        if pattern.endswith("/**"):
            pattern = pattern[: -len("/**")]
        if not pattern:
            continue
        if "/" not in pattern and not (root / pattern).exists():
            glob = f"**/{pattern}"
        elif (root / pattern).is_dir():
            glob = f"./{pattern}/**"
        else:
            glob = f"./{pattern}"
        arguments += ["--exclude", glob]
    return arguments


class Syft(ToolAdapter):
    name = "syft"
    binary = "syft"
    homepage = "https://github.com/anchore/syft"
    install_hint = (
        "`brew install syft`, or download a release from https://github.com/anchore/syft/releases"
    )
    network = "none"
    version_args = ("version",)

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"sbom"} if profile.has(PACKAGE_MANAGER) else set()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        cyclonedx = ctx.artifacts_dir / SBOM_CYCLONEDX
        native = ctx.artifacts_dir / SBOM_SYFT
        result = ctx.runner.run(
            [
                "syft",
                "scan",
                "dir:.",
                "--source-name",
                ctx.asset.id,
                "-o",
                f"cyclonedx-json={cyclonedx}",
                "-o",
                f"syft-json={native}",
                "-q",
                *anchore_excludes(ctx.root, ctx.asset.exclude),
            ],
            cwd=ctx.root,
            extra_env={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
        )
        if result.returncode != 0 or not cyclonedx.exists():
            raise self._fail(result)
        ctx.artifacts["sbom"] = cyclonedx
        if native.exists():
            ctx.artifacts["sbom-syft"] = native
        return []
