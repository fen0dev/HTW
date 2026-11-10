"""cosign verify-blob, opt-in, offline.

Signature files (`*.sig`) next to a blob are checked with `cosign.pub` from the asset.
HTW does not call `cosign verify` on a registry image and does not fetch a key.
"""

from __future__ import annotations

import os
from pathlib import Path

from htw.core.finding import PIPELINE, Finding, Location, Severity
from htw.core.paths import is_excluded
from htw.detect.model import CI_CD, CONTAINER, StackProfile
from htw.detect.signatures import PRUNED_DIRECTORIES
from htw.errors import ToolError
from htw.scanners.base import ScanContext, ToolAdapter

MAX_SIGNATURES = 20


def _signatures(root: Path, exclude: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [
            name
            for name in sorted(dirnames)
            if name not in PRUNED_DIRECTORIES
            and not is_excluded(f"{rel_dir}/{name}" if rel_dir else name, exclude)
        ]
        for name in filenames:
            if not name.endswith(".sig"):
                continue
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if is_excluded(rel, exclude):
                continue
            found.append(rel)
            if len(found) >= MAX_SIGNATURES:
                return found
    return found


class Cosign(ToolAdapter):
    name = "cosign"
    binary = "cosign"
    homepage = "https://github.com/sigstore/cosign"
    install_hint = (
        "`brew install cosign`, or download a release from "
        "https://github.com/sigstore/cosign/releases"
    )
    network = "none; verify-blob with a key file in the asset, never a registry"
    optional = True
    version_args = ("version",)

    def coverage(self, profile: StackProfile) -> set[str]:
        if profile.has(CONTAINER) or profile.has(CI_CD):
            return {"supply-chain:signatures"}
        return set()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        key = ctx.root / "cosign.pub"
        if key.is_symlink() or not key.is_file():
            raise ToolError(
                "cosign verification needs cosign.pub in the asset. "
                "HTW does not fetch keys and does not verify registry images."
            )
        findings = []
        for signature in _signatures(ctx.root, ctx.asset.exclude):
            blob = signature[: -len(".sig")]
            if not (ctx.root / blob).is_file() or (ctx.root / blob).is_symlink():
                continue
            argv = [
                "cosign", "verify-blob", "--offline", "--key", "cosign.pub",
                "--signature", signature, blob,
            ]  # fmt: skip
            result = self.invoke(ctx, argv)
            if result.returncode == 0:
                continue
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="pipeline",
                    tool=self.name,
                    category=PIPELINE,
                    rule_id="cosign-verify-blob",
                    title=f"Signature verification failed for {blob}",
                    message="cosign verify-blob did not accept this signature with cosign.pub.",
                    severity=Severity.HIGH,
                    location=Location(path=signature),
                )
            )
        return findings
