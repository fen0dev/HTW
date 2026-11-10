"""TruffleHog: secrets in the working tree and in git history.

Verification is always disabled. Checking whether a found credential is live means
talking to the service it belongs to, which is an L1 action that needs an explicit
opt-in this release does not offer.
"""

from __future__ import annotations

import json

from htw.core.finding import SECRET, Finding, Location, Severity
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int


class TruffleHog(ToolAdapter):
    name = "trufflehog"
    binary = "trufflehog"
    homepage = "https://github.com/trufflesecurity/trufflehog"
    install_hint = (
        "`brew install trufflehog`, or download a release from "
        "https://github.com/trufflesecurity/trufflehog/releases"
    )
    network = "none (verification of found credentials is disabled)"

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"secrets"}

    def scan(self, ctx: ScanContext) -> list[Finding]:
        history = bool(ctx.settings.options.get("history", True)) and (ctx.root / ".git").exists()
        source = ["git", ctx.root.as_uri()] if history else ["filesystem", str(ctx.root)]
        result = ctx.runner.run(
            ["trufflehog", *source, "--json", "--no-verification", "--no-update"], cwd=ctx.root
        )
        if result.returncode != 0:
            raise self._fail(result)

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = as_dict(json.loads(line))
            except ValueError:
                continue
            detector = str(entry.get("DetectorName") or "")
            if not detector:
                continue
            data = as_dict(as_dict(entry.get("SourceMetadata")).get("Data"))
            source_data = as_dict(data.get("Git")) or as_dict(data.get("Filesystem"))
            path = ctx.relative(str(source_data.get("file") or ""))
            if path is None:
                continue
            # The Raw, RawV2, Redacted and ExtraData fields can hold the credential or
            # parts of it. They are deliberately never read.
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="secrets",
                    tool=self.name,
                    category=SECRET,
                    rule_id=detector,
                    title=f"Secret detected ({detector})",
                    message=f"A value matching the {detector} credential format was found. "
                    "It was not checked for validity.",
                    severity=Severity.HIGH,
                    location=Location(
                        path=path,
                        start_line=as_int(source_data.get("line")),
                        end_line=as_int(source_data.get("line")),
                        commit=str(source_data.get("commit") or "") or None,
                    ),
                    identifiers=("CWE-798",),
                    context=f"detector:{detector}",
                )
            )
        return findings
