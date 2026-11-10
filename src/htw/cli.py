"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from htw import __version__
from htw.agents import AGENTS
from htw.agents.orchestrator import Orchestrator
from htw.agents.reporting import console_summary
from htw.agents.run import INCOMPLETE, REFUSED, STOPPED, AssetRun
from htw.core.audit import AuditLog
from htw.core.config import DEFAULT_CONFIG_NAME, Config, load_config
from htw.core.finding import Severity
from htw.core.runner import ToolRunner
from htw.core.scope import read_git_remotes
from htw.detect.model import CATEGORIES, CATEGORY_TITLES
from htw.errors import (
    EXIT_FINDINGS,
    EXIT_INCOMPLETE,
    EXIT_OK,
    EXIT_REFUSED,
    ConfigError,
    HtwError,
)

AUTHORIZED_USE = (
    "Only scan systems you own or are explicitly authorized to test. "
    "HTW scans nothing that is not declared, with an authorization record, in the scope file."
)

INIT_TEMPLATE = """\
# HTW scope file. This is the allowlist: nothing outside it is ever scanned.
# Keep it in version control and require review for every change to it.
version: 1

# Where HTW keeps its state, audit log and reports. Keep this out of version control.
state_dir: .htw

# Report-only by default. Proposals are files for a person to review.
# pull_requests opens them as drafts and never merges. private_destination is
# required before a patch that describes an unfixed weakness may be published.
fixes:
  propose: false
  pull_requests: false
  private_destination: false

# Deterministic triage (deduplicate, rank, drop obvious false positives).
# A model is off unless provider and api_key_env are set. No key is stored here.
triage:
  enabled: true
  llm: false

assets:
  - id: {asset_id}
    type: {asset_type}
    path: .
    owner: ""              # REQUIRED: team or person responsible for this asset
    environment: development
    criticality: medium    # low | medium | high | critical
    max_level: L0          # static analysis only
{ownership}    authorization:
      authorized_by: ""    # REQUIRED: the named person who authorizes scanning this asset
      authorized_on: ""    # REQUIRED: YYYY-MM-DD
      expires_on: ""       # REQUIRED: YYYY-MM-DD; scans are refused after this date
      reference: ""        # optional: ticket or document recording the authorization
    exclude: []
"""


def _load(arguments: argparse.Namespace) -> Config:
    return load_config(arguments.config)


def _validate_tools(config: Config) -> None:
    agents = {agent.name: agent for agent in AGENTS}
    for asset in config.assets:
        for name, settings in asset.scanners.items():
            for tool in settings.tools or ():
                agents[name].adapter(tool)


def cmd_init(arguments: argparse.Namespace) -> int:
    target = Path(arguments.config)
    if target.exists():
        raise ConfigError(f"{target} already exists; not overwriting it")
    cwd = Path.cwd()
    remotes = read_git_remotes(cwd) if (cwd / ".git").exists() else []
    asset_id = "".join(c if c.isalnum() or c in "._-" else "-" for c in cwd.name.lower()).strip(
        "-._"
    )
    if remotes:
        ownership = f"    ownership:\n      git_remote: {remotes[0]}\n"
        asset_type = "repository"
    else:
        ownership = ""
        asset_type = "directory"
    target.write_text(
        INIT_TEMPLATE.format(
            asset_id=asset_id or "my-asset", asset_type=asset_type, ownership=ownership
        ),
        encoding="utf-8",
    )
    print(f"Wrote {target}.")
    print("Fill in `owner` and the `authorization` record, then run `htw validate`.")
    print(AUTHORIZED_USE)
    print("Add the state directory (.htw/) to your .gitignore.")
    return EXIT_OK


def cmd_validate(arguments: argparse.Namespace) -> int:
    config = _load(arguments)
    _validate_tools(config)
    orchestrator = Orchestrator(config)
    refused = 0
    print(f"{config.path}: valid, {len(config.assets)} asset(s)")
    for asset in config.assets:
        decision, _, _ = orchestrator.plan(asset)
        if decision.allowed:
            print(f"  {asset.id}: in scope ({decision.ownership_evidence})")
        else:
            refused += 1
            print(f"  {asset.id}: WOULD BE REFUSED")
            for reason in decision.reasons:
                print(f"    - {reason}")
        for warning in decision.warnings:
            print(f"    warning: {warning}")
    return EXIT_REFUSED if refused else EXIT_OK


def cmd_doctor(arguments: argparse.Namespace) -> int:
    runner = ToolRunner()
    print(f"htw {__version__}")
    print("External scanners (HTW wraps these; none is bundled):\n")
    for agent in AGENTS:
        print(f"{agent.title}")
        for adapter in agent.adapters:
            if adapter.available(runner):
                version = adapter.version(runner, Path.cwd()) or "version unknown"
                print(f"  [found]   {adapter.name} {version}")
            else:
                print(f"  [missing] {adapter.name}: {adapter.install_hint}")
            print(f"            network: {adapter.network}")
        print()
    print("A missing scanner is skipped with a warning; the scan still runs with the rest.")
    return EXIT_OK


def cmd_detect(arguments: argparse.Namespace) -> int:
    config = _load(arguments)
    _validate_tools(config)
    orchestrator = Orchestrator(config)
    exit_code = EXIT_OK
    output = []
    for asset in orchestrator.select_assets(arguments.asset):
        decision, profile, plans = orchestrator.plan(asset)
        if not decision.allowed or profile is None:
            exit_code = EXIT_REFUSED
            print(f"[{asset.id}] REFUSED: not inspected.", file=sys.stderr)
            for reason in decision.reasons:
                print(f"  - {reason}", file=sys.stderr)
            continue
        if arguments.json:
            output.append(
                {
                    "asset": asset.id,
                    "stack": profile.to_dict(),
                    "plan": [plan.to_dict() for plan in plans],
                }
            )
            continue
        print(f"[{asset.id}] {asset.path} ({profile.files_seen} files)")
        for category in CATEGORIES:
            components = profile.of(category)
            if not components:
                continue
            print(f"  {CATEGORY_TITLES[category]}:")
            for component in components:
                confidence = "" if component.confidence == "high" else f" [{component.confidence}]"
                evidence = ", ".join(component.evidence[:3])
                print(f"    {component.name} ({component.count}){confidence}: {evidence}")
        for note in profile.notes:
            print(f"  note: {note}")
        print("  Scan plan:")
        for plan in plans:
            if not plan.applicable:
                print(f"    {plan.title}: not applicable ({plan.reason})")
                continue
            tools = ", ".join(adapter.name for adapter in plan.selected) or "no tool available"
            print(f"    {plan.title}: {tools}")
            for adapter in plan.missing:
                print(f"      missing: {adapter.missing_message()}")
            for gap in sorted(set(plan.uncovered.values())):
                print(f"      not covered: {gap}")
    if arguments.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    return exit_code


def _exit_code(runs: list[AssetRun], fail_on: Severity | None, strict: bool) -> int:
    if any(run.status in (REFUSED, STOPPED) for run in runs):
        return EXIT_REFUSED
    if any(run.status == INCOMPLETE for run in runs):
        return EXIT_INCOMPLETE
    if strict and any(run.gaps for run in runs):
        return EXIT_INCOMPLETE
    if fail_on is not None:
        for run in runs:
            for finding in run.visible(run.delta.new + run.delta.reappeared):
                if finding.severity.rank >= fail_on.rank:
                    return EXIT_FINDINGS
    return EXIT_OK


def cmd_scan(arguments: argparse.Namespace) -> int:
    config = _load(arguments)
    _validate_tools(config)
    orchestrator = Orchestrator(config)
    runs = orchestrator.scan(arguments.asset)
    for run in runs:
        print(console_summary(run))
    if any(run.status == STOPPED for run in runs):
        print("Kill switch engaged: the scan was stopped.", file=sys.stderr)
    fail_on = Severity(arguments.fail_on) if arguments.fail_on else None
    return _exit_code(runs, fail_on, arguments.strict)


def cmd_audit_verify(arguments: argparse.Namespace) -> int:
    config = _load(arguments)
    result = AuditLog(config.audit_path).verify()
    if result.ok:
        print(f"{config.audit_path}: {result.records} record(s), hash chain intact")
        return EXIT_OK
    print(f"{config.audit_path}: TAMPERING OR DAMAGE DETECTED: {result.error}", file=sys.stderr)
    return EXIT_FINDINGS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="htw",
        description="Security scanning agents for systems you own. " + AUTHORIZED_USE,
    )
    parser.add_argument("--version", action="version", version=f"htw {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def add(name: str, handler, help_text: str, config: bool = True) -> argparse.ArgumentParser:  # type: ignore[no-untyped-def]
        sub = commands.add_parser(name, help=help_text, description=help_text)
        sub.set_defaults(handler=handler)
        if config:
            sub.add_argument(
                "-c", "--config", default=DEFAULT_CONFIG_NAME,
                help=f"scope file (default: {DEFAULT_CONFIG_NAME})",
            )  # fmt: skip
        return sub

    add("init", cmd_init, "Write a starter scope file for the current directory.")
    add("validate", cmd_validate, "Check the scope file and whether each asset would be scanned.")
    add("doctor", cmd_doctor, "Show which external scanners are installed.", config=False)

    detect = add(
        "detect", cmd_detect, "Detect the stack of declared assets and show the scan plan."
    )
    detect.add_argument(
        "--asset", action="append", help="asset id from the scope file (repeatable)"
    )
    detect.add_argument("--json", action="store_true", help="print machine-readable output")

    scan = add("scan", cmd_scan, "Scan declared assets and report what changed.")
    scan.add_argument("--asset", action="append", help="asset id from the scope file (repeatable)")
    scan.add_argument(
        "--fail-on", choices=[s.value for s in Severity],
        help="exit 1 if a new or reappeared finding has at least this severity",
    )  # fmt: skip
    scan.add_argument(
        "--strict", action="store_true",
        help="exit 3 if part of the detected stack could not be covered by an installed scanner",
    )  # fmt: skip

    audit = add("audit-verify", cmd_audit_verify, "Verify the hash chain of the audit log.")
    del audit
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        return int(arguments.handler(arguments))
    except HtwError as exc:
        print(f"htw: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("htw: interrupted", file=sys.stderr)
        return 130
